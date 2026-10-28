"""Stateless OAuth 2.0 resource-server auth: validate externally issued JWTs.

Used when MCP_AUTH_MODE=oauth. Instead of running its own authorization
server (see oauth_provider.py, whose tokens live in memory and are lost on
every restart), the server only *verifies* RS256 access tokens minted by an
external authorization server such as Okta, against that issuer's JWKS.
Nothing is stored per token, so a container restart never invalidates a
client's credentials.

The intended caller is an MCP gateway (e.g. LiteLLM) that obtains tokens from
the issuer - e.g. per-user tokens via Okta Cross App Access (ID-JAG), or a
client_credentials grant - and sends ``Authorization: Bearer <jwt>`` on
every request.

Tokens are never logged.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

import httpx
import jwt
from starlette.types import ASGIApp, Receive, Scope, Send

logger = logging.getLogger(__name__)

REALM = "mfp-mcp"
ALGORITHM = "RS256"

DEFAULT_AUDIENCE = "api://default"
DEFAULT_REQUIRED_SCOPES = "mfp.read"
DEFAULT_CLOCK_TOLERANCE_SEC = 30

# How long a fetched JWKS is trusted before being refreshed on next use, and
# the minimum gap between refetches triggered by an unknown `kid` (so a flood
# of tokens with random kids can't turn into a flood of requests to the IdP).
JWKS_CACHE_TTL_SEC = 3600
JWKS_MIN_REFETCH_INTERVAL_SEC = 10
JWKS_FETCH_TIMEOUT_SEC = 10

_LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}


def _split_csv(raw: str | None) -> tuple[str, ...]:
    if not raw:
        return ()
    return tuple(item.strip() for item in raw.split(",") if item.strip())


def _require_secure_url(name: str, url: str) -> None:
    parsed = urlparse(url)
    if not parsed.scheme or not parsed.hostname:
        raise RuntimeError(f"{name}={url!r} is not an absolute URL.")
    if parsed.scheme == "https":
        return
    if parsed.scheme == "http" and parsed.hostname in _LOCAL_HOSTS:
        return
    raise RuntimeError(
        f"{name}={url!r} must use https:// (plain http is only allowed for localhost)."
    )


@dataclass(frozen=True)
class JWTAuthConfig:
    issuer: str
    audiences: tuple[str, ...]
    required_scopes: tuple[str, ...]
    allowed_client_ids: tuple[str, ...]  # empty => any client id accepted
    jwks_uri: str
    clock_tolerance_sec: int

    @classmethod
    def from_env(cls, env: Mapping[str, str]) -> JWTAuthConfig:
        """Build config from MCP_OAUTH_* variables; raise RuntimeError if invalid.

        Fails loudly rather than degrading: a deployment that asked for
        MCP_AUTH_MODE=oauth must never end up serving /mcp unauthenticated.
        """
        issuer = (env.get("MCP_OAUTH_ISSUER") or "").strip().rstrip("/")
        if not issuer:
            raise RuntimeError(
                "MCP_AUTH_MODE=oauth requires MCP_OAUTH_ISSUER (e.g. "
                "https://your-org.okta.com/oauth2/default). Refusing to start "
                "rather than serving the MCP endpoint without authentication."
            )
        _require_secure_url("MCP_OAUTH_ISSUER", issuer)

        jwks_uri = (env.get("MCP_OAUTH_JWKS_URI") or "").strip() or f"{issuer}/v1/keys"
        _require_secure_url("MCP_OAUTH_JWKS_URI", jwks_uri)

        audiences = _split_csv(env.get("MCP_OAUTH_AUDIENCE")) or (DEFAULT_AUDIENCE,)

        raw_scopes = env.get("MCP_OAUTH_REQUIRED_SCOPES")
        required_scopes = _split_csv(
            DEFAULT_REQUIRED_SCOPES if raw_scopes is None else raw_scopes
        )
        if not required_scopes:
            raise RuntimeError(
                "MCP_OAUTH_REQUIRED_SCOPES resolved to an empty list; at least "
                f"one scope must be required (default: {DEFAULT_REQUIRED_SCOPES})."
            )

        raw_tolerance = (env.get("MCP_OAUTH_CLOCK_TOLERANCE_SEC") or "").strip()
        if raw_tolerance:
            try:
                tolerance = int(raw_tolerance)
            except ValueError:
                raise RuntimeError(
                    f"MCP_OAUTH_CLOCK_TOLERANCE_SEC={raw_tolerance!r} is not an integer."
                ) from None
            if tolerance < 0:
                raise RuntimeError("MCP_OAUTH_CLOCK_TOLERANCE_SEC must be >= 0.")
        else:
            tolerance = DEFAULT_CLOCK_TOLERANCE_SEC

        return cls(
            issuer=issuer,
            audiences=audiences,
            required_scopes=required_scopes,
            allowed_client_ids=_split_csv(env.get("MCP_OAUTH_ALLOWED_CLIENT_IDS")),
            jwks_uri=jwks_uri,
            clock_tolerance_sec=tolerance,
        )


class InvalidTokenError(Exception):
    """Token rejected -> 401 invalid_token. Message is safe to return/log."""


class InsufficientScopeError(Exception):
    """Token valid but lacks a required scope -> 403 insufficient_scope."""


class JWKSUnavailableError(Exception):
    """The issuer's JWKS could not be fetched and no usable key is cached."""


class JWKSCache:
    """Caches the issuer's signing keys by `kid`; refetches on unknown kid."""

    def __init__(
        self,
        jwks_uri: str,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
        ttl_sec: float = JWKS_CACHE_TTL_SEC,
        min_refetch_interval_sec: float = JWKS_MIN_REFETCH_INTERVAL_SEC,
    ):
        self._jwks_uri = jwks_uri
        self._transport = transport
        self._ttl = ttl_sec
        self._min_refetch = min_refetch_interval_sec
        self._keys: dict[str, Any] = {}
        self._fetched_at: float | None = None
        self._lock = asyncio.Lock()

    async def _fetch(self) -> None:
        async with httpx.AsyncClient(
            transport=self._transport, timeout=JWKS_FETCH_TIMEOUT_SEC
        ) as client:
            resp = await client.get(self._jwks_uri, headers={"Accept": "application/json"})
            resp.raise_for_status()
            data = resp.json()
        keys: dict[str, Any] = {}
        for jwk in data.get("keys", []):
            kid = jwk.get("kid")
            if not kid or jwk.get("kty") != "RSA":
                continue
            if jwk.get("use", "sig") != "sig" or jwk.get("alg", ALGORITHM) != ALGORITHM:
                continue
            try:
                keys[kid] = jwt.PyJWK.from_dict(jwk, algorithm=ALGORITHM).key
            except jwt.PyJWTError:
                logger.warning("Ignoring unparseable JWK kid=%s from %s", kid, self._jwks_uri)
        self._keys = keys
        self._fetched_at = time.monotonic()
        logger.info("Loaded %d signing key(s) from %s", len(keys), self._jwks_uri)

    async def get_key(self, kid: str) -> Any:
        now = time.monotonic()
        stale = self._fetched_at is None or now - self._fetched_at > self._ttl
        if not stale and kid in self._keys:
            return self._keys[kid]

        async with self._lock:
            now = time.monotonic()
            stale = self._fetched_at is None or now - self._fetched_at > self._ttl
            if not stale and kid in self._keys:
                return self._keys[kid]  # another task refreshed while we waited
            # Unknown kid on a fresh key set: refetch (key rotation), but at
            # most once per min_refetch interval.
            last = self._fetched_at
            if stale or last is None or now - last >= self._min_refetch:
                try:
                    await self._fetch()
                except (httpx.HTTPError, ValueError) as exc:
                    logger.error("Failed to fetch JWKS from %s: %s", self._jwks_uri, exc)
                    if kid in self._keys:
                        return self._keys[kid]  # keep serving the last good key set
                    raise JWKSUnavailableError("signing keys unavailable") from None

        key = self._keys.get(kid)
        if key is None:
            raise InvalidTokenError("unknown signing key")
        return key


@dataclass(frozen=True)
class VerifiedToken:
    client_id: str | None
    subject: str | None
    scopes: tuple[str, ...]
    expires_at: int | None


class JWTVerifier:
    def __init__(self, config: JWTAuthConfig, jwks: JWKSCache | None = None):
        self.config = config
        self._jwks = jwks or JWKSCache(config.jwks_uri)

    async def verify(self, token: str) -> VerifiedToken:
        try:
            header = jwt.get_unverified_header(token)
        except jwt.PyJWTError:
            raise InvalidTokenError("malformed token") from None

        # Pin the algorithm before touching any key: rejects alg=none and
        # HS256-with-the-public-key confusion outright.
        if header.get("alg") != ALGORITHM:
            raise InvalidTokenError("unsupported token algorithm")
        kid = header.get("kid")
        if not isinstance(kid, str) or not kid:
            raise InvalidTokenError("token has no key id")

        key = await self._jwks.get_key(kid)

        cfg = self.config
        try:
            claims = jwt.decode(
                token,
                key,
                algorithms=[ALGORITHM],
                audience=list(cfg.audiences),
                issuer=cfg.issuer,
                leeway=cfg.clock_tolerance_sec,
                options={"require": ["exp", "iat", "iss", "aud"]},
            )
        except jwt.ExpiredSignatureError:
            raise InvalidTokenError("token expired") from None
        except jwt.InvalidAudienceError:
            raise InvalidTokenError("invalid audience") from None
        except jwt.InvalidIssuerError:
            raise InvalidTokenError("invalid issuer") from None
        except jwt.PyJWTError:
            raise InvalidTokenError("invalid token") from None

        client_id = claims.get("cid", claims.get("client_id"))
        if cfg.allowed_client_ids and client_id not in cfg.allowed_client_ids:
            raise InvalidTokenError("client not allowed")

        raw_scopes = claims.get("scp", claims.get("scope"))
        if isinstance(raw_scopes, str):
            scopes = tuple(raw_scopes.split())
        elif isinstance(raw_scopes, list):
            scopes = tuple(s for s in raw_scopes if isinstance(s, str))
        else:
            scopes = ()
        if any(s not in scopes for s in cfg.required_scopes):
            raise InsufficientScopeError("insufficient scope")

        exp = claims.get("exp")
        return VerifiedToken(
            client_id=client_id if isinstance(client_id, str) else None,
            subject=claims.get("sub"),
            scopes=scopes,
            expires_at=int(exp) if isinstance(exp, (int, float)) else None,
        )


def _normalize_path(path: str) -> str:
    while "//" in path:
        path = path.replace("//", "/")
    return path.rstrip("/") or "/"


class JWTAuthMiddleware:
    """ASGI middleware requiring a valid bearer JWT on the MCP endpoint.

    Only the MCP path (and anything beneath it) is guarded; other paths fall
    through to the app, which in oauth mode serves nothing else (404).
    """

    def __init__(self, app: ASGIApp, verifier: JWTVerifier, mcp_path: str = "/mcp"):
        self.app = app
        self.verifier = verifier
        self.mcp_path = _normalize_path(mcp_path)

    def _is_protected(self, path: str) -> bool:
        p = _normalize_path(path)
        return p == self.mcp_path or p.startswith(self.mcp_path + "/")

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] not in ("http", "websocket") or not self._is_protected(scope.get("path", "")):
            await self.app(scope, receive, send)
            return
        if scope["type"] == "websocket":
            await send({"type": "websocket.close", "code": 1008})  # MCP is HTTP-only here
            return

        auth_values = [v for k, v in scope.get("headers", []) if k.lower() == b"authorization"]
        if not auth_values:
            await _send_error(send, 401, f'Bearer realm="{REALM}"', "unauthorized", "missing bearer token")
            return

        token = _parse_bearer(auth_values)
        if token is None:
            await _send_error(
                send, 401, _www_auth("invalid_token", "malformed authorization header"),
                "invalid_token", "malformed authorization header",
            )
            return

        try:
            verified = await self.verifier.verify(token)
        except InvalidTokenError as exc:
            logger.info("Rejected bearer token: %s", exc)
            await _send_error(send, 401, _www_auth("invalid_token", str(exc)), "invalid_token", str(exc))
            return
        except InsufficientScopeError:
            needed = " ".join(self.verifier.config.required_scopes)
            logger.info("Rejected bearer token: missing required scope(s) %s", needed)
            await _send_error(
                send, 403,
                _www_auth("insufficient_scope", "insufficient scope") + f', scope="{needed}"',
                "insufficient_scope", "insufficient scope",
            )
            return
        except JWKSUnavailableError:
            await _send_error(
                send, 503, f'Bearer realm="{REALM}"',
                "temporarily_unavailable", "cannot verify token right now",
            )
            return

        scope = dict(scope)
        scope["state"] = {**scope.get("state", {}), "oauth_token": verified}
        await self.app(scope, receive, send)


def _parse_bearer(values: list[bytes]) -> str | None:
    if len(values) != 1:
        return None
    try:
        value = values[0].decode("latin-1").strip()
    except UnicodeDecodeError:
        return None
    parts = value.split(" ")
    if len(parts) != 2 or parts[0].lower() != "bearer" or not parts[1]:
        return None
    token = parts[1]
    if any(c.isspace() for c in token) or token.count(".") != 2:
        return None
    return token


def _www_auth(error: str, description: str) -> str:
    return f'Bearer realm="{REALM}", error="{error}", error_description="{description}"'


async def _send_error(send: Send, status: int, www_authenticate: str, error: str, description: str) -> None:
    body = json.dumps({"error": error, "error_description": description}).encode()
    await send({
        "type": "http.response.start",
        "status": status,
        "headers": [
            (b"content-type", b"application/json"),
            (b"content-length", str(len(body)).encode()),
            (b"www-authenticate", www_authenticate.encode()),
            (b"cache-control", b"no-store"),
        ],
    })
    await send({"type": "http.response.body", "body": body})
