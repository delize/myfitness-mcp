"""Tests for MCP_AUTH_MODE=oauth: stateless validation of external (Okta) JWTs.

Fully offline: a locally generated RSA key signs the tokens and an
httpx.MockTransport serves the matching JWKS, so nothing talks to Okta.
"""

import json
import os
import subprocess
import sys
import textwrap
import time

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from starlette.routing import Route
from starlette.testclient import TestClient

import myfitnesspal_mcp.server as srv
from myfitnesspal_mcp.jwt_auth import (
    JWKSCache,
    JWTAuthConfig,
    JWTAuthMiddleware,
    JWTVerifier,
)

ISSUER = "https://example.okta.com/oauth2/default"
AUDIENCE = "api://default"
CLIENT_ID = "0oatestclient"
KID = "test-key-1"

PRIVATE_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
OTHER_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)


def jwk_for(private_key, kid):
    jwk = jwt.algorithms.RSAAlgorithm.to_jwk(private_key.public_key(), as_dict=True)
    jwk.update({"kid": kid, "alg": "RS256", "use": "sig"})
    return jwk


def make_token(
    *,
    key=PRIVATE_KEY,
    kid=KID,
    alg="RS256",
    iss=ISSUER,
    aud=AUDIENCE,
    cid=CLIENT_ID,
    scp=("mfp.read",),
    exp_in=3600,
    **extra,
):
    now = int(time.time())
    claims = {"iss": iss, "aud": aud, "iat": now, "exp": now + exp_in, "sub": cid, "cid": cid,
              **extra}
    if scp is not None:
        claims["scp"] = list(scp)
    headers = {"kid": kid} if kid else {}
    return jwt.encode(claims, key, algorithm=alg, headers=headers)


class FakeJWKSServer:
    """Serves a mutable JWKS document through httpx.MockTransport."""

    def __init__(self, *jwks):
        self.keys = list(jwks)
        self.requests = 0

    def transport(self):
        def handler(request):
            self.requests += 1
            assert str(request.url) == f"{ISSUER}/v1/keys"
            return httpx.Response(200, json={"keys": self.keys})

        return httpx.MockTransport(handler)


def make_config(**overrides):
    env = {"MCP_OAUTH_ISSUER": ISSUER, **overrides}
    return JWTAuthConfig.from_env(env)


def downstream_app():
    async def ok(request):
        token = request.scope["state"]["oauth_token"]
        return PlainTextResponse(f"ok {token.client_id}")

    return Starlette(routes=[Route("/mcp", ok, methods=["GET", "POST"])])


@pytest.fixture
def jwks_server():
    return FakeJWKSServer(jwk_for(PRIVATE_KEY, KID))


def make_client(jwks_server, **config_overrides):
    config = make_config(**config_overrides)
    cache = JWKSCache(config.jwks_uri, transport=jwks_server.transport(), min_refetch_interval_sec=0)
    app = JWTAuthMiddleware(downstream_app(), JWTVerifier(config, cache))
    return TestClient(app)


def bearer(token):
    return {"Authorization": f"Bearer {token}"}


def www_auth(resp):
    return resp.headers.get("www-authenticate", "")


# --- Config ---------------------------------------------------------------


class TestConfig:
    def test_defaults(self):
        cfg = make_config()
        assert cfg.issuer == ISSUER
        assert cfg.audiences == ("api://default",)
        assert cfg.required_scopes == ("mfp.read",)
        assert cfg.allowed_client_ids == ()
        assert cfg.jwks_uri == f"{ISSUER}/v1/keys"
        assert cfg.clock_tolerance_sec == 30

    def test_lists_and_overrides(self):
        cfg = make_config(
            MCP_OAUTH_AUDIENCE="api://a, api://b",
            MCP_OAUTH_REQUIRED_SCOPES="mfp.read,mfp.write",
            MCP_OAUTH_ALLOWED_CLIENT_IDS="c1, c2",
            MCP_OAUTH_JWKS_URI="https://keys.example.com/jwks",
            MCP_OAUTH_CLOCK_TOLERANCE_SEC="5",
        )
        assert cfg.audiences == ("api://a", "api://b")
        assert cfg.required_scopes == ("mfp.read", "mfp.write")
        assert cfg.allowed_client_ids == ("c1", "c2")
        assert cfg.jwks_uri == "https://keys.example.com/jwks"
        assert cfg.clock_tolerance_sec == 5

    def test_trailing_slash_on_issuer_is_stripped(self):
        assert make_config(MCP_OAUTH_ISSUER=ISSUER + "/").issuer == ISSUER

    @pytest.mark.parametrize("issuer", ["", "   "])
    def test_missing_issuer_raises(self, issuer):
        with pytest.raises(RuntimeError, match="MCP_OAUTH_ISSUER"):
            JWTAuthConfig.from_env({"MCP_OAUTH_ISSUER": issuer})

    def test_http_issuer_rejected(self):
        with pytest.raises(RuntimeError, match="https"):
            make_config(MCP_OAUTH_ISSUER="http://example.okta.com/oauth2/default")

    def test_http_localhost_issuer_allowed(self):
        assert make_config(MCP_OAUTH_ISSUER="http://localhost:8080/oauth2/default").issuer

    def test_http_jwks_uri_rejected(self):
        with pytest.raises(RuntimeError, match="MCP_OAUTH_JWKS_URI"):
            make_config(MCP_OAUTH_JWKS_URI="http://keys.example.com/jwks")

    def test_empty_required_scopes_rejected(self):
        with pytest.raises(RuntimeError, match="MCP_OAUTH_REQUIRED_SCOPES"):
            make_config(MCP_OAUTH_REQUIRED_SCOPES=" , ")

    def test_bad_tolerance_rejected(self):
        with pytest.raises(RuntimeError, match="CLOCK_TOLERANCE"):
            make_config(MCP_OAUTH_CLOCK_TOLERANCE_SEC="soon")


# --- Middleware / verification -------------------------------------------


class TestJWTAuth:
    def test_valid_token(self, jwks_server):
        with make_client(jwks_server) as client:
            resp = client.get("/mcp", headers=bearer(make_token()))
        assert resp.status_code == 200
        assert resp.text == f"ok {CLIENT_ID}"

    def test_per_user_cross_app_access_token(self, jwks_server):
        # Shape of the Okta Cross App Access (ID-JAG) tokens the LiteLLM gateway
        # sends: per-user `sub` (email), custom audience, gateway client id.
        captured = {}

        async def ok(request):
            captured["token"] = request.scope["state"]["oauth_token"]
            return PlainTextResponse("ok")

        config = make_config(
            MCP_OAUTH_AUDIENCE="mcp-gateway",
            MCP_OAUTH_ALLOWED_CLIENT_IDS=CLIENT_ID,
        )
        cache = JWKSCache(config.jwks_uri, transport=jwks_server.transport())
        app = JWTAuthMiddleware(Starlette(routes=[Route("/mcp", ok, methods=["POST"])]),
                                JWTVerifier(config, cache))
        token = make_token(aud="mcp-gateway", sub="user@example.com", scp=("openid", "mfp.read"))
        with TestClient(app) as client:
            assert client.post("/mcp", headers=bearer(token)).status_code == 200
            assert client.post("/mcp", headers=bearer(make_token())).status_code == 401  # aud api://default
        verified = captured["token"]
        assert verified.subject == "user@example.com"
        assert verified.client_id == CLIENT_ID
        assert verified.scopes == ("openid", "mfp.read")

    def test_scope_string_claim_also_accepted(self, jwks_server):
        token = make_token(scp=None, scope="openid mfp.read")
        with make_client(jwks_server) as client:
            assert client.get("/mcp", headers=bearer(token)).status_code == 200

    def test_missing_header(self, jwks_server):
        with make_client(jwks_server) as client:
            resp = client.get("/mcp")
        assert resp.status_code == 401
        assert www_auth(resp) == 'Bearer realm="mfp-mcp"'

    @pytest.mark.parametrize(
        "value",
        ["Basic dXNlcjpwYXNz", "Bearer", "Bearer ", "Bearer a b", "Bearer not-a-jwt", "Token abc.def.ghi"],
    )
    def test_malformed_header(self, jwks_server, value):
        with make_client(jwks_server) as client:
            resp = client.get("/mcp", headers={"Authorization": value})
        assert resp.status_code == 401
        assert 'error="invalid_token"' in www_auth(resp)

    def test_lowercase_bearer_scheme_accepted(self, jwks_server):
        with make_client(jwks_server) as client:
            resp = client.get("/mcp", headers={"Authorization": f"bearer {make_token()}"})
        assert resp.status_code == 200

    @pytest.mark.parametrize(
        "token_kwargs",
        [
            pytest.param({"iss": "https://evil.okta.com/oauth2/default"}, id="wrong-iss"),
            pytest.param({"aud": "api://other"}, id="wrong-aud"),
            pytest.param({"exp_in": -3600}, id="expired"),
            pytest.param({"kid": "unknown-kid"}, id="unknown-kid"),
            pytest.param({"kid": None}, id="no-kid"),
            pytest.param({"key": OTHER_KEY}, id="bad-signature"),
        ],
    )
    def test_invalid_tokens_rejected(self, jwks_server, token_kwargs):
        with make_client(jwks_server) as client:
            resp = client.get("/mcp", headers=bearer(make_token(**token_kwargs)))
        assert resp.status_code == 401
        assert 'error="invalid_token"' in www_auth(resp)
        assert 'realm="mfp-mcp"' in www_auth(resp)

    def test_expired_within_clock_tolerance_accepted(self, jwks_server):
        with make_client(jwks_server) as client:
            resp = client.get("/mcp", headers=bearer(make_token(exp_in=-10)))
        assert resp.status_code == 200

    def test_hs256_rejected(self, jwks_server):
        # Classic alg-confusion: HMAC "signed" with the public key material.
        pem_ish = b"a-shared-secret-of-sufficient-length-0123456789"
        token = make_token(key=pem_ish, alg="HS256")
        with make_client(jwks_server) as client:
            resp = client.get("/mcp", headers=bearer(token))
        assert resp.status_code == 401
        assert 'error="invalid_token"' in www_auth(resp)

    def test_alg_none_rejected(self, jwks_server):
        token = jwt.encode({"iss": ISSUER, "aud": AUDIENCE, "exp": int(time.time()) + 60,
                            "iat": int(time.time()), "scp": ["mfp.read"]},
                           None, algorithm="none", headers={"kid": KID})
        with make_client(jwks_server) as client:
            assert client.get("/mcp", headers=bearer(token)).status_code == 401

    def test_missing_scope_is_403(self, jwks_server):
        with make_client(jwks_server) as client:
            resp = client.get("/mcp", headers=bearer(make_token(scp=("openid",))))
        assert resp.status_code == 403
        assert 'error="insufficient_scope"' in www_auth(resp)
        assert 'scope="mfp.read"' in www_auth(resp)

    def test_all_required_scopes_needed(self, jwks_server):
        with make_client(jwks_server, MCP_OAUTH_REQUIRED_SCOPES="mfp.read,mfp.write") as client:
            assert client.get("/mcp", headers=bearer(make_token())).status_code == 403
            token = make_token(scp=("mfp.read", "mfp.write"))
            assert client.get("/mcp", headers=bearer(token)).status_code == 200

    def test_disallowed_client_id(self, jwks_server):
        with make_client(jwks_server, MCP_OAUTH_ALLOWED_CLIENT_IDS="0oaother") as client:
            resp = client.get("/mcp", headers=bearer(make_token()))
        assert resp.status_code == 401
        assert 'error="invalid_token"' in www_auth(resp)

    def test_allowed_client_id(self, jwks_server):
        with make_client(jwks_server, MCP_OAUTH_ALLOWED_CLIENT_IDS=f"0oaother,{CLIENT_ID}") as client:
            assert client.get("/mcp", headers=bearer(make_token())).status_code == 200

    def test_multiple_audiences(self, jwks_server):
        with make_client(jwks_server, MCP_OAUTH_AUDIENCE="api://mfp,api://default") as client:
            assert client.get("/mcp", headers=bearer(make_token())).status_code == 200
            assert client.get("/mcp", headers=bearer(make_token(aud="api://mfp"))).status_code == 200
            assert client.get("/mcp", headers=bearer(make_token(aud="api://x"))).status_code == 401

    def test_subpath_and_trailing_slash_protected(self, jwks_server):
        with make_client(jwks_server) as client:
            assert client.get("/mcp/").status_code == 401
            assert client.get("/mcp/anything").status_code == 401

    def test_path_normalization(self):
        mw = JWTAuthMiddleware(downstream_app(), JWTVerifier(make_config()))
        for path in ("/mcp", "/mcp/", "//mcp", "/mcp//", "/mcp/x"):
            assert mw._is_protected(path), path
        for path in ("/", "/mcpx", "/authorize", "/.well-known/oauth-protected-resource/mcp"):
            assert not mw._is_protected(path), path

    def test_other_paths_not_guarded(self, jwks_server):
        with make_client(jwks_server) as client:
            assert client.get("/authorize").status_code == 404

    def test_token_never_logged(self, jwks_server, caplog):
        caplog.set_level("DEBUG")
        token = make_token(aud="api://other")
        with make_client(jwks_server) as client:
            client.get("/mcp", headers=bearer(token))
        assert token not in caplog.text
        assert token.split(".")[2] not in caplog.text

    def test_jwks_unreachable_is_503(self):
        def handler(request):
            raise httpx.ConnectError("offline")

        config = make_config()
        cache = JWKSCache(config.jwks_uri, transport=httpx.MockTransport(handler))
        app = JWTAuthMiddleware(downstream_app(), JWTVerifier(config, cache))
        with TestClient(app) as client:
            resp = client.get("/mcp", headers=bearer(make_token()))
        assert resp.status_code == 503


class TestJWKSCache:
    def test_keys_are_cached(self, jwks_server):
        with make_client(jwks_server) as client:
            for _ in range(3):
                assert client.get("/mcp", headers=bearer(make_token())).status_code == 200
        assert jwks_server.requests == 1

    def test_key_rotation_refetches_on_unknown_kid(self, jwks_server):
        with make_client(jwks_server) as client:
            assert client.get("/mcp", headers=bearer(make_token())).status_code == 200
            # IdP rotates: publishes a new key and signs with it.
            jwks_server.keys.append(jwk_for(OTHER_KEY, "test-key-2"))
            token = make_token(key=OTHER_KEY, kid="test-key-2")
            assert client.get("/mcp", headers=bearer(token)).status_code == 200
        assert jwks_server.requests == 2

    def test_unknown_kid_refetch_is_rate_limited(self, jwks_server):
        config = make_config()
        cache = JWKSCache(config.jwks_uri, transport=jwks_server.transport(), min_refetch_interval_sec=60)
        app = JWTAuthMiddleware(downstream_app(), JWTVerifier(config, cache))
        with TestClient(app) as client:
            assert client.get("/mcp", headers=bearer(make_token())).status_code == 200
            for i in range(5):
                resp = client.get("/mcp", headers=bearer(make_token(kid=f"bogus-{i}")))
                assert resp.status_code == 401
        assert jwks_server.requests == 1

    def test_non_rs256_jwks_entries_ignored(self):
        hs_key = {"kty": "oct", "kid": KID, "k": "c2VjcmV0", "alg": "HS256"}
        server = FakeJWKSServer(hs_key)
        with make_client(server) as client:
            assert client.get("/mcp", headers=bearer(make_token())).status_code == 401


# --- Integration with the real FastMCP streamable-http app ----------------


class TestFastMCPIntegration:
    def test_initialize_through_real_mcp_app(self, jwks_server):
        mcp = FastMCP("t", transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False))
        config = make_config()
        cache = JWKSCache(config.jwks_uri, transport=jwks_server.transport())
        app = JWTAuthMiddleware(mcp.streamable_http_app(), JWTVerifier(config, cache))
        body = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": "2025-06-18", "capabilities": {},
            "clientInfo": {"name": "test", "version": "0"}}}
        headers = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json"}
        with TestClient(app) as client:
            assert client.post("/mcp", json=body, headers=headers).status_code == 401
            resp = client.post("/mcp", json=body, headers={**headers, **bearer(make_token())})
        assert resp.status_code == 200
        assert "serverInfo" in resp.text


# --- Mode selection in server.py ------------------------------------------


class TestAuthModeSelection:
    @pytest.fixture(autouse=True)
    def clean_env(self, monkeypatch):
        for var in ("MCP_AUTH_MODE", "MCP_OAUTH_PASSCODE", "MCP_RESOURCE_URL", "MCP_OAUTH_ISSUER",
                    "MCP_OAUTH_AUDIENCE", "MCP_OAUTH_REQUIRED_SCOPES", "MCP_OAUTH_ALLOWED_CLIENT_IDS",
                    "MCP_OAUTH_JWKS_URI", "MCP_OAUTH_CLOCK_TOLERANCE_SEC"):
            monkeypatch.delenv(var, raising=False)
        monkeypatch.setenv("MCP_TRANSPORT", "streamable-http")

    def test_unset_mode_is_legacy_no_auth(self):
        assert srv._build_auth() == (None, None, None, None)

    def test_unset_mode_is_legacy_passcode(self, monkeypatch):
        monkeypatch.setenv("MCP_OAUTH_PASSCODE", "secret")
        monkeypatch.setenv("MCP_RESOURCE_URL", "https://mfp.example.com")
        mode, provider, settings, verifier = srv._build_auth()
        assert mode is None and verifier is None
        assert provider is not None and provider.verify_passcode("secret")
        assert settings is not None

    def test_unset_mode_partial_passcode_still_fails_closed(self, monkeypatch):
        monkeypatch.setenv("MCP_RESOURCE_URL", "https://mfp.example.com")
        with pytest.raises(RuntimeError, match="MCP_OAUTH_PASSCODE"):
            srv._build_auth()

    def test_explicit_passcode_mode_requires_both(self, monkeypatch):
        monkeypatch.setenv("MCP_AUTH_MODE", "passcode_oauth")
        with pytest.raises(RuntimeError, match="MCP_OAUTH_PASSCODE and MCP_RESOURCE_URL"):
            srv._build_auth()

    def test_explicit_none(self, monkeypatch):
        monkeypatch.setenv("MCP_AUTH_MODE", "none")
        monkeypatch.setenv("MCP_OAUTH_PASSCODE", "secret")
        assert srv._build_auth() == ("none", None, None, None)

    def test_oauth_mode_without_issuer_raises(self, monkeypatch):
        monkeypatch.setenv("MCP_AUTH_MODE", "oauth")
        with pytest.raises(RuntimeError, match="MCP_OAUTH_ISSUER"):
            srv._build_auth()

    def test_oauth_mode_builds_verifier_only(self, monkeypatch):
        monkeypatch.setenv("MCP_AUTH_MODE", "OAuth")
        monkeypatch.setenv("MCP_OAUTH_ISSUER", ISSUER)
        monkeypatch.setenv("MCP_OAUTH_PASSCODE", "ignored")
        monkeypatch.setenv("MCP_RESOURCE_URL", "https://mfp.example.com")
        mode, provider, settings, verifier = srv._build_auth()
        assert mode == "oauth"
        assert provider is None and settings is None
        assert verifier is not None and verifier.config.issuer == ISSUER

    def test_unknown_mode_raises(self, monkeypatch):
        monkeypatch.setenv("MCP_AUTH_MODE", "jwt")
        with pytest.raises(RuntimeError, match="MCP_AUTH_MODE"):
            srv._build_auth()


# --- Real process startup (module-level wiring) ----------------------------

_PROBE = textwrap.dedent(
    """
    import json
    from starlette.testclient import TestClient
    import myfitnesspal_mcp.server as srv
    paths = ["/mcp", "/authorize", "/token", "/register", "/login", "/revoke",
             "/.well-known/oauth-authorization-server",
             "/.well-known/oauth-protected-resource",
             "/.well-known/oauth-protected-resource/mcp"]
    out = {}
    with TestClient(srv.create_http_app()) as client:
        for p in paths:
            r = client.get(p, follow_redirects=False)
            out[p] = [r.status_code, r.headers.get("www-authenticate")]
    print(json.dumps(out))
    """
)


def _run_server_probe(extra_env, code=_PROBE):
    env = {k: v for k, v in os.environ.items() if not k.startswith(("MCP_", "MFP_"))}
    env.update({"MCP_TRANSPORT": "streamable-http", **extra_env})
    return subprocess.run([sys.executable, "-c", code], check=False, env=env, capture_output=True, text=True, timeout=120)


class TestServerStartup:
    def test_oauth_mode_without_issuer_fails_at_startup(self):
        result = _run_server_probe({"MCP_AUTH_MODE": "oauth"}, code="import myfitnesspal_mcp.server")
        assert result.returncode != 0
        assert "MCP_OAUTH_ISSUER" in result.stderr

    def test_oauth_mode_disables_own_oauth_endpoints(self):
        result = _run_server_probe({
            "MCP_AUTH_MODE": "oauth",
            "MCP_OAUTH_ISSUER": ISSUER,
            # Leftover legacy config must not resurrect the passcode server.
            "MCP_OAUTH_PASSCODE": "secret",
            "MCP_RESOURCE_URL": "https://mfp.example.com",
        })
        assert result.returncode == 0, result.stderr
        out = json.loads(result.stdout.strip().splitlines()[-1])
        assert out.pop("/mcp") == [401, 'Bearer realm="mfp-mcp"']
        for path, (status, _) in out.items():
            assert status == 404, path

    def test_legacy_passcode_mode_unchanged(self):
        result = _run_server_probe({
            "MCP_OAUTH_PASSCODE": "secret",
            "MCP_RESOURCE_URL": "https://mfp.example.com",
        })
        assert result.returncode == 0, result.stderr
        out = json.loads(result.stdout.strip().splitlines()[-1])
        assert out["/mcp"][0] == 401
        assert "resource_metadata" in (out["/mcp"][1] or "")  # SDK's own bearer challenge
        assert out["/.well-known/oauth-authorization-server"][0] == 200
        assert out["/login"][0] == 400  # route exists (no login_id given)
        assert out["/authorize"][0] != 404

    def test_legacy_no_auth_mode_unchanged(self):
        result = _run_server_probe({})
        assert result.returncode == 0, result.stderr
        out = json.loads(result.stdout.strip().splitlines()[-1])
        assert out["/mcp"][0] not in (401, 403, 404)  # served, no auth challenge
        assert out["/.well-known/oauth-authorization-server"][0] == 404
