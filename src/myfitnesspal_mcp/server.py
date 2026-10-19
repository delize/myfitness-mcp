"""MyFitnessPal MCP Server - Main entry point.

A Model Context Protocol (MCP) server that provides tools for interacting
with MyFitnessPal data including food diary, exercises, measurements, goals,
water intake, and food search.

Tool implementations are ported from AdamWalt/myfitnesspal-mcp-python (MIT).
The OAuth 2.1 / transport skeleton (streamable-http, single-passcode OAuth
provider, allowed-hosts DNS-rebinding protection) mirrors garmin-mcp-service
so this can be used as a remote Claude connector.

Authentication: MyFitnessPal's login page is captcha-protected, so password
login is not supported. Session cookies are read from a mounted Firefox
profile (MFP_FIREFOX_PROFILE_DIR) or a JSON cookies file (MFP_COOKIES_FILE) -
see cookie_loader.
"""

import json
import logging
import os
import sys
import threading
from collections import OrderedDict
from datetime import date, datetime, timedelta
from enum import Enum
from http.cookiejar import CookieJar
from typing import Any, Dict, List, Optional, Tuple

from mcp.server.auth.settings import AuthSettings, ClientRegistrationOptions
from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from pydantic import BaseModel, ConfigDict, Field
from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse, Response

from . import cookie_loader
from .jwt_auth import JWTAuthConfig, JWTAuthMiddleware, JWTVerifier
from .oauth_provider import SinglePasscodeOAuthProvider

# Configure logging to stderr (required for stdio transport)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(sys.stderr)],
)
logger = logging.getLogger("myfitnesspal_mcp")


# Configure transport security based on mode
# When running in HTTP mode (0.0.0.0), we need to either disable DNS rebinding
# protection or configure allowed hosts via MCP_ALLOWED_HOSTS env var
def _get_transport_security() -> TransportSecuritySettings | None:
    """Get transport security settings based on environment."""
    transport = os.getenv("MCP_TRANSPORT", "stdio")
    if transport != "streamable-http":
        return None  # Use FastMCP defaults for stdio

    # Check for explicitly configured allowed hosts
    allowed_hosts_str = os.getenv("MCP_ALLOWED_HOSTS", "")
    if allowed_hosts_str:
        allowed_hosts = [h.strip() for h in allowed_hosts_str.split(",") if h.strip()]
        # Also allow localhost for local testing
        allowed_hosts.extend(["127.0.0.1:*", "localhost:*", "[::1]:*"])
        return TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=allowed_hosts,
            allowed_origins=[],  # Allow any origin (MCP clients aren't browsers)
        )

    # No allowed hosts configured - disable DNS rebinding protection for remote access
    return TransportSecuritySettings(enable_dns_rebinding_protection=False)


# Configure OAuth for remote MCP connectors (Claude, ChatGPT), which require
# full OAuth 2.1 + dynamic client registration rather than a bare bearer
# token. Gated behind MCP_OAUTH_PASSCODE/MCP_RESOURCE_URL so local stdio use
# and simple Docker testing don't need to set any of this up.
def _build_oauth() -> tuple[SinglePasscodeOAuthProvider | None, AuthSettings | None]:
    """Build the OAuth provider/settings pair, or (None, None) if unconfigured.

    Raises RuntimeError if exactly one of MCP_OAUTH_PASSCODE/MCP_RESOURCE_URL
    is set. That combination is almost always a misconfiguration (e.g. a
    passcode that resolved empty due to a missing .env line or shell/compose
    variable-expansion mangling it), not an intentional choice - silently
    falling back to no-auth in that case would serve every tool unauthenticated
    on the public internet with nothing louder than a warning log line.
    """
    transport = os.getenv("MCP_TRANSPORT", "stdio")
    if transport != "streamable-http":
        return None, None

    passcode = os.getenv("MCP_OAUTH_PASSCODE")
    resource_url = os.getenv("MCP_RESOURCE_URL")

    if not passcode and not resource_url:
        logging.getLogger(__name__).warning(
            "MCP_TRANSPORT=streamable-http with no MCP_OAUTH_PASSCODE/"
            "MCP_RESOURCE_URL set - running WITHOUT OAuth. Do not expose "
            "this deployment to the internet without configuring both."
        )
        return None, None

    if not passcode or not resource_url:
        missing = "MCP_OAUTH_PASSCODE" if not passcode else "MCP_RESOURCE_URL"
        raise RuntimeError(
            f"{missing} is unset but the other OAuth variable is set - this "
            "looks like a misconfiguration, not an intentional no-auth "
            "deployment. Refusing to start rather than silently serving the "
            "MCP endpoint without authentication. Set both "
            "MCP_OAUTH_PASSCODE and MCP_RESOURCE_URL, or neither."
        )

    provider = SinglePasscodeOAuthProvider(passcode)
    auth_settings = AuthSettings(
        issuer_url=resource_url,
        resource_server_url=resource_url,
        client_registration_options=ClientRegistrationOptions(
            enabled=True, valid_scopes=["mcp"], default_scopes=["mcp"]
        ),
        required_scopes=["mcp"],
    )
    return provider, auth_settings


# MCP_AUTH_MODE selects how the HTTP transport authenticates callers:
#   (unset)         legacy behaviour: passcode OAuth if MCP_OAUTH_PASSCODE and
#                   MCP_RESOURCE_URL are both set, no auth if both are unset,
#                   refuse to start if only one is set.
#   none            explicitly no auth (LAN-only / trusted network).
#   passcode_oauth  the built-in passcode OAuth server; both variables required.
#   oauth           stateless resource server: validate RS256 JWT access tokens
#                   from an external issuer (e.g. Okta); see jwt_auth.py.
AUTH_MODES = ("none", "passcode_oauth", "oauth")


def _resolve_auth_mode() -> str | None:
    """Return the configured MCP_AUTH_MODE, or None when unset (legacy)."""
    raw = (os.getenv("MCP_AUTH_MODE") or "").strip().lower()
    if not raw:
        return None
    if raw not in AUTH_MODES:
        raise RuntimeError(
            f"MCP_AUTH_MODE={raw!r} is not one of {', '.join(AUTH_MODES)} "
            "(or unset). Refusing to start."
        )
    return raw


def _build_auth() -> tuple[
    str | None, SinglePasscodeOAuthProvider | None, AuthSettings | None, JWTVerifier | None
]:
    """Resolve (mode, passcode provider, auth settings, JWT verifier) from env."""
    mode = _resolve_auth_mode()
    log = logging.getLogger(__name__)

    if mode == "oauth":
        # Validate even for stdio so a broken config is never silently ignored.
        verifier = JWTVerifier(JWTAuthConfig.from_env(os.environ))
        if os.getenv("MCP_OAUTH_PASSCODE"):
            log.warning("MCP_AUTH_MODE=oauth: ignoring MCP_OAUTH_PASSCODE (passcode OAuth is disabled).")
        return mode, None, None, verifier

    if mode == "none":
        if os.getenv("MCP_TRANSPORT", "stdio") == "streamable-http":
            log.warning(
                "MCP_AUTH_MODE=none - serving /mcp WITHOUT authentication. "
                "Do not expose this deployment to the internet."
            )
        return mode, None, None, None

    if mode == "passcode_oauth" and os.getenv("MCP_TRANSPORT", "stdio") == "streamable-http":
        missing = [v for v in ("MCP_OAUTH_PASSCODE", "MCP_RESOURCE_URL") if not os.getenv(v)]
        if missing:
            raise RuntimeError(
                f"MCP_AUTH_MODE=passcode_oauth requires {' and '.join(missing)}. "
                "Refusing to start rather than serving the MCP endpoint without authentication."
            )

    provider, auth_settings = _build_oauth()
    return mode, provider, auth_settings, None


_auth_mode, _oauth_provider, _auth_settings, _jwt_verifier = _build_auth()

# Initialize MCP server
mcp = FastMCP(
    "MyFitnessPal MCP",
    dependencies=["myfitnesspal", "httpx"],
    host=os.getenv("MCP_HOST", "127.0.0.1"),
    port=int(os.getenv("MCP_PORT", "8000")),
    transport_security=_get_transport_security(),
    auth=_auth_settings,
    auth_server_provider=_oauth_provider,
)

_LOGIN_FORM = """
<!doctype html>
<html>
<head><title>MyFitnessPal MCP - Sign in</title></head>
<body style="font-family: sans-serif; max-width: 24rem; margin: 4rem auto;">
  <h2>MyFitnessPal MCP</h2>
  <p>{message}</p>
  <form method="post">
    <input type="hidden" name="login_id" value="{login_id}">
    <input type="password" name="passcode" placeholder="Passcode" autofocus
           style="width: 100%; padding: 0.5rem; font-size: 1rem;">
    <button type="submit" style="margin-top: 0.75rem; padding: 0.5rem 1rem;">Continue</button>
  </form>
</body>
</html>
"""


if _oauth_provider is not None:

    @mcp.custom_route("/login", methods=["GET", "POST"])
    async def login(request: Request) -> Response:
        """Passcode gate standing in for a real login screen (see oauth_provider)."""
        if request.method == "GET":
            login_id = request.query_params.get("login_id", "")
        else:
            form = await request.form()
            login_id = str(form.get("login_id", ""))

        if not login_id or _oauth_provider.get_pending(login_id) is None:
            return HTMLResponse(
                _LOGIN_FORM.format(message="This login link has expired. Please retry from your MCP client.", login_id=""),
                status_code=400,
            )

        if request.method == "GET":
            return HTMLResponse(_LOGIN_FORM.format(message="Enter the server passcode to continue.", login_id=login_id))

        form = await request.form()
        passcode = str(form.get("passcode", ""))
        if not _oauth_provider.verify_passcode(passcode):
            return HTMLResponse(
                _LOGIN_FORM.format(message="Incorrect passcode, try again.", login_id=login_id),
                status_code=401,
            )

        redirect_url = _oauth_provider.complete_login(login_id)
        if redirect_url is None:
            return HTMLResponse(
                _LOGIN_FORM.format(message="This login link has expired. Please retry from your MCP client.", login_id=""),
                status_code=400,
            )
        return RedirectResponse(redirect_url, status_code=302)


# ============================================================================
# Authentication
# ============================================================================

_client_lock = threading.Lock()
_cached_client: Any = None
_cached_jar: Optional[CookieJar] = None


def create_mfp_client(cookiejar: Optional[CookieJar] = None):
    """
    Create a MyFitnessPal client using a plain requests-backed session.

    python-myfitnesspal builds its session with ``cloudscraper.create_scraper``.
    On some hosts that path gets a 403 from ``/user/auth_token`` (called during
    ``Client.__init__``) even when the exact same authenticated cookies work
    fine with a plain ``requests`` session. We temporarily monkeypatch
    ``myfitnesspal.client.cloudscraper.create_scraper`` to hand back the plain
    ``requests.Session`` the library already passes in as ``sess``, then restore
    it immediately. Everything else about the client (cookie handling, headers,
    ``session.get``/``session.post``) is unchanged, so this is a minimal and
    reversible swap.

    Ported from AdamWalt/myfitnesspal-mcp-python#1.
    """
    import requests
    import myfitnesspal
    import myfitnesspal.client as myfitnesspal_client

    original_create_scraper = myfitnesspal_client.cloudscraper.create_scraper
    myfitnesspal_client.cloudscraper.create_scraper = (
        lambda sess=None, *args, **kwargs: (sess or requests.Session())
    )
    try:
        if cookiejar is None:
            return myfitnesspal.Client()
        return myfitnesspal.Client(cookiejar=cookiejar)
    finally:
        myfitnesspal_client.cloudscraper.create_scraper = original_create_scraper


def get_mfp_client():
    """
    Get an authenticated MyFitnessPal client.

    Session cookies are loaded via cookie_loader (Firefox profile mount or
    JSON cookies file). The client is cached and only rebuilt when the
    underlying cookie source changes (cookie_loader returns the same jar
    object while the source file is unchanged).

    Returns:
        myfitnesspal.Client: Authenticated client instance

    Raises:
        RuntimeError: If no cookie source is configured or readable
    """
    global _cached_client, _cached_jar

    jar = cookie_loader.get_cookiejar()
    with _client_lock:
        if _cached_client is not None and _cached_jar is jar:
            return _cached_client
        logger.info("Building MyFitnessPal client from cookie jar (%d cookies)", len(jar))
        client = create_mfp_client(cookiejar=jar)
        _cached_client = client
        _cached_jar = jar
        return client


# ============================================================================
# Data Formatting Helper Functions
# ============================================================================


def parse_date(date_str: Optional[str] = None) -> date:
    """
    Parse a date string or return today's date.

    Args:
        date_str: Date in YYYY-MM-DD format, or None for today

    Returns:
        date: Parsed date object
    """
    if date_str is None:
        return date.today()
    return datetime.strptime(date_str, "%Y-%m-%d").date()


def format_nutrition_dict(nutrition: Dict[str, Any]) -> Dict[str, Any]:
    """
    Format nutrition dictionary for consistent output.

    Args:
        nutrition: Raw nutrition dictionary

    Returns:
        dict: Formatted nutrition data
    """
    formatted = {}
    for key, value in nutrition.items():
        if hasattr(value, "magnitude"):
            # Handle pint quantities
            formatted[key] = float(value.magnitude)
        else:
            formatted[key] = value
    return formatted


def format_meal_entry(entry, entry_id: Optional[str] = None) -> Dict[str, Any]:
    """
    Format a meal entry for output.

    Args:
        entry: MFP Entry object
        entry_id: Optional stable diary-entry ID (surfaced so callers can
            target the entry with mfp_update_food_entry / mfp_delete_food_entry)

    Returns:
        dict: Formatted entry data
    """
    data = {
        "name": entry.name,
        "short_name": getattr(entry, "short_name", None),
        "quantity": getattr(entry, "quantity", None),
        "unit": getattr(entry, "unit", None),
        "nutrition": format_nutrition_dict(entry.totals),
    }
    if entry_id:
        data["entry_id"] = entry_id
    return data


def format_exercise(exercise) -> Dict[str, Any]:
    """
    Format an exercise object for output.

    Args:
        exercise: MFP Exercise object

    Returns:
        dict: Formatted exercise data
    """
    entries = exercise.get_as_list()
    return {"name": exercise.name, "entries": entries}


def ordered_dict_to_dict(od: OrderedDict) -> Dict[str, Any]:
    """
    Convert OrderedDict with date keys to regular dict with string keys.

    Args:
        od: OrderedDict with date keys

    Returns:
        dict: Regular dict with string keys
    """
    return {str(k): v for k, v in od.items()}


class ResponseFormat(str, Enum):
    """Output format for tool responses."""

    MARKDOWN = "markdown"
    JSON = "json"


def format_response(data: Any, format_type: ResponseFormat, title: str = "") -> str:
    """
    Format response data based on requested format.

    Args:
        data: Data to format
        format_type: Output format (markdown or json)
        title: Optional title for markdown format

    Returns:
        str: Formatted response string
    """
    if format_type == ResponseFormat.JSON:
        return json.dumps(data, indent=2, default=str)

    # Markdown format
    lines = []
    if title:
        lines.append(f"## {title}\n")

    if isinstance(data, dict):
        for key, value in data.items():
            if isinstance(value, dict):
                lines.append(f"### {key}")
                for k, v in value.items():
                    lines.append(f"- **{k}**: {v}")
            elif isinstance(value, list):
                lines.append(f"### {key}")
                for item in value:
                    if isinstance(item, dict):
                        lines.append(f"- {item.get('name', str(item))}")
                        for k, v in item.items():
                            if k != "name":
                                lines.append(f"  - {k}: {v}")
                    else:
                        lines.append(f"- {item}")
            else:
                lines.append(f"- **{key}**: {value}")
    else:
        lines.append(str(data))

    return "\n".join(lines)


# ============================================================================
# Pydantic Input Models
# ============================================================================


class GetDiaryInput(BaseModel):
    """Input model for getting food diary."""

    model_config = ConfigDict(str_strip_whitespace=True)

    date: Optional[str] = Field(
        default=None,
        description="Date in YYYY-MM-DD format. Defaults to today if not specified.",
        pattern=r"^\d{4}-\d{2}-\d{2}$",
    )
    response_format: ResponseFormat = Field(
        default=ResponseFormat.MARKDOWN,
        description="Output format: 'markdown' for human-readable or 'json' for structured data",
    )


class SearchFoodInput(BaseModel):
    """Input model for searching foods."""

    model_config = ConfigDict(str_strip_whitespace=True)

    query: str = Field(
        ...,
        description="Search query for food items (e.g., 'chicken breast', 'apple')",
        min_length=1,
        max_length=200,
    )
    limit: int = Field(
        default=10,
        description="Maximum number of results to return",
        ge=1,
        le=50,
    )
    response_format: ResponseFormat = Field(
        default=ResponseFormat.MARKDOWN,
        description="Output format: 'markdown' for human-readable or 'json' for structured data",
    )


class GetFoodDetailsInput(BaseModel):
    """Input model for getting food item details."""

    model_config = ConfigDict(str_strip_whitespace=True)

    mfp_id: str = Field(
        ...,
        description="MyFitnessPal food item ID (obtained from search results)",
        min_length=1,
    )
    response_format: ResponseFormat = Field(
        default=ResponseFormat.MARKDOWN,
        description="Output format: 'markdown' for human-readable or 'json' for structured data",
    )


class GetFoodCollectionInput(BaseModel):
    """Input model for fetching recent, frequent, or saved foods."""

    model_config = ConfigDict(str_strip_whitespace=True)

    limit: Optional[int] = Field(
        default=None,
        description="Maximum number of foods to return",
        ge=1,
        le=100,
    )
    response_format: ResponseFormat = Field(
        default=ResponseFormat.MARKDOWN,
        description="Output format: 'markdown' for human-readable or 'json' for structured data",
    )


class GetMeasurementsInput(BaseModel):
    """Input model for getting measurements."""

    model_config = ConfigDict(str_strip_whitespace=True)

    measurement: str = Field(
        default="Weight",
        description="Type of measurement to retrieve (e.g., 'Weight', 'Body Fat', 'Waist')",
    )
    start_date: Optional[str] = Field(
        default=None,
        description="Start date in YYYY-MM-DD format. Defaults to 30 days ago.",
        pattern=r"^\d{4}-\d{2}-\d{2}$",
    )
    end_date: Optional[str] = Field(
        default=None,
        description="End date in YYYY-MM-DD format. Defaults to today.",
        pattern=r"^\d{4}-\d{2}-\d{2}$",
    )
    response_format: ResponseFormat = Field(
        default=ResponseFormat.MARKDOWN,
        description="Output format: 'markdown' for human-readable or 'json' for structured data",
    )


class SetMeasurementInput(BaseModel):
    """Input model for setting a measurement."""

    model_config = ConfigDict(str_strip_whitespace=True)

    measurement: str = Field(
        default="Weight",
        description="Type of measurement to set (e.g., 'Weight', 'Body Fat', 'Waist')",
    )
    value: float = Field(
        ...,
        description="Measurement value (e.g., 185.5 for weight in lbs)",
        gt=0,
    )


class GetExercisesInput(BaseModel):
    """Input model for getting exercises."""

    model_config = ConfigDict(str_strip_whitespace=True)

    date: Optional[str] = Field(
        default=None,
        description="Date in YYYY-MM-DD format. Defaults to today if not specified.",
        pattern=r"^\d{4}-\d{2}-\d{2}$",
    )
    response_format: ResponseFormat = Field(
        default=ResponseFormat.MARKDOWN,
        description="Output format: 'markdown' for human-readable or 'json' for structured data",
    )


class GetGoalsInput(BaseModel):
    """Input model for getting nutrition goals."""

    model_config = ConfigDict(str_strip_whitespace=True)

    date: Optional[str] = Field(
        default=None,
        description="Date in YYYY-MM-DD format. Defaults to today if not specified.",
        pattern=r"^\d{4}-\d{2}-\d{2}$",
    )
    response_format: ResponseFormat = Field(
        default=ResponseFormat.MARKDOWN,
        description="Output format: 'markdown' for human-readable or 'json' for structured data",
    )


class SetGoalsInput(BaseModel):
    """Input model for setting nutrition goals."""

    model_config = ConfigDict(str_strip_whitespace=True)

    calories: Optional[int] = Field(
        default=None,
        description="Daily calorie goal (e.g., 2000)",
        ge=500,
        le=10000,
    )
    protein: Optional[int] = Field(
        default=None,
        description="Daily protein goal in grams (e.g., 150)",
        ge=0,
        le=1000,
    )
    carbohydrates: Optional[int] = Field(
        default=None,
        description="Daily carbohydrate goal in grams (e.g., 200)",
        ge=0,
        le=2000,
    )
    fat: Optional[int] = Field(
        default=None,
        description="Daily fat goal in grams (e.g., 65)",
        ge=0,
        le=500,
    )


class GetWaterInput(BaseModel):
    """Input model for getting water intake."""

    model_config = ConfigDict(str_strip_whitespace=True)

    date: Optional[str] = Field(
        default=None,
        description="Date in YYYY-MM-DD format. Defaults to today if not specified.",
        pattern=r"^\d{4}-\d{2}-\d{2}$",
    )


class GetStepsInput(BaseModel):
    """Input model for getting daily step counts."""

    model_config = ConfigDict(str_strip_whitespace=True)

    start_date: Optional[str] = Field(
        default=None,
        description="Start date in YYYY-MM-DD format. Defaults to 6 days before end_date (7 days total).",
        pattern=r"^\d{4}-\d{2}-\d{2}$",
    )
    end_date: Optional[str] = Field(
        default=None,
        description="End date in YYYY-MM-DD format. Defaults to today.",
        pattern=r"^\d{4}-\d{2}-\d{2}$",
    )
    response_format: ResponseFormat = Field(
        default=ResponseFormat.MARKDOWN,
        description="Output format: 'markdown' for human-readable or 'json' for structured data",
    )

class GetReportInput(BaseModel):
    """Input model for getting nutrition reports."""

    model_config = ConfigDict(str_strip_whitespace=True)

    report_name: str = Field(
        default="Net Calories",
        description="Report name (e.g., 'Net Calories', 'Total Calories', 'Protein', 'Fat', 'Carbs')",
    )
    start_date: Optional[str] = Field(
        default=None,
        description="Start date in YYYY-MM-DD format. Defaults to 7 days ago.",
        pattern=r"^\d{4}-\d{2}-\d{2}$",
    )
    end_date: Optional[str] = Field(
        default=None,
        description="End date in YYYY-MM-DD format. Defaults to today.",
        pattern=r"^\d{4}-\d{2}-\d{2}$",
    )
    response_format: ResponseFormat = Field(
        default=ResponseFormat.MARKDOWN,
        description="Output format: 'markdown' for human-readable or 'json' for structured data",
    )


class AddFoodToDiaryInput(BaseModel):
    """Input model for adding food to diary."""

    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    mfp_id: str = Field(
        ...,
        description="MyFitnessPal food item ID (obtained from mfp_search_food)",
        min_length=1,
    )
    meal: str = Field(
        default="Breakfast",
        description="Meal name (e.g., 'Breakfast', 'Lunch', 'Dinner', 'Snacks')",
    )
    date: Optional[str] = Field(
        default=None,
        description="Date in YYYY-MM-DD format. Defaults to today if not specified.",
        pattern=r"^\d{4}-\d{2}-\d{2}$",
    )
    quantity: float = Field(
        default=1.0,
        description=(
            "Quantity in number of default servings (e.g., 1.5 for 1.5 servings). "
            "The 'default serving' is the first weight option for the food in "
            "MyFitnessPal -- call mfp_get_food_details(mfp_id) to see what the "
            "default unit actually is for any given food."
        ),
        gt=0,
        le=10000,
    )


class CreateFoodInput(BaseModel):
    """Input model for creating a new custom food in the MyFitnessPal database."""

    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    description: str = Field(
        ...,
        description="Food name/description (e.g., 'Bluecorn Tortilla Chips').",
        min_length=1,
    )
    brand: str = Field(
        default="",
        description="Brand or manufacturer (e.g., 'ICA Selection'). Leave empty for a generic/homemade food.",
    )
    # Core macros (per serving). Required by MyFitnessPal.
    calories: float = Field(..., description="Calories per serving (kcal).", ge=0)
    fat: float = Field(..., description="Total fat per serving (g).", ge=0)
    carbs: float = Field(..., description="Total carbohydrates per serving (g).", ge=0)
    protein: float = Field(..., description="Protein per serving (g).", ge=0)
    # Optional nutrients (per serving). Omit any that are unknown.
    saturated_fat: Optional[float] = Field(default=None, description="Saturated fat (g).", ge=0)
    polyunsaturated_fat: Optional[float] = Field(default=None, description="Polyunsaturated fat (g).", ge=0)
    monounsaturated_fat: Optional[float] = Field(default=None, description="Monounsaturated fat (g).", ge=0)
    trans_fat: Optional[float] = Field(default=None, description="Trans fat (g).", ge=0)
    fiber: Optional[float] = Field(default=None, description="Dietary fiber (g).", ge=0)
    sugar: Optional[float] = Field(default=None, description="Sugars (g).", ge=0)
    sodium: Optional[float] = Field(default=None, description="Sodium (mg).", ge=0)
    potassium: Optional[float] = Field(default=None, description="Potassium (mg).", ge=0)
    cholesterol: Optional[float] = Field(default=None, description="Cholesterol (mg).", ge=0)
    vitamin_a: Optional[float] = Field(default=None, description="Vitamin A (% daily value).", ge=0)
    vitamin_c: Optional[float] = Field(default=None, description="Vitamin C (% daily value).", ge=0)
    calcium: Optional[float] = Field(default=None, description="Calcium (% daily value).", ge=0)
    iron: Optional[float] = Field(default=None, description="Iron (% daily value).", ge=0)
    # Serving definition.
    serving_size: str = Field(
        default="1 Serving",
        description="Serving-size label, e.g. '1 Serving', '30 g', '100 ml'. Nutrition values above are per this serving.",
    )
    servings_per_container: float = Field(
        default=1.0,
        description="Number of servings per container/package.",
        gt=0,
    )
    share_public: bool = Field(
        default=False,
        description="If true, submit the food to the public MyFitnessPal database; otherwise keep it private to your account.",
    )


class UpdateFoodEntryInput(BaseModel):
    """Input model for updating an existing diary entry."""

    model_config = ConfigDict(str_strip_whitespace=True)

    entry_id: str = Field(
        ...,
        description="Diary entry ID from mfp_get_diary",
        min_length=1,
    )
    date: Optional[str] = Field(
        default=None,
        description="Diary date in YYYY-MM-DD format. Required for historical entries; defaults to today.",
        pattern=r"^\d{4}-\d{2}-\d{2}$",
    )
    meal: Optional[str] = Field(
        default=None,
        description="New meal name (e.g., 'Breakfast', 'Lunch', 'Dinner', 'Snacks').",
    )
    quantity: Optional[float] = Field(
        default=None,
        description="New quantity/servings.",
        gt=0,
        le=100,
    )
    unit: Optional[str] = Field(
        default=None,
        description="New serving size label exactly as shown by MyFitnessPal (for example '350 ml').",
    )
    weight_id: Optional[str] = Field(
        default=None,
        description="Raw MyFitnessPal serving-size option ID. Overrides `unit` when both are provided.",
        min_length=1,
    )


class DeleteFoodEntryInput(BaseModel):
    """Input model for deleting an existing diary entry."""

    model_config = ConfigDict(str_strip_whitespace=True)

    entry_id: str = Field(
        ...,
        description="Diary entry ID from mfp_get_diary",
        min_length=1,
    )
    date: Optional[str] = Field(
        default=None,
        description="Diary date in YYYY-MM-DD format. Required for historical entries; defaults to today.",
        pattern=r"^\d{4}-\d{2}-\d{2}$",
    )


class SetWaterInput(BaseModel):
    """Input model for setting water intake."""

    model_config = ConfigDict(str_strip_whitespace=True)

    cups: float = Field(
        ...,
        description="Number of cups of water (e.g., 2.5 for 2.5 cups). Note: MyFitnessPal uses cups as the unit.",
        ge=0,
        le=50,
    )
    date: Optional[str] = Field(
        default=None,
        description="Date in YYYY-MM-DD format. Defaults to today if not specified.",
        pattern=r"^\d{4}-\d{2}-\d{2}$",
    )


# ============================================================================
# Diary Entry Creation Helper Functions
# ============================================================================


def add_food_to_diary(
    client, mfp_id: str, meal: str, target_date: date, quantity: float = 1.0,
) -> None:
    """
    Add a food item to the diary for a specific date and meal.

    Uses the modern MFP add flow (the legacy /food/diary/{user}/add endpoint
    this used to target was retired by MyFitnessPal and now 404s -- every
    write silently no-op'd):
      1. Visit /food/add_to_diary?meal=X to get the page CSRF
      2. POST /food/search to find the food and capture its `data-original-id`
         + `data-weight-ids` + the page's csrf-token meta
      3. POST /food/add with food_entry[food_id]=original_id (NOT mfp_id),
         food_entry[meal_id]=index, food_entry[weight_id]=first weight id

    The food's default weight_id (first one MFP exposes for the food) is
    always used. The quantity is in units of that default serving.

    Raises RuntimeError if no search result exactly matches the requested
    mfp_id -- we do NOT silently substitute another food, because adding the
    wrong item to a diary is materially worse than failing the call.

    Args:
        client: Authenticated myfitnesspal.Client instance
        mfp_id: MyFitnessPal external food ID (from search results)
        meal: Meal name (Breakfast, Lunch, Dinner, Snacks)
        target_date: Date to add the food entry
        quantity: Number of default servings (default 1.0)
    """
    import re

    meal_map = {"breakfast": "0", "lunch": "1", "dinner": "2",
                "snacks": "3", "snack": "3"}
    meal_index = meal_map.get(meal.lower(), "0")
    date_str = target_date.strftime("%Y-%m-%d")

    try:
        # Step 1: Visit the diary page so Rails session cookies are present.
        client._get_document_for_url(
            f"{client.BASE_URL_SECURE}food/diary"
        )

        # Step 2: Get the add_to_diary page (needed for CSRF + warm form session)
        add_page_url = (
            f"{client.BASE_URL_SECURE}food/add_to_diary?meal={meal_index}"
        )
        add_page_doc = client._get_document_for_url(add_page_url)
        page_auth = add_page_doc.xpath(
            "(//input[@name='authenticity_token']/@value)[1]"
        )
        if not page_auth:
            raise RuntimeError("Could not find authenticity token on add_to_diary page")
        page_auth = page_auth[0]

        # Step 3: Get the food's name so we can search for it.
        # MFP's search box doesn't accept mfp_ids directly -- only names.
        try:
            food_item = client.get_food_item_details(mfp_id)
            brand = getattr(food_item, "brand", "") or ""
            name = getattr(food_item, "name", "") or ""
            search_query = f"{brand} {name}".strip() or str(mfp_id)
        except Exception as details_err:
            # If we can't resolve the food's name, the id may simply be
            # invalid. Continue with the id as the query so the search step
            # gives a clean "no results" error, which is more actionable
            # than the lxml/HTTP failure here.
            logger.warning(
                f"Could not fetch details for food {mfp_id}: {details_err}"
            )
            search_query = str(mfp_id)

        # Trim to a reasonable length for the search box
        if len(search_query) > 60:
            search_query = search_query[:60]

        search_url = f"{client.BASE_URL_SECURE}food/search"
        search_resp = client.session.post(search_url, data={
            "authenticity_token": page_auth,
            "meal_name": meal,
            "search": search_query,
            "date": date_str,
            "page": "1",
        })
        search_html = search_resp.text

        # Find the link whose data-external-id matches mfp_id exactly.
        # We deliberately do NOT fall back to "first result" if the exact
        # match isn't there -- silently adding the wrong food to a diary
        # is a far worse failure mode than raising. The caller can use
        # mfp_search_food to pick a more specific id and retry.
        link_match = re.search(
            r'<a[^>]+class="search"[^>]+data-external-id="' + re.escape(str(mfp_id)) + r'"[^>]+data-original-id="(\d+)"[^>]+data-weight-ids="([^"]+)"',
            search_html,
        )
        if not link_match:
            # See if ANY results came back, to give the caller a hint about
            # whether the issue is "wrong id" vs "search returned nothing".
            has_any_results = bool(re.search(
                r'<a[^>]+class="search"[^>]+data-external-id=',
                search_html,
            ))
            if has_any_results:
                raise RuntimeError(
                    f"Food {mfp_id} (search query '{search_query}') was not "
                    "in the first page of search results. The mfp_id may be "
                    "stale or the food may be hard to surface from its name. "
                    "Try mfp_search_food with a more specific query, pick a "
                    "result whose mfp_id appears in the returned list, then "
                    "retry mfp_add_food_to_diary with that id."
                )
            raise RuntimeError(
                f"No search results returned for food {mfp_id} "
                f"(query '{search_query}'). Try mfp_search_food directly "
                "to find a valid id, then retry."
            )
        original_id = link_match.group(1)
        weight_ids = link_match.group(2).split(",")

        # CSRF tokens from the search results page
        page_csrf_match = re.search(
            r'<meta[^>]+name=["\']csrf-token["\'][^>]+content=["\']([^"\']+)["\']',
            search_html,
        )
        page_csrf = page_csrf_match.group(1) if page_csrf_match else None

        results_auth_matches = re.findall(
            r'authenticity_token["\'][^>]*value=["\']([^"\']+)["\']',
            search_html,
        )
        results_auth = results_auth_matches[0] if results_auth_matches else page_auth

        # Step 4: POST /food/add with the modern field names
        add_url = f"{client.BASE_URL_SECURE}food/add"
        payload = {
            "authenticity_token": results_auth,
            "food_entry[food_id]": original_id,
            "food_entry[date]": date_str,
            "food_entry[quantity]": str(quantity),
            "food_entry[weight_id]": weight_ids[0],
            "food_entry[meal_id]": meal_index,
        }
        headers = {
            "Referer": search_url,
            "Origin": "https://www.myfitnesspal.com",
        }
        if page_csrf:
            headers["X-CSRF-Token"] = page_csrf

        response = client.session.post(
            add_url, data=payload, headers=headers, allow_redirects=False
        )

        # Success = 302 redirect to /food/diary/* . Failure = 200 with form,
        # or 302 to /account/login, or 4xx.
        loc = response.headers.get("Location", "")
        if response.status_code in (302, 303) and "/food/diary" in loc:
            logger.info(
                f"Successfully added food {mfp_id} -> original_id={original_id} "
                f"to {meal} for {target_date}"
            )
            return
        if response.status_code in (302, 303) and "/account/login" in loc:
            raise RuntimeError(
                "Add failed: session not authenticated for write. "
                "Refresh the session cookie."
            )
        raise RuntimeError(
            f"Add failed: HTTP {response.status_code} -> {loc or '(no redirect)'}"
        )

    except RuntimeError:
        raise
    except Exception as e:
        raise RuntimeError(f"Failed to add food to diary: {e}")


def set_water_intake(client, target_date: date, cups: float) -> None:
    """
    Set water intake for a specific date.

    The diary page is now a client-rendered (Next.js) page with no
    server-rendered <form> for water, so there's no per-form authenticity
    token to scrape the way the old measurements/food forms worked. The
    live site's own `food/diary/water-*.js` bundle does a plain jQuery
    `$.post("/food/water", {milliliters, date})`, authenticated the same
    way every other jQuery-rails AJAX call on the site is: the global
    `X-CSRF-Token` header sourced from the page's `<meta name="csrf-token">`
    tag, not a body field. Confirmed by probing the live endpoint directly
    (2026-08-11): POSTing to `food/water` (no username, no `/diary/`
    prefix) with `milliliters`/`date` form fields plus that header returns
    the updated `{"item": {"date", "milliliters"}}` and persists.

    Args:
        client: Authenticated myfitnesspal.Client instance
        target_date: Date to set water intake
        cups: Number of cups of water

    Raises:
        RuntimeError: If the operation fails
    """
    import re
    from urllib import parse

    try:
        date_str = target_date.strftime("%Y-%m-%d")

        # Any logged-in page carries the same site-wide CSRF meta tag; the
        # diary page is as good as any and lets us reuse the existing
        # cookie-authenticated session.
        diary_url = parse.urljoin(client.BASE_URL_SECURE, "food/diary")
        page = client.session.get(diary_url, timeout=30)
        page.raise_for_status()

        csrf_match = re.search(
            r'<meta name="csrf-token" content="([^"]+)"', page.text
        )
        if not csrf_match:
            raise RuntimeError("Could not find csrf-token meta tag on diary page")
        csrf_token = csrf_match.group(1)

        water_url = parse.urljoin(client.BASE_URL_SECURE, "food/water")
        headers = {
            "X-CSRF-Token": csrf_token,
            "X-Requested-With": "XMLHttpRequest",
            "Referer": diary_url,
        }
        milliliters = round(cups * 236.588, 2)

        response = client.session.post(
            water_url,
            data={"milliliters": milliliters, "date": date_str},
            headers=headers,
            timeout=30,
        )
        response.raise_for_status()

        logger.info(f"Successfully set water intake to {cups} cups for {target_date}")

    except Exception as e:
        # Don't expose internal error details to avoid leaking sensitive information
        error_msg = str(e)
        # Only include safe error information
        if "HTTP" in error_msg or "status" in error_msg.lower():
            raise RuntimeError(f"Failed to set water intake: {error_msg}")
        else:
            raise RuntimeError("Failed to set water intake. Please check your authentication and try again.")


# ============================================================================
# Food Collection & Diary Entry Edit Helper Functions
# ============================================================================
#
# Ported from AdamWalt/myfitnesspal-mcp-python#1. These back the recent/
# frequent/my-foods reads (via the legacy add-to-diary AJAX endpoints) and the
# update/delete diary-entry writes. python-myfitnesspal parses entry nutrition
# but discards the stable diary-entry IDs needed for edit/delete, so we scrape
# them off the diary page ourselves.


def get_diary_page_url(client, target_date: date) -> str:
    """Build the MyFitnessPal diary URL for a specific user and date."""
    from urllib import parse

    date_str = target_date.strftime("%Y-%m-%d")
    return parse.urljoin(
        client.BASE_URL_SECURE,
        f"food/diary/{client.effective_username}?date={date_str}",
    )


def get_diary_document(client, target_date: date):
    """Fetch the diary page document for a specific date."""
    return client._get_document_for_url(get_diary_page_url(client, target_date))


def extract_authenticity_token(document) -> str:
    """Extract the Rails authenticity token from a diary or edit form."""
    authenticity_token = document.xpath("(//input[@name='authenticity_token']/@value)[1]")
    if not authenticity_token:
        raise RuntimeError("Could not find authenticity token on the page")
    return authenticity_token[0]


def extract_csrf_param_and_token(document) -> Tuple[str, str]:
    """Extract the Rails CSRF param/token pair from page metadata or forms."""
    csrf_param = document.xpath("string(//meta[@name='csrf-param']/@content)") or "authenticity_token"
    csrf_token = document.xpath("string(//meta[@name='csrf-token']/@content)")
    if not csrf_token:
        csrf_token = extract_authenticity_token(document)
    return csrf_param, csrf_token


def normalize_meal_name(meal: str) -> str:
    """Normalize a meal name for comparisons and routing."""
    normalized = meal.strip().lower()
    if normalized == "snack":
        return "snacks"
    return normalized


def meal_name_to_id(meal: str) -> str:
    """Map user-facing meal names to MyFitnessPal's meal IDs."""
    meal_map = {
        "breakfast": "0",
        "lunch": "1",
        "dinner": "2",
        "snacks": "3",
        "snack": "3",
    }
    return meal_map.get(normalize_meal_name(meal), "0")


def meal_id_to_name(meal_id: Optional[Any]) -> Optional[str]:
    """Map MyFitnessPal meal IDs back to display names."""
    if meal_id is None:
        return None

    meal_map = {
        0: "Breakfast",
        1: "Lunch",
        2: "Dinner",
        3: "Snacks",
        "0": "Breakfast",
        "1": "Lunch",
        "2": "Dinner",
        "3": "Snacks",
    }
    return meal_map.get(meal_id, str(meal_id))


def get_diary_add_page_url(
    client,
    meal: str = "Breakfast",
    target_date: Optional[date] = None,
) -> str:
    """
    Build the legacy add-to-diary page URL.

    The modern `/food/mine`, `/meal/mine`, and `/food/new` pages can redirect to
    `/account/logout` even when the account is otherwise authenticated. The
    legacy diary-add page still exposes stable AJAX endpoints for recent,
    frequent, and saved foods.
    """
    from urllib import parse

    target_date = target_date or date.today()
    return parse.urljoin(
        client.BASE_URL_SECURE,
        f"user/{client.effective_username}/diary/add?meal={meal_name_to_id(meal)}&date={target_date:%Y-%m-%d}",
    )


def get_diary_add_tab_headers(
    client,
    meal: str = "Breakfast",
    target_date: Optional[date] = None,
) -> Dict[str, str]:
    """Build the AJAX headers required by the legacy add-page tab endpoints."""
    add_page_url = get_diary_add_page_url(client, meal=meal, target_date=target_date)
    document = client._get_document_for_url(add_page_url)
    _, csrf_token = extract_csrf_param_and_token(document)
    return {
        "X-Requested-With": "XMLHttpRequest",
        "Referer": add_page_url,
        "Origin": client.BASE_URL_SECURE.rstrip("/"),
        "X-CSRF-Token": csrf_token,
    }


def normalize_food_collection_item(item: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize a legacy add-page item into a stable MCP response shape."""
    food = item.get("food", {})
    weight = item.get("weight") or {}
    brand_name = food.get("brand_name")
    description = food.get("description")
    if brand_name and brand_name != "Generic":
        name = f"{brand_name} - {description}"
    else:
        name = description or brand_name or "Unknown Food"

    nutritional_contents = food.get("nutritional_contents") or {}
    energy = nutritional_contents.get("energy") or {}

    return {
        "name": name,
        "description": description,
        "brand_name": brand_name,
        "date": item.get("date"),
        "meal": meal_id_to_name(item.get("meal_id")),
        "meal_id": item.get("meal_id"),
        "quantity": item.get("quantity"),
        "unit": weight.get("unit"),
        "serving_value": weight.get("value"),
        "nutrition_multiplier": weight.get("nutrition_multiplier"),
        "calories": energy.get("value"),
        "food_id": food.get("id"),
        "food_version": food.get("version"),
        "public": food.get("public"),
        "confirmations": food.get("confirmations"),
        "item_type": item.get("type"),
    }


def fetch_legacy_food_collection(
    client,
    category: str,
    limit: int,
    meal: str = "Breakfast",
    target_date: Optional[date] = None,
) -> List[Dict[str, Any]]:
    """Fetch recent, frequent, or saved foods via the legacy add-page AJAX endpoints."""
    from urllib import parse

    category_map = {
        "recent": "recent",
        "frequent": "most_used",
        "my_foods": "my_foods",
    }
    if category not in category_map:
        raise RuntimeError(f"Unsupported legacy food collection '{category}'")

    headers = get_diary_add_tab_headers(client, meal=meal, target_date=target_date)
    endpoint = parse.urljoin(client.BASE_URL_SECURE, f"food/load_{category_map[category]}")

    items: List[Dict[str, Any]] = []
    base_index = 0
    page = 1
    while len(items) < limit:
        response = client.session.post(
            endpoint,
            data={"meal": meal_name_to_id(meal), "base_index": base_index, "page": page},
            headers=headers,
        )
        response.raise_for_status()
        payload = response.json()
        batch = payload.get("items", [])
        if not batch:
            break

        items.extend(normalize_food_collection_item(item) for item in batch)
        base_index += len(batch)
        page += 1

    return items[:limit]


def extract_diary_entry_ids(client, target_date: date) -> Dict[str, List[Optional[str]]]:
    """
    Extract entry IDs from the diary page, grouped by meal.

    The upstream python-myfitnesspal library parses entry nutrition but discards
    the stable diary-entry IDs needed for edit/delete operations.
    """
    document = get_diary_document(client, target_date)
    entry_ids_by_meal: Dict[str, List[Optional[str]]] = {}

    for meal_header in document.xpath("//tr[@class='meal_header']"):
        meal_name = "".join(meal_header.xpath("./td[1]//text()")).strip().lower()
        ids: List[Optional[str]] = []
        row = meal_header
        while True:
            row = row.getnext()
            if row is None or row.attrib.get("class") is not None:
                break

            entry_link = row.xpath(".//a[@data-food-entry-id][1]")
            if entry_link:
                ids.append(entry_link[0].attrib.get("data-food-entry-id"))
                continue

            delete_link = row.xpath(".//td[contains(@class, 'delete')]//a/@href")
            if delete_link:
                ids.append(delete_link[0].split("/")[-1].split("?")[0])
            else:
                ids.append(None)

        entry_ids_by_meal[meal_name] = ids

    return entry_ids_by_meal


def get_diary_entry_snapshots(client, target_date: date) -> Dict[str, Dict[str, Any]]:
    """Return diary entries keyed by stable entry ID for a given date."""
    day = client.get_date(target_date)
    entry_ids_by_meal = extract_diary_entry_ids(client, target_date)
    snapshots: Dict[str, Dict[str, Any]] = {}

    for meal in day.meals:
        meal_entry_ids = entry_ids_by_meal.get(meal.name.lower(), [])
        for idx, entry in enumerate(meal.entries):
            entry_id = meal_entry_ids[idx] if idx < len(meal_entry_ids) else None
            if not entry_id:
                continue
            snapshot = format_meal_entry(entry, entry_id=entry_id)
            snapshot["meal"] = meal.name
            snapshots[entry_id] = snapshot

    return snapshots


def get_edit_entry_form(client, entry_id: str):
    """Fetch the edit form for a specific diary entry."""
    from urllib import parse
    import lxml.html

    edit_url = parse.urljoin(client.BASE_URL_SECURE, f"food/edit_entry/{entry_id}")
    response = client.session.get(edit_url)
    response.raise_for_status()
    document = lxml.html.document_fromstring(response.text)
    forms = document.xpath("//form[@id='edit_entry_form']")
    if not forms:
        raise RuntimeError(f"Could not load edit form for entry {entry_id}")
    return edit_url, forms[0]


def resolve_weight_id(form, weight_id: Optional[str], unit: Optional[str]) -> str:
    """Resolve the serving-size option to submit back to MyFitnessPal."""
    selected = form.xpath(".//select[@name='food_entry[weight_id]']/option[@selected='selected']/@value")
    if weight_id:
        return weight_id
    if unit:
        wanted = " ".join(unit.split()).lower()
        for option in form.xpath(".//select[@name='food_entry[weight_id]']/option"):
            label = " ".join("".join(option.itertext()).split()).lower()
            if label == wanted:
                return option.attrib["value"]
        raise RuntimeError(f"Serving size '{unit}' was not available for this entry")
    if selected:
        return selected[0]
    first_option = form.xpath(".//select[@name='food_entry[weight_id]']/option[1]/@value")
    if not first_option:
        raise RuntimeError("Could not determine a serving size for this entry")
    return first_option[0]


def find_replacement_entry(
    before_entries: Dict[str, Dict[str, Any]],
    after_entries: Dict[str, Dict[str, Any]],
    original_entry: Dict[str, Any],
    requested_meal: Optional[str],
) -> Optional[Dict[str, Any]]:
    """Find the most likely replacement entry when MyFitnessPal rewrites the entry ID."""
    new_entries = [
        entry for entry_id, entry in after_entries.items() if entry_id not in before_entries
    ]
    if not new_entries:
        return None

    target_meal = normalize_meal_name(requested_meal or original_entry["meal"])
    meal_matches = [
        entry for entry in new_entries if normalize_meal_name(entry["meal"]) == target_meal
    ]
    if len(meal_matches) == 1:
        return meal_matches[0]

    original_short_name = original_entry.get("short_name")
    if original_short_name:
        short_name_matches = [
            entry
            for entry in meal_matches or new_entries
            if entry.get("short_name") == original_short_name
        ]
        if len(short_name_matches) == 1:
            return short_name_matches[0]

    original_name = original_entry["name"]
    name_matches = [
        entry
        for entry in meal_matches or new_entries
        if original_name in entry["name"] or entry["name"] in original_name
    ]
    if len(name_matches) == 1:
        return name_matches[0]

    if len(new_entries) == 1:
        return new_entries[0]

    return None


def update_food_entry(
    client,
    entry_id: str,
    target_date: date,
    meal: Optional[str] = None,
    quantity: Optional[float] = None,
    unit: Optional[str] = None,
    weight_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Update an existing diary entry and return the confirmed resulting entry."""
    from urllib import parse

    before_entries = get_diary_entry_snapshots(client, target_date)
    original_entry = before_entries.get(entry_id)
    if not original_entry:
        raise RuntimeError(f"Diary entry {entry_id} was not found on {target_date}")

    edit_url, form = get_edit_entry_form(client, entry_id)

    def val(xpath: str, default: str = "") -> str:
        result = form.xpath(xpath)
        return result[0] if result else default

    payload = {
        "authenticity_token": val(".//input[@name='authenticity_token']/@value"),
        "food_entry[id]": val(".//input[@name='food_entry[id]']/@value"),
        "food_entry[date]": target_date.strftime("%Y-%m-%d"),
        "food_entry[quantity]": str(quantity if quantity is not None else val(".//input[@name='food_entry[quantity]']/@value")),
        "food_entry[weight_id]": resolve_weight_id(form, weight_id=weight_id, unit=unit),
        "food_entry[meal_id]": meal_name_to_id(meal) if meal else val(".//select[@name='food_entry[meal_id]']/option[@selected='selected']/@value"),
    }

    action = parse.urljoin(client.BASE_URL_SECURE, form.attrib["action"])
    response = client.session.post(
        action,
        data=payload,
        headers={"Referer": edit_url, "Content-Type": "application/x-www-form-urlencoded"},
        allow_redirects=False,
    )
    response.raise_for_status()
    if response.status_code not in (200, 204, 302, 303):
        raise RuntimeError(f"Failed to update food entry: HTTP {response.status_code}")

    after_entries = get_diary_entry_snapshots(client, target_date)
    current_entry = after_entries.get(entry_id)
    if current_entry is None:
        current_entry = find_replacement_entry(before_entries, after_entries, original_entry, meal)
    if current_entry is None:
        raise RuntimeError(f"Updated entry {entry_id} could not be confirmed on {target_date}")

    logger.info(
        "Successfully updated food entry %s for %s (current entry id: %s)",
        entry_id,
        target_date,
        current_entry["entry_id"],
    )
    return {
        "before": original_entry,
        "after": current_entry,
        "entry_id_changed": current_entry["entry_id"] != entry_id,
    }


def delete_food_entry(client, entry_id: str, target_date: date) -> Dict[str, Any]:
    """Delete an existing diary entry and return the deleted entry snapshot."""
    from urllib import parse

    before_entries = get_diary_entry_snapshots(client, target_date)
    existing_entry = before_entries.get(entry_id)
    if not existing_entry:
        raise RuntimeError(f"Diary entry {entry_id} was not found on {target_date}")

    diary_url = get_diary_page_url(client, target_date)
    document = get_diary_document(client, target_date)
    csrf_param, csrf_token = extract_csrf_param_and_token(document)
    delete_url = parse.urljoin(
        client.BASE_URL_SECURE,
        f"food/remove/{entry_id}",
    )

    response = client.session.post(
        delete_url,
        data={"_method": "delete", csrf_param: csrf_token},
        headers={"Referer": diary_url, "Content-Type": "application/x-www-form-urlencoded"},
    )
    response.raise_for_status()
    if response.status_code not in (200, 204, 302, 303):
        raise RuntimeError(f"Failed to delete food entry: HTTP {response.status_code}")

    after_entries = get_diary_entry_snapshots(client, target_date)
    if entry_id in after_entries:
        raise RuntimeError(f"Diary entry {entry_id} still exists after delete")

    logger.info("Successfully deleted food entry %s for %s", entry_id, target_date)
    return existing_entry


# ============================================================================
# MCP Tools
# ============================================================================


@mcp.tool(
    name="mfp_get_diary",
    annotations={
        "title": "Get Food Diary",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def mfp_get_diary(params: GetDiaryInput) -> str:
    """
    Get the food diary for a specific date including all meals and their nutritional information.

    Returns meals (Breakfast, Lunch, Dinner, Snacks) with each food entry's name,
    quantity, and complete nutrition breakdown (calories, protein, carbs, fat, etc.).
    Also includes daily totals and goals.

    Args:
        params: GetDiaryInput containing:
            - date (str, optional): Date in YYYY-MM-DD format, defaults to today
            - response_format (str): 'markdown' or 'json'

    Returns:
        str: Formatted diary data with meals, entries, nutrition, and goals
    """
    try:
        client = get_mfp_client()
        target_date = parse_date(params.date)
        day = client.get_date(target_date)
        entry_ids_by_meal = extract_diary_entry_ids(client, target_date)

        # Build response data
        data = {
            "date": str(target_date),
            "meals": {},
            "daily_totals": {},
            "daily_goals": {},
            "water": day.water,
            "notes": day.notes or "",
        }

        # Process meals
        for meal in day.meals:
            meal_entry_ids = entry_ids_by_meal.get(meal.name.lower(), [])
            if len(meal_entry_ids) != len(meal.entries):
                logger.warning(
                    "Diary entry ID count mismatch for %s on %s: ids=%s entries=%s",
                    meal.name,
                    target_date,
                    len(meal_entry_ids),
                    len(meal.entries),
                )
            meal_data = {
                "entries": [
                    format_meal_entry(
                        entry,
                        entry_id=meal_entry_ids[idx] if idx < len(meal_entry_ids) else None,
                    )
                    for idx, entry in enumerate(meal.entries)
                ],
                "totals": format_nutrition_dict(meal.totals),
            }
            data["meals"][meal.name] = meal_data

        # Get daily totals and goals
        totals = {}
        for entry in day.entries:
            for key, value in entry.totals.items():
                val = float(value.magnitude) if hasattr(value, "magnitude") else value
                totals[key] = totals.get(key, 0) + val
        data["daily_totals"] = totals
        data["daily_goals"] = day.goals

        return format_response(
            data, params.response_format, f"Food Diary for {target_date}"
        )

    except Exception as e:
        return f"Error retrieving diary: {str(e)}"


@mcp.tool(
    name="mfp_search_food",
    annotations={
        "title": "Search Food Database",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def mfp_search_food(params: SearchFoodInput) -> str:
    """
    Search the MyFitnessPal food database for food items.

    Returns a list of matching foods with their name, brand, serving size,
    calories, and MFP ID (which can be used with mfp_get_food_details).

    Args:
        params: SearchFoodInput containing:
            - query (str): Search query (e.g., 'chicken breast')
            - limit (int): Maximum results to return (default 10)
            - response_format (str): 'markdown' or 'json'

    Returns:
        str: List of matching food items with basic nutrition info
    """
    try:
        client = get_mfp_client()
        results = client.get_food_search_results(params.query)

        # Limit results
        results = results[: params.limit]

        data = {"query": params.query, "count": len(results), "results": []}

        for item in results:
            data["results"].append(
                {
                    "name": item.name,
                    "brand": item.brand,
                    "serving": item.serving,
                    "calories": item.calories,
                    "mfp_id": item.mfp_id,
                }
            )

        return format_response(
            data, params.response_format, f"Food Search Results for '{params.query}'"
        )

    except Exception as e:
        return f"Error searching foods: {str(e)}"


@mcp.tool(
    name="mfp_get_food_details",
    annotations={
        "title": "Get Food Item Details",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def mfp_get_food_details(params: GetFoodDetailsInput) -> str:
    """
    Get detailed nutritional information for a specific food item by its MFP ID.

    Returns complete nutrition breakdown including calories, macros (protein, carbs, fat),
    fiber, sugar, sodium, cholesterol, vitamins, minerals, and available serving sizes.

    Args:
        params: GetFoodDetailsInput containing:
            - mfp_id (str): MyFitnessPal food item ID from search results
            - response_format (str): 'markdown' or 'json'

    Returns:
        str: Complete nutritional information for the food item
    """
    try:
        client = get_mfp_client()
        # client.get_food_item_details() scrapes a now-client-rendered page
        # and raises on nearly every food; get_food_v2 is the reliable path.
        food = get_food_v2(client, params.mfp_id)
        nutrition = food.get("nutritional_contents", {}) or {}
        energy = nutrition.get("energy") or {}

        data = {
            "mfp_id": params.mfp_id,
            "description": food.get("description", "N/A"),
            "brand_name": food.get("brand_name") or None,
            "verified": food.get("verified", False),
            "calories": energy.get("value"),
            # nutrition values below are per this many grams of the food
            "nutrition_basis_grams": nutrition.get("grams"),
            "nutrition": {
                "protein": nutrition.get("protein"),
                "carbohydrates": nutrition.get("carbohydrates"),
                "fat": nutrition.get("fat"),
                "fiber": nutrition.get("fiber"),
                "sugar": nutrition.get("sugar"),
                "sodium": nutrition.get("sodium"),
                "cholesterol": nutrition.get("cholesterol"),
                "saturated_fat": nutrition.get("saturated_fat"),
                "polyunsaturated_fat": nutrition.get("polyunsaturated_fat"),
                "monounsaturated_fat": nutrition.get("monounsaturated_fat"),
                "trans_fat": nutrition.get("trans_fat"),
                "potassium": nutrition.get("potassium"),
                "vitamin_a": nutrition.get("vitamin_a"),
                "vitamin_c": nutrition.get("vitamin_c"),
                "calcium": nutrition.get("calcium"),
                "iron": nutrition.get("iron"),
            },
            "servings": [
                f"{s['value']} {s['unit']}" for s in food.get("serving_sizes", [])
            ],
        }

        return format_response(data, params.response_format, "Food Item Details")

    except Exception as e:
        return f"Error getting food details: {str(e)}"


@mcp.tool(
    name="mfp_get_recent_foods",
    annotations={
        "title": "Get Recent Foods",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def mfp_get_recent_foods(params: GetFoodCollectionInput) -> str:
    """
    Get recently used foods from MyFitnessPal.

    Uses the legacy diary-add AJAX endpoint that still works when newer
    account pages like `/food/mine` redirect away from authenticated sessions.

    Args:
        params: GetFoodCollectionInput containing:
            - limit (int, optional): Max results (default 10, max 100)
            - response_format (str): 'markdown' or 'json'

    Returns:
        str: List of recently used foods
    """
    try:
        client = get_mfp_client()
        limit = params.limit or 10
        items = fetch_legacy_food_collection(client, category="recent", limit=limit)
        data = {
            "count": len(items),
            "limit": limit,
            "items": items,
        }
        return format_response(data, params.response_format, "Recent Foods")
    except Exception as e:
        return f"Error getting recent foods: {str(e)}"


@mcp.tool(
    name="mfp_get_frequent_foods",
    annotations={
        "title": "Get Frequent Foods",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def mfp_get_frequent_foods(params: GetFoodCollectionInput) -> str:
    """
    Get most-used foods from MyFitnessPal.

    This is backed by the legacy `load_most_used` endpoint exposed by the
    add-to-diary page.

    Args:
        params: GetFoodCollectionInput containing:
            - limit (int, optional): Max results (default 10, max 100)
            - response_format (str): 'markdown' or 'json'

    Returns:
        str: List of most-used foods
    """
    try:
        client = get_mfp_client()
        limit = params.limit or 10
        items = fetch_legacy_food_collection(client, category="frequent", limit=limit)
        data = {
            "count": len(items),
            "limit": limit,
            "items": items,
        }
        return format_response(data, params.response_format, "Frequent Foods")
    except Exception as e:
        return f"Error getting frequent foods: {str(e)}"


@mcp.tool(
    name="mfp_get_my_foods",
    annotations={
        "title": "Get My Foods",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def mfp_get_my_foods(params: GetFoodCollectionInput) -> str:
    """
    Get foods created or saved by the authenticated user.

    This uses the legacy `load_my_foods` endpoint from the add-to-diary page,
    which remains accessible even when the modern `My Foods` page redirects
    away from authenticated sessions.

    Args:
        params: GetFoodCollectionInput containing:
            - limit (int, optional): Max results (default 100, max 100)
            - response_format (str): 'markdown' or 'json'

    Returns:
        str: List of foods created or saved by the account
    """
    try:
        client = get_mfp_client()
        limit = params.limit or 100
        items = fetch_legacy_food_collection(client, category="my_foods", limit=limit)
        data = {
            "count": len(items),
            "limit": limit,
            "items": items,
        }
        return format_response(data, params.response_format, "My Foods")
    except Exception as e:
        return f"Error getting my foods: {str(e)}"


@mcp.tool(
    name="mfp_get_measurements",
    annotations={
        "title": "Get Body Measurements",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def mfp_get_measurements(params: GetMeasurementsInput) -> str:
    """
    Get body measurements (weight, body fat, etc.) over a date range.

    Returns historical measurement data with dates and values. Useful for
    tracking weight loss progress and body composition changes.

    Args:
        params: GetMeasurementsInput containing:
            - measurement (str): Type of measurement (default 'Weight')
            - start_date (str, optional): Start date, defaults to 30 days ago
            - end_date (str, optional): End date, defaults to today
            - response_format (str): 'markdown' or 'json'

    Returns:
        str: Measurement history with dates and values
    """
    try:
        client = get_mfp_client()

        end = parse_date(params.end_date)
        if params.start_date:
            start = parse_date(params.start_date)
        else:
            start = end - timedelta(days=30)

        # client.get_measurements() scrapes a "dehydratedState" key that no
        # longer exists on the (now client-rendered) page - KeyErrors every
        # call. The v2 endpoint below works, but its begin_date/end_date/type
        # params don't actually filter server-side, so we filter here.
        response = client.session.get(
            f"{MFP_API_BASE}/v2/measurements",
            params={
                "type": params.measurement,
                "begin_date": start.strftime("%Y-%m-%d"),
                "end_date": end.strftime("%Y-%m-%d"),
            },
            headers=_mfp_api_headers(client),
            timeout=30,
        )
        if response.status_code != 200:
            raise RuntimeError(
                f"Could not fetch measurements: HTTP {response.status_code}"
            )

        wanted_type = params.measurement.strip().lower()
        measurements: OrderedDict[str, float] = OrderedDict(
            sorted(
                (
                    (item["date"], float(item["value"]))
                    for item in response.json().get("items", [])
                    if item.get("type", "").strip().lower() == wanted_type
                    and start <= parse_date(item["date"]) <= end
                ),
                key=lambda pair: pair[0],
            )
        )

        data = {
            "measurement_type": params.measurement,
            "start_date": str(start),
            "end_date": str(end),
            "count": len(measurements),
            "values": ordered_dict_to_dict(measurements),
        }

        # Calculate summary stats if we have data
        if measurements:
            values = list(measurements.values())
            data["summary"] = {
                "latest": values[-1] if values else None,
                "earliest": values[0] if values else None,
                "change": round(values[-1] - values[0], 2) if len(values) >= 2 else 0,
                "min": min(values),
                "max": max(values),
                "average": round(sum(values) / len(values), 2),
            }

        return format_response(
            data, params.response_format, f"{params.measurement} History"
        )

    except Exception as e:
        return f"Error getting measurements: {str(e)}"


@mcp.tool(
    name="mfp_set_measurement",
    annotations={
        "title": "Log Body Measurement",
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": False,
        "openWorldHint": True,
    },
)
async def mfp_set_measurement(params: SetMeasurementInput) -> str:
    """
    Log a new body measurement (weight, body fat, etc.) for today.

    Records the measurement value in MyFitnessPal for tracking progress.

    Args:
        params: SetMeasurementInput containing:
            - measurement (str): Type of measurement (default 'Weight')
            - value (float): Measurement value (e.g., 185.5)

    Returns:
        str: Confirmation message with the logged value
    """
    try:
        client = get_mfp_client()
        client.set_measurements(params.measurement, params.value)

        return json.dumps(
            {
                "success": True,
                "message": f"Successfully logged {params.measurement}: {params.value}",
                "measurement": params.measurement,
                "value": params.value,
                "date": str(date.today()),
            },
            indent=2,
        )

    except Exception as e:
        return f"Error setting measurement: {str(e)}"


@mcp.tool(
    name="mfp_get_exercises",
    annotations={
        "title": "Get Exercise Log",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def mfp_get_exercises(params: GetExercisesInput) -> str:
    """
    Get logged exercises for a specific date.

    Returns both cardiovascular and strength training exercises with their
    details (duration, calories burned, sets, reps, weight, etc.).

    Args:
        params: GetExercisesInput containing:
            - date (str, optional): Date in YYYY-MM-DD format, defaults to today
            - response_format (str): 'markdown' or 'json'

    Returns:
        str: List of exercises with details and calories burned
    """
    try:
        client = get_mfp_client()
        target_date = parse_date(params.date)
        day = client.get_date(target_date)

        data = {"date": str(target_date), "exercises": []}

        for exercise in day.exercises:
            data["exercises"].append(format_exercise(exercise))

        # Calculate total calories burned
        total_burned = 0
        for ex in data["exercises"]:
            for entry in ex.get("entries", []):
                if "nutrition_information" in entry:
                    total_burned += entry["nutrition_information"].get(
                        "calories burned", 0
                    )

        data["total_calories_burned"] = total_burned

        return format_response(
            data, params.response_format, f"Exercise Log for {target_date}"
        )

    except Exception as e:
        return f"Error getting exercises: {str(e)}"


@mcp.tool(
    name="mfp_get_goals",
    annotations={
        "title": "Get Nutrition Goals",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def mfp_get_goals(params: GetGoalsInput) -> str:
    """
    Get the user's daily nutrition goals (calories, protein, carbs, fat, etc.).

    Returns the configured daily targets for all tracked nutrients.

    Args:
        params: GetGoalsInput containing:
            - date (str, optional): Date in YYYY-MM-DD format, defaults to today
            - response_format (str): 'markdown' or 'json'

    Returns:
        str: Daily nutrition goals and targets
    """
    try:
        client = get_mfp_client()
        target_date = parse_date(params.date)
        day = client.get_date(target_date)

        data = {"date": str(target_date), "goals": day.goals}

        return format_response(data, params.response_format, "Daily Nutrition Goals")

    except Exception as e:
        return f"Error getting goals: {str(e)}"


@mcp.tool(
    name="mfp_set_goals",
    annotations={
        "title": "Update Nutrition Goals",
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def mfp_set_goals(params: SetGoalsInput) -> str:
    """
    Update daily nutrition goals (calories, protein, carbs, fat).

    Sets new daily targets for the specified nutrients. Only updates the
    values that are provided; others remain unchanged.

    Args:
        params: SetGoalsInput containing:
            - calories (int, optional): Daily calorie goal
            - protein (int, optional): Daily protein goal in grams
            - carbohydrates (int, optional): Daily carb goal in grams
            - fat (int, optional): Daily fat goal in grams

    Returns:
        str: Confirmation message with updated goals
    """
    try:
        # Check that at least one goal is provided
        if not any(
            [params.calories, params.protein, params.carbohydrates, params.fat]
        ):
            return "Error: Please provide at least one goal to update (calories, protein, carbohydrates, or fat)"

        client = get_mfp_client()

        # Build kwargs for set_new_goal
        kwargs = {}
        if params.calories:
            kwargs["energy"] = params.calories
        if params.protein:
            kwargs["protein"] = params.protein
        if params.carbohydrates:
            kwargs["carbohydrates"] = params.carbohydrates
        if params.fat:
            kwargs["fat"] = params.fat

        client.set_new_goal(**kwargs)

        return json.dumps(
            {
                "success": True,
                "message": "Successfully updated nutrition goals",
                "updated_goals": {
                    "calories": params.calories,
                    "protein": params.protein,
                    "carbohydrates": params.carbohydrates,
                    "fat": params.fat,
                },
            },
            indent=2,
        )

    except Exception as e:
        return f"Error setting goals: {str(e)}"


@mcp.tool(
    name="mfp_get_water",
    annotations={
        "title": "Get Water Intake",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def mfp_get_water(params: GetWaterInput) -> str:
    """
    Get water intake for a specific date.

    Returns the number of cups/glasses of water logged for the day.

    Args:
        params: GetWaterInput containing:
            - date (str, optional): Date in YYYY-MM-DD format, defaults to today

    Returns:
        str: Water intake amount for the specified date
    """
    try:
        client = get_mfp_client()
        target_date = parse_date(params.date)
        day = client.get_date(target_date)

        data = {
            "date": str(target_date),
            "water_cups": day.water,
            "water_ml": day.water * 236.588,  # Convert cups to ml
        }

        return json.dumps(data, indent=2)

    except Exception as e:
        return f"Error getting water intake: {str(e)}"


# Step counts synced from Apple Health / Google Fit / device integrations land
# in the v2 diary as `steps_aggregate` items, one per source per day:
#   {"type": "steps_aggregate", "date": "2026-10-16", "steps": 3241,
#    "energy": {"unit": "kilojoules", "value": 48}, "primary": true}
# The endpoint only honours `entry_date`; from/to range params are silently
# ignored (verified 2026-10-17), so a range costs one request per day.
MAX_STEPS_RANGE_DAYS = 31


def _primary_steps(items: List[Dict[str, Any]]) -> Optional[int]:
    """Pick the day's step count, preferring the source MFP marks primary."""
    aggregates = [i for i in items if i.get("type") == "steps_aggregate"]
    if not aggregates:
        return None
    chosen = next((i for i in aggregates if i.get("primary")), aggregates[0])
    return chosen.get("steps")


def get_steps_range(client, start: date, end: date) -> List[Dict[str, Any]]:
    """
    Fetch daily step totals for each date from start to end inclusive.

    Days with no synced step data get `steps: None` so callers can tell
    "no data" apart from a genuine zero.

    Raises:
        RuntimeError: If any day's request fails
    """
    days = []
    current = start
    while current <= end:
        date_str = current.strftime("%Y-%m-%d")
        response = client.session.get(
            f"{MFP_API_BASE}/v2/diary",
            params={"entry_date": date_str, "types": "steps_aggregate"},
            headers=_mfp_api_headers(client),
            timeout=30,
        )
        if response.status_code != 200:
            raise RuntimeError(
                f"Could not fetch steps for {date_str}: HTTP {response.status_code}"
            )
        days.append({
            "date": date_str,
            "steps": _primary_steps(response.json().get("items") or []),
        })
        current += timedelta(days=1)
    return days


@mcp.tool(
    name="mfp_get_steps",
    annotations={
        "title": "Get Daily Steps",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def mfp_get_steps(params: GetStepsInput) -> str:
    """
    Get daily step counts synced into MyFitnessPal (e.g. from Apple Health).

    Returns one entry per day in the range. Days with no synced data have
    `steps: null`. Ranges are limited to 31 days per call.

    Args:
        params: GetStepsInput containing:
            - start_date (str, optional): Defaults to 6 days before end_date
            - end_date (str, optional): Defaults to today
            - response_format (str): 'markdown' or 'json'

    Returns:
        str: Daily step counts with a total/average summary
    """
    try:
        end = parse_date(params.end_date)
        if params.start_date:
            start = parse_date(params.start_date)
        else:
            start = end - timedelta(days=6)

        if start > end:
            raise ValueError("start_date must be on or before end_date")
        span = (end - start).days + 1
        if span > MAX_STEPS_RANGE_DAYS:
            raise ValueError(
                f"Range is {span} days; the maximum is {MAX_STEPS_RANGE_DAYS}. "
                "Split it into smaller calls."
            )

        client = get_mfp_client()
        days = get_steps_range(client, start, end)

        counts = [d["steps"] for d in days if d["steps"] is not None]
        data: Dict[str, Any] = {
            "start_date": str(start),
            "end_date": str(end),
            "days": days,
            "summary": {
                "days_with_data": len(counts),
                "total": sum(counts),
                "average": round(sum(counts) / len(counts)) if counts else None,
            },
        }

        if params.response_format == ResponseFormat.MARKDOWN:
            # format_response renders lists of dicts poorly; show date: steps.
            data["days"] = {
                d["date"]: d["steps"] if d["steps"] is not None else "no data"
                for d in days
            }

        return format_response(data, params.response_format, "Daily Steps")

    except Exception as e:
        return f"Error getting steps: {str(e)}"


@mcp.tool(
    name="mfp_add_food_to_diary",
    annotations={
        "title": "Add Food to Diary",
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": False,
        "openWorldHint": True,
    },
)
async def mfp_add_food_to_diary(params: AddFoodToDiaryInput) -> str:
    """
    Add a food item to your MyFitnessPal food diary for a specific date and meal.

    This tool adds a food entry to your diary. You can search for foods using
    mfp_search_food to find the food ID (mfp_id) needed for this tool.

    Args:
        params: AddFoodToDiaryInput containing:
            - mfp_id (str): MyFitnessPal food item ID (from mfp_search_food)
            - meal (str): Meal name - 'Breakfast', 'Lunch', 'Dinner', or 'Snacks' (default: 'Breakfast')
            - date (str, optional): Date in YYYY-MM-DD format, defaults to today
            - quantity (float): Number of default servings for this food (default: 1.0)

    Returns:
        str: Confirmation message with details of the added food entry
    """
    try:
        client = get_mfp_client()
        target_date = parse_date(params.date)

        # Normalize meal name (capitalize first letter)
        meal = params.meal.strip().capitalize()
        if meal.lower() == "snack":
            meal = "Snacks"

        # Add food to diary
        add_food_to_diary(
            client=client,
            mfp_id=params.mfp_id,
            meal=meal,
            target_date=target_date,
            quantity=params.quantity,
        )

        try:
            food_name = get_food_v2(client, params.mfp_id).get("description", "Food item")
        except Exception:
            food_name = "Food item"

        return json.dumps(
            {
                "success": True,
                "message": f"Successfully added {food_name} to {meal}",
                "date": str(target_date),
                "meal": meal,
                "food_id": params.mfp_id,
                "food_name": food_name,
                "quantity": params.quantity,
            },
            indent=2,
        )

    except Exception as e:
        return f"Error adding food to diary: {str(e)}"


# Serving-size unit labels MFP can convert to grams, and their grams-per-unit.
# Used to populate gram_weight/grams so gram-based scaling is correct; other
# units (Serving, bag, cup, ml, ...) have unknown mass and are left to MFP.
_GRAM_UNITS = {
    "g": 1.0, "gram": 1.0, "grams": 1.0, "gm": 1.0,
    "mg": 0.001, "kg": 1000.0,
    "oz": 28.3495, "ounce": 28.3495, "ounces": 28.3495,
    "lb": 453.592, "lbs": 453.592, "pound": 453.592, "pounds": 453.592,
}


def create_food(
    client,
    *,
    description: str,
    calories: float,
    fat: float,
    carbs: float,
    protein: float,
    brand: str = "",
    serving_size: str = "1 Serving",
    servings_per_container: float = 1.0,
    share_public: bool = False,
    saturated_fat: Optional[float] = None,
    polyunsaturated_fat: Optional[float] = None,
    monounsaturated_fat: Optional[float] = None,
    trans_fat: Optional[float] = None,
    cholesterol: Optional[float] = None,
    sodium: Optional[float] = None,
    potassium: Optional[float] = None,
    fiber: Optional[float] = None,
    sugar: Optional[float] = None,
    vitamin_a: Optional[float] = None,
    vitamin_c: Optional[float] = None,
    calcium: Optional[float] = None,
    iron: Optional[float] = None,
) -> dict:
    """Create a custom food via MyFitnessPal's v2 API; return the created item.

    Why not myfitnesspal.Client.set_new_food(): MFP replaced the old
    server-rendered ``/food/submit`` and ``/food/new`` Rails forms with a
    client-side (Next.js) SPA. Those pages no longer contain the hidden
    ``<input name="authenticity_token">``, so set_new_food()'s token scrape hits
    an empty xpath result and raises ``IndexError: list index out of range`` for
    every call, regardless of the nutrition passed.

    Instead we POST the same JSON payload the SPA builds, to the v2 API,
    authenticated with the account's bearer token (the same mechanism the
    library uses for set_new_goal)::

        POST {BASE_API_URL}v2/foods
        {"item": {user_id, brand_name, description, [public],
                  nutritional_contents: {energy: {unit, value}, <macros>},
                  serving_sizes: [{value, unit, nutrition_multiplier}]}}

    The ``accept: application/json`` header is REQUIRED -- without it the API
    edge returns ``400 Illegal request``. Nutrition values are per one
    ``serving_size``. ``share_public=True`` submits the food to MyFitnessPal's
    shared database and is IRREVERSIBLE: public foods cannot be edited or
    deleted afterwards, so this defaults to a private (deletable) food.

    Returns the created food item dict (its ``id`` is the mfp_id). Raises
    RuntimeError if the API rejects the request.
    """
    import re

    # Per-serving nutrition. MFP stores energy as an object, macros as numbers.
    nutritional_contents: Dict[str, Any] = {
        "energy": {"unit": "calories", "value": calories},
        "fat": fat,
        "carbohydrates": carbs,
        "protein": protein,
    }
    optional_nutrients = {
        "saturated_fat": saturated_fat,
        "polyunsaturated_fat": polyunsaturated_fat,
        "monounsaturated_fat": monounsaturated_fat,
        "trans_fat": trans_fat,
        "cholesterol": cholesterol,
        "sodium": sodium,
        "potassium": potassium,
        "fiber": fiber,
        "sugar": sugar,
        "vitamin_a": vitamin_a,
        "vitamin_c": vitamin_c,
        "calcium": calcium,
        "iron": iron,
    }
    for key, value in optional_nutrients.items():
        if value is not None:
            nutritional_contents[key] = value

    # Parse "125 g" / "1 Serving" / "0.5 cup" into a numeric value + unit label.
    match = re.match(r"^\s*([0-9]*\.?[0-9]+)?\s*(.*\S)?\s*$", serving_size or "")
    serving_value = float(match.group(1)) if match and match.group(1) else 1.0
    serving_unit = (match.group(2) if match and match.group(2) else "Serving") or "Serving"

    # If the serving unit is a known mass unit, record gram weights so MFP's
    # gram-based scaling is correct; otherwise leave grams unknown (MFP defaults).
    grams_per_unit = _GRAM_UNITS.get(serving_unit.lower())
    if grams_per_unit is not None:
        nutritional_contents["grams"] = serving_value * grams_per_unit

    def _serving(value, unit, multiplier, gram_weight=None):
        s: Dict[str, Any] = {"value": value, "unit": unit, "nutrition_multiplier": multiplier}
        if gram_weight is not None:
            s["gram_weight"] = gram_weight
        return s

    # Base serving carries the nutrition as entered (multiplier 1.0). Mirror the
    # SPA: add a normalized single-unit serving, plus a container serving when
    # servings_per_container is meaningful, so users can also log by unit/container.
    serving_sizes: List[Dict[str, Any]] = [
        _serving(serving_value, serving_unit, 1.0,
                 serving_value * grams_per_unit if grams_per_unit is not None else None)
    ]
    if serving_value != 1.0:
        serving_sizes.append(
            _serving(1.0, serving_unit, 1.0 / serving_value, grams_per_unit)
        )
    if servings_per_container and servings_per_container != 1.0:
        total = serving_value * servings_per_container
        serving_sizes.append(
            _serving(
                1.0,
                f"container ({total:g} {serving_unit} ea.)",
                float(servings_per_container),
                total * grams_per_unit if grams_per_unit is not None else None,
            )
        )

    item: Dict[str, Any] = {
        "user_id": str(client.user_id),
        "brand_name": brand.strip(),
        "description": description.strip(),
        "nutritional_contents": nutritional_contents,
        "serving_sizes": serving_sizes,
    }
    # Only send public when sharing: omitting it yields a private, deletable
    # food; sending public=true is irreversible.
    if share_public:
        item["public"] = True

    headers = {
        "authorization": f"Bearer {client.access_token}",
        "mfp-client-id": "mfp-main-js",
        "mfp-user-id": str(client.user_id),
        "content-type": "application/json",
        "accept": "application/json",  # required; without it the edge returns 400 "Illegal request"
    }
    url = f"{client.BASE_API_URL}v2/foods"
    resp = client.session.post(url, data=json.dumps({"item": item}), headers=headers)
    if not resp.ok:
        raise RuntimeError(
            f"MyFitnessPal API rejected the new food (HTTP {resp.status_code}): "
            f"{resp.text[:300]}"
        )
    try:
        payload = resp.json()
    except ValueError:
        payload = {}
    items = payload.get("items") or ([payload["item"]] if payload.get("item") else [])
    return items[0] if items else {}


@mcp.tool(
    name="mfp_create_food",
    annotations={
        "title": "Create Custom Food",
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": False,
        "openWorldHint": True,
    },
)
async def mfp_create_food(params: CreateFoodInput) -> str:
    """
    Create a new custom food in the MyFitnessPal database (via the v2 API).

    Use this when a food is not already in MyFitnessPal (mfp_search_food returns
    nothing suitable) and you want it available to log. All nutrition values are
    entered PER ONE `serving_size` (e.g. serving_size='125 g' with the numbers
    for a 125 g portion).

    On success the new food's id is returned as `mfp_id`; pass it to
    mfp_add_food_to_diary to log the food (it may take a short moment to also
    surface in mfp_search_food). Calling this repeatedly creates duplicate foods.

    IMPORTANT: share_public=True submits the food to MyFitnessPal's shared public
    database and is IRREVERSIBLE -- public foods can no longer be edited or
    deleted. Leave it False (default) to create a private food you can later
    delete.

    Args:
        params: CreateFoodInput containing:
            - description (str): Food name (required)
            - brand (str, optional): Brand/manufacturer
            - calories, fat, carbs, protein (float): Core macros per serving (required)
            - saturated_fat, polyunsaturated_fat, monounsaturated_fat, trans_fat,
              fiber, sugar, sodium, potassium, cholesterol, vitamin_a, vitamin_c,
              calcium, iron (float, optional): Additional nutrients per serving
            - serving_size (str): Serving-size label, e.g. '1 Serving', '125 g' (default '1 Serving')
            - servings_per_container (float): Servings per container (default 1.0)
            - share_public (bool): Submit to the public database; irreversible (default False)

    Returns:
        str: JSON confirmation including the new food's mfp_id
    """
    try:
        client = get_mfp_client()

        created = create_food(
            client=client,
            description=params.description,
            brand=params.brand,
            calories=params.calories,
            fat=params.fat,
            carbs=params.carbs,
            protein=params.protein,
            serving_size=params.serving_size,
            servings_per_container=params.servings_per_container,
            share_public=params.share_public,
            saturated_fat=params.saturated_fat,
            polyunsaturated_fat=params.polyunsaturated_fat,
            monounsaturated_fat=params.monounsaturated_fat,
            trans_fat=params.trans_fat,
            cholesterol=params.cholesterol,
            sodium=params.sodium,
            potassium=params.potassium,
            fiber=params.fiber,
            sugar=params.sugar,
            vitamin_a=params.vitamin_a,
            vitamin_c=params.vitamin_c,
            calcium=params.calcium,
            iron=params.iron,
        )

        food_label = f"{params.brand} {params.description}".strip()
        note = (
            "Food created. Use the returned mfp_id with mfp_add_food_to_diary to "
            "log it (it may take a moment to also appear in mfp_search_food)."
        )
        if params.share_public:
            note += " This food was shared PUBLICLY and can no longer be edited or deleted."
        return json.dumps(
            {
                "success": True,
                "message": f"Successfully created custom food '{food_label}'",
                "mfp_id": created.get("id"),
                "brand": params.brand,
                "description": params.description,
                "serving_size": params.serving_size,
                "servings_per_container": params.servings_per_container,
                "calories": params.calories,
                "fat": params.fat,
                "carbs": params.carbs,
                "protein": params.protein,
                "public": params.share_public,
                "note": note,
            },
            indent=2,
        )

    except Exception as e:
        return f"Error creating custom food: {str(e)}"


@mcp.tool(
    name="mfp_update_food_entry",
    annotations={
        "title": "Update Diary Entry",
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": False,
        "openWorldHint": True,
    },
)
async def mfp_update_food_entry(params: UpdateFoodEntryInput) -> str:
    """
    Update an existing MyFitnessPal diary entry.

    Supports changing the meal, quantity, serving size, and date for an entry
    previously returned by mfp_get_diary (use response_format='json' to get the
    entry_id). MyFitnessPal can rewrite an entry during edit and return a
    replacement row, so the response includes `current_entry_id` and
    `entry_id_changed` to keep callers tracking the right diary row.

    Args:
        params: UpdateFoodEntryInput containing:
            - entry_id (str): Diary entry ID from mfp_get_diary JSON output
            - date (str, optional): Date in YYYY-MM-DD format, defaults to today
            - meal (str, optional): New meal name
            - quantity (float, optional): New number of servings
            - unit (str, optional): New serving-size label
            - weight_id (str, optional): Raw MFP serving-size option ID

    Returns:
        str: Confirmation with the current entry id and whether it changed
    """
    try:
        if params.meal is None and params.quantity is None and params.unit is None and params.weight_id is None:
            return "Error updating food entry: provide at least one of meal, quantity, unit, or weight_id."

        client = get_mfp_client()
        target_date = parse_date(params.date)
        result = update_food_entry(
            client=client,
            entry_id=params.entry_id,
            target_date=target_date,
            meal=params.meal,
            quantity=params.quantity,
            unit=params.unit,
            weight_id=params.weight_id,
        )

        return json.dumps(
            {
                "success": True,
                "message": f"Successfully updated diary entry {params.entry_id}",
                "entry_id": params.entry_id,
                "current_entry_id": result["after"]["entry_id"],
                "entry_id_changed": result["entry_id_changed"],
                "date": str(target_date),
                "meal": result["after"]["meal"],
                "quantity": result["after"]["quantity"],
                "unit": result["after"]["unit"],
                "weight_id": params.weight_id,
                "confirmed_entry_name": result["after"]["name"],
                "confirmed_meal": result["after"]["meal"],
            },
            indent=2,
        )
    except Exception as e:
        return f"Error updating food entry: {str(e)}"


@mcp.tool(
    name="mfp_delete_food_entry",
    annotations={
        "title": "Delete Diary Entry",
        "readOnlyHint": False,
        "destructiveHint": True,
        "idempotentHint": False,
        "openWorldHint": True,
    },
)
async def mfp_delete_food_entry(params: DeleteFoodEntryInput) -> str:
    """
    Delete an existing MyFitnessPal diary entry.

    Deletes a diary entry identified by the `entry_id` returned by mfp_get_diary
    (use response_format='json' to get the entry_id).

    Args:
        params: DeleteFoodEntryInput containing:
            - entry_id (str): Diary entry ID from mfp_get_diary JSON output
            - date (str, optional): Date in YYYY-MM-DD format, defaults to today

    Returns:
        str: Confirmation message with the deleted entry's name and meal
    """
    try:
        client = get_mfp_client()
        target_date = parse_date(params.date)
        deleted_entry = delete_food_entry(client=client, entry_id=params.entry_id, target_date=target_date)
        return json.dumps(
            {
                "success": True,
                "message": f"Successfully deleted diary entry {params.entry_id}",
                "entry_id": params.entry_id,
                "date": str(target_date),
                "deleted_entry_name": deleted_entry["name"],
                "deleted_meal": deleted_entry["meal"],
            },
            indent=2,
        )
    except Exception as e:
        return f"Error deleting food entry: {str(e)}"


@mcp.tool(
    name="mfp_set_water",
    annotations={
        "title": "Log Water Intake",
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": False,
        "openWorldHint": True,
    },
)
async def mfp_set_water(params: SetWaterInput) -> str:
    """
    Log water intake for a specific date.

    Sets the number of cups of water consumed for the day. MyFitnessPal uses
    cups as the unit (1 cup = ~237ml).

    Args:
        params: SetWaterInput containing:
            - cups (float): Number of cups of water (e.g., 2.5 for 2.5 cups)
            - date (str, optional): Date in YYYY-MM-DD format, defaults to today

    Returns:
        str: Confirmation message with the logged water amount
    """
    try:
        client = get_mfp_client()
        target_date = parse_date(params.date)

        # Set water intake
        set_water_intake(client=client, target_date=target_date, cups=params.cups)

        return json.dumps(
            {
                "success": True,
                "message": f"Successfully logged {params.cups} cups of water",
                "date": str(target_date),
                "cups": params.cups,
                "milliliters": round(params.cups * 236.588, 2),
            },
            indent=2,
        )

    except Exception as e:
        return f"Error setting water intake: {str(e)}"


@mcp.tool(
    name="mfp_get_report",
    annotations={
        "title": "Get Nutrition Report",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def mfp_get_report(params: GetReportInput) -> str:
    """
    Get a nutrition report over a date range.

    Returns daily values for the specified nutrient/metric over the date range.
    Useful for analyzing trends and patterns in nutrition intake.

    Args:
        params: GetReportInput containing:
            - report_name (str): Report type (e.g., 'Net Calories', 'Protein')
            - start_date (str, optional): Start date, defaults to 7 days ago
            - end_date (str, optional): End date, defaults to today
            - response_format (str): 'markdown' or 'json'

    Returns:
        str: Daily values and summary statistics for the report period
    """
    try:
        client = get_mfp_client()

        end = parse_date(params.end_date)
        if params.start_date:
            start = parse_date(params.start_date)
        else:
            start = end - timedelta(days=7)

        report = client.get_report(
            report_name=params.report_name,
            report_category="Nutrition",
            lower_bound=start,
            upper_bound=end,
        )

        data = {
            "report_name": params.report_name,
            "start_date": str(start),
            "end_date": str(end),
            "values": (
                ordered_dict_to_dict(report) if isinstance(report, OrderedDict) else report
            ),
        }

        # Calculate summary stats
        if report:
            values = list(report.values())
            numeric_values = [v for v in values if isinstance(v, (int, float))]
            if numeric_values:
                data["summary"] = {
                    "total": sum(numeric_values),
                    "average": round(sum(numeric_values) / len(numeric_values), 2),
                    "min": min(numeric_values),
                    "max": max(numeric_values),
                }

        return format_response(
            data, params.response_format, f"{params.report_name} Report"
        )

    except Exception as e:
        return f"Error getting report: {str(e)}"


# ============================================================================
# Main Entry Point
# ============================================================================


def create_http_app():
    """The streamable-http ASGI app, wrapped in JWT auth when MCP_AUTH_MODE=oauth.

    In oauth mode FastMCP is built with no auth provider, so none of the
    passcode OAuth endpoints (/authorize, /token, /register, /login,
    /.well-known/*) exist - the bearer JWT is the single auth path.
    """
    app = mcp.streamable_http_app()
    if _jwt_verifier is not None:
        return JWTAuthMiddleware(app, _jwt_verifier, mcp_path=mcp.settings.streamable_http_path)
    return app


def main():
    """Run the MCP server.

    Supports two transport modes controlled by MCP_TRANSPORT environment variable:
    - "stdio" (default): Standard input/output for local MCP clients
    - "streamable-http": HTTP server for remote/Docker deployments

    For HTTP mode, also supports:
    - MCP_HOST: Host to bind to (default: "127.0.0.1" for stdio, "0.0.0.0" for http)
    - MCP_PORT: Port to listen on (default: 8000)
    - MCP_ALLOWED_HOSTS: Comma-separated list of allowed Host headers for reverse proxy
      (e.g., "mfp.example.com,mfp.example.com:443")
      If not set, DNS rebinding protection is disabled for HTTP mode.
    - MCP_AUTH_MODE: none | passcode_oauth | oauth (unset = legacy passcode
      auto-detection). See README "Behind an MCP Gateway".
    """
    transport = os.getenv("MCP_TRANSPORT", "stdio")

    if transport == "streamable-http" and _jwt_verifier is not None:
        import uvicorn

        uvicorn.run(
            create_http_app(),
            host=mcp.settings.host,
            port=mcp.settings.port,
            log_level=mcp.settings.log_level.lower(),
        )
    elif transport == "streamable-http":
        mcp.run(transport="streamable-http")
    else:
        mcp.run()


if __name__ == "__main__":
    main()
