import contextvars

from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from .api_client import CompassOneClient
from .config import Settings

# ─────────────────────────────────────────────────────────────────────────────
# Per-request API-token contextvar for gateway mode.
# GatewayTokenMiddleware sets this before the MCP handler runs.
# Python asyncio copies context per task, so concurrent requests are isolated.
# ─────────────────────────────────────────────────────────────────────────────
_gateway_token_var: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "compassone_gateway_token", default=None
)


def get_client_from_context(settings: Settings) -> CompassOneClient | None:
    """Resolve the active CompassOneClient for the current request context."""
    if settings.auth_mode == "gateway":
        api_token = _gateway_token_var.get()
    else:
        api_token = settings.compassone_api_token

    if not api_token:
        return None
    return CompassOneClient(api_token, settings.compassone_base_url)


class GatewayTokenMiddleware:
    """ASGI middleware for gateway mode.

    Reads the configured API-token header from each request and stores it in
    the contextvar for the duration of that request. Returns 401 if the header
    is missing on /mcp requests.

    Note what is deliberately NOT read here: the customer tenant. CompassOne's
    x-tenant-id is a per-call value (one partner credential spans many customer
    tenants), so it arrives as a tool argument, not as a connection-level
    credential header. Binding it here would freeze one tenant per
    authorization and defeat the point.
    """

    def __init__(self, app: ASGIApp, settings: Settings):
        self.app = app
        self.settings = settings

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")
        if not path.startswith("/mcp"):
            await self.app(scope, receive, send)
            return

        request = Request(scope)
        # Header lookup is case-insensitive in Starlette
        api_token = request.headers.get(self.settings.compassone_api_token_header.lower())
        if not api_token:
            response = JSONResponse(
                {
                    "error": "Missing credentials",
                    "message": (
                        "Gateway mode requires the "
                        f"{self.settings.compassone_api_token_header} header"
                    ),
                    "required_headers": [self.settings.compassone_api_token_header],
                },
                status_code=401,
            )
            await response(scope, receive, send)
            return

        ctx_token = _gateway_token_var.set(api_token)
        try:
            await self.app(scope, receive, send)
        finally:
            _gateway_token_var.reset(ctx_token)


INSTRUCTIONS = (
    "CompassOne (Blackpoint Cyber) is an MDR security platform. This server "
    "reads one MSP partner's CompassOne data across all of its customer "
    "tenants.\n"
    "TENANT SCOPING IS MANDATORY. The credential is a partner token covering "
    "many customers, so every tool except compassone_list_tenants takes a "
    "required tenant_id, sent as the x-tenant-id header. Always start with "
    "compassone_list_tenants to resolve a customer's UUID — never guess one, "
    "and never assume a previous call's tenant still applies. Its `type` field "
    "(MDR / MDR ONBOARD / POC / SELF / UNSET) identifies the MSP's own tenant, "
    "which is normally not the one you want. A tenant_id you have no access to "
    "returns an `unauthorized` error, not an empty list; treat an error as an "
    "error, never as 'no findings'.\n"
    "Core concepts: detections (a.k.a. alert groups) aggregate related alerts, "
    "typed CR (Cloud Response: M365, Google Workspace, Cisco Duo) or MDR "
    "(endpoint products); assets are inventory rows and require a class; the "
    "security posture rating is a scored control assessment whose maximumScore "
    "varies by CompassOne edition; reports are pre-generated monthly runs "
    "fetched by id.\n"
    "Typical flow for a monthly client report: compassone_list_tenants -> "
    "compassone_list_reports (filter the month) -> compassone_get_report_json, "
    "then compassone_get_security_posture_rating and the "
    "compassone_*_detections tools for supporting detail. All 18 tools are "
    "read-only."
)


def create_mcp_server(settings: Settings) -> FastMCP:
    """Build the FastMCP server instance and register all tools."""
    # DNS-rebinding protection is disabled because the container runs behind
    # mcp-gateway on an internal Docker network and is never publicly exposed.
    mcp = FastMCP(
        name="compassone-mcp",
        instructions=INSTRUCTIONS,
        transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
        stateless_http=True,
        json_response=True,
    )

    def client_factory() -> CompassOneClient | None:
        return get_client_from_context(settings)

    # Tools are always registered, including when no credential is configured.
    # A missing credential is a per-request condition in gateway mode (the
    # container serves many tenants), so tools/list must not depend on it;
    # each tool returns the `not_configured` envelope instead.
    from .tools import assets, detections, posture, reports, tenants, vulnerabilities

    tenants.register(mcp, client_factory)
    posture.register(mcp, client_factory)
    reports.register(mcp, client_factory)
    detections.register(mcp, client_factory)
    assets.register(mcp, client_factory)
    vulnerabilities.register(mcp, client_factory)

    return mcp
