"""Gateway credential middleware: 401 on a missing header, no context leakage."""

import pytest
from starlette.testclient import TestClient

from compassone_mcp.__main__ import _build_http_app
from compassone_mcp.config import Settings
from compassone_mcp.server import GatewayTokenMiddleware, _gateway_token_var, create_mcp_server

TOOLS_LIST = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
ACCEPT = {"Accept": "application/json, text/event-stream"}


def _make_app():
    settings = Settings(auth_mode="gateway")
    return _build_http_app(create_mcp_server(settings), settings), settings


def test_missing_header_returns_401_with_required_headers_listed():
    app, _ = _make_app()
    with TestClient(app) as client:
        resp = client.post("/mcp", json=TOOLS_LIST, headers=ACCEPT)
    assert resp.status_code == 401
    assert "X-Blackpoint-API-Token" in resp.json()["required_headers"]


def test_health_needs_no_credentials():
    app, _ = _make_app()
    with TestClient(app) as client:
        resp = client.get("/health")
    assert resp.status_code == 200
    # SOP §1.1: a pure local probe, body exactly {"status": "ok"}, never
    # dependent on CompassOne being reachable.
    assert resp.json() == {"status": "ok"}


def test_tools_list_with_header_is_200_not_400():
    """Statelessness self-check (SOP §1.3): a bare tools/call with no prior
    initialize must work, because the gateway does not keep a session."""
    app, _ = _make_app()
    with TestClient(app) as client:
        resp = client.post(
            "/mcp", json=TOOLS_LIST, headers={**ACCEPT, "X-Blackpoint-API-Token": "dummy"}
        )
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_token_reaches_context_and_is_reset_afterwards():
    seen = {}

    async def downstream(scope, receive, send):
        seen["token"] = _gateway_token_var.get()
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    middleware = GatewayTokenMiddleware(downstream, Settings(auth_mode="gateway"))
    scope = {
        "type": "http",
        "path": "/mcp",
        "method": "POST",
        "headers": [(b"x-blackpoint-api-token", b"secret-token")],
    }

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(_message):
        return None

    await middleware(scope, receive, send)

    assert seen["token"] == "secret-token"
    # No credential may outlive the request that carried it.
    assert _gateway_token_var.get() is None
