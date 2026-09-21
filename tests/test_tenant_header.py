"""The x-tenant-id contract (PRD-19227).

If this file is ever loosened, the quiet-empty failure mode comes back: a call
that runs at partner scope answers with data belonging to nobody in
particular, and a 403 rendered as an empty list reads exactly like a client
who had a quiet month. These findings are stated to end clients, so every
assertion here is deliberate.

Covered:
  1. every scoped tool actually sends x-tenant-id, with the value it was given
  2. compassone_list_tenants does NOT send it (it is what produces a tenant id)
  3. an upstream 403 becomes an `unauthorized` envelope, never an empty result
  4. a blank tenant_id is refused before any request leaves the process
"""

import json

import httpx
import pytest
import respx

from compassone_mcp.config import Settings
from compassone_mcp.server import _gateway_token_var, create_mcp_server
from compassone_mcp.tools._common import NO_CREDS

BASE = "https://api.blackpointcyber.com"
TENANT = "11111111-2222-3333-4444-555555555555"

# One representative invocation per tool. Minimal arguments: whatever the tool
# requires, plus nothing else.
TOOL_CALLS = {
    "compassone_get_security_posture_rating": {},
    "compassone_list_reports": {},
    "compassone_get_report_json": {"report_id": "rep-1"},
    "compassone_list_detections": {},
    "compassone_get_detection": {"alert_group_id": "ag-1"},
    "compassone_list_detection_alerts": {"alert_group_id": "ag-1"},
    "compassone_count_detections": {},
    "compassone_list_detections_by_week": {},
    "compassone_top_detections_by_entity": {},
    "compassone_top_detections_by_threat": {},
    "compassone_list_assets": {"asset_class": ["DEVICE"]},
    "compassone_get_asset": {"asset_id": "asset-1"},
    "compassone_list_asset_relationships": {
        "asset_id": "asset-1",
        "related_class": "ALERT",
        "direction": "out",
    },
    "compassone_list_vulnerabilities": {},
    "compassone_list_vulnerability_scans": {},
    "compassone_list_darkweb_exposures": {},
    "compassone_get_external_scan_exposures": {"scan_id": "scan-1"},
}


def _server():
    return create_mcp_server(Settings(auth_mode="gateway"))


async def _call(tool_name, args):
    """Invoke a tool with a credential in context, as the middleware would."""
    ctx_token = _gateway_token_var.set("test-token")
    try:
        return await _server().call_tool(tool_name, args)
    finally:
        _gateway_token_var.reset(ctx_token)


def test_every_scoped_tool_is_exercised_here():
    """Guards against a new tool slipping past this file unnoticed."""
    from test_tools import EXPECTED_REQUIRED, UNSCOPED_TOOLS

    assert set(TOOL_CALLS) == set(EXPECTED_REQUIRED) - UNSCOPED_TOOLS


@pytest.mark.asyncio
@pytest.mark.parametrize("tool_name", sorted(TOOL_CALLS))
@respx.mock
async def test_scoped_tool_sends_the_tenant_header(tool_name):
    route = respx.get(url__startswith=BASE).mock(
        return_value=httpx.Response(200, json={"data": [], "meta": {}})
    )

    await _call(tool_name, {"tenant_id": TENANT, **TOOL_CALLS[tool_name]})

    assert route.called, tool_name
    request = route.calls.last.request
    assert request.headers.get("x-tenant-id") == TENANT, tool_name
    assert request.headers.get("authorization") == "Bearer test-token", tool_name


@pytest.mark.asyncio
@respx.mock
async def test_tenant_directory_does_not_send_the_tenant_header():
    """GET /v1/tenants is the one call that produces a tenant id, so it is the
    one call that must not be scoped by one."""
    route = respx.get(f"{BASE}/v1/tenants").mock(
        return_value=httpx.Response(200, json={"data": [], "meta": {}})
    )

    await _call("compassone_list_tenants", {})

    assert route.called
    assert "x-tenant-id" not in route.calls.last.request.headers


@pytest.mark.asyncio
@pytest.mark.parametrize("tool_name", sorted(TOOL_CALLS))
@respx.mock
async def test_forbidden_tenant_is_an_error_not_an_empty_result(tool_name):
    """403 means the credential cannot reach that tenant. It must surface as
    itself. Rendering it as [] is the exact bug this service exists to avoid."""
    respx.get(url__startswith=BASE).mock(
        return_value=httpx.Response(403, json={"message": "forbidden"})
    )

    result = await _call(tool_name, {"tenant_id": TENANT, **TOOL_CALLS[tool_name]})
    payload = json.loads(_text(result))

    assert payload["error"]["code"] == "unauthorized", tool_name
    assert payload["error"]["retryable"] is False, tool_name


@pytest.mark.asyncio
@pytest.mark.parametrize("blank", ["", "   "])
@respx.mock
async def test_blank_tenant_id_never_reaches_the_network(blank):
    route = respx.get(url__startswith=BASE).mock(
        return_value=httpx.Response(200, json={"data": []})
    )

    result = await _call("compassone_list_detections", {"tenant_id": blank})
    payload = json.loads(_text(result))

    # The tool returns an envelope rather than raising — tools never let a
    # CompassOneError escape — but the refusal still happens in get_scoped,
    # before anything is put on the wire.
    assert payload["error"]["code"] == "invalid_argument"
    assert not route.called, "a blank tenant_id must fail before any request is sent"


@pytest.mark.asyncio
async def test_missing_credential_returns_not_configured():
    """No credential in context (gateway mode, header absent) is a per-request
    condition, so tools stay listed and answer with an envelope."""
    result = await _server().call_tool("compassone_list_tenants", {})
    assert _text(result) == NO_CREDS


def _text(result):
    """call_tool returns (content, structured) on current MCP versions and a
    bare content list on older ones."""
    content = result[0] if isinstance(result, tuple) else result
    return content[0].text
