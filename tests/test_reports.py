"""compassone_get_report_json: verbatim payload, and how oversize is handled."""

import json

import httpx
import pytest
import respx

from compassone_mcp._json import MAX_CHARS
from compassone_mcp.config import Settings
from compassone_mcp.server import _gateway_token_var, create_mcp_server

BASE = "https://api.blackpointcyber.com"
TENANT = "tenant-uuid"


async def _call(args):
    ctx_token = _gateway_token_var.set("test-token")
    try:
        result = await create_mcp_server(Settings(auth_mode="gateway")).call_tool(
            "compassone_get_report_json", args
        )
    finally:
        _gateway_token_var.reset(ctx_token)
    content = result[0] if isinstance(result, tuple) else result
    return content[0].text


@pytest.mark.asyncio
@respx.mock
async def test_legacy_and_current_executive_shapes_both_survive_verbatim():
    """The vendor ships a legacy Executive payload keyed executiveSummary
    alongside the current one keyed securityPosture, and consumers branch on
    which is present. Merging or renaming them would destroy that signal."""
    upstream = {
        "data": {
            "reportType": "Executive",
            "report": {
                "tenant": {"id": TENANT},
                "period": {"start": "2026-08-01"},
                "executiveSummary": {"legacy": True},
                "securityPosture": {"score": 42, "maximumScore": 50},
            },
        }
    }
    respx.get(url__startswith=BASE).mock(return_value=httpx.Response(200, json=upstream))

    payload = json.loads(await _call({"tenant_id": TENANT, "report_id": "rep-1"}))
    assert payload == upstream


@pytest.mark.asyncio
@respx.mock
async def test_oversize_report_errors_with_the_section_list_instead_of_truncating():
    """A half-delivered monthly report looks complete to a consumer that cannot
    see what was dropped, so this tool fails loudly and names the way forward."""
    upstream = {
        "data": {
            "reportType": "MDR",
            "report": {
                "tenant": {"id": TENANT},
                "socActivity": [{"pad": "x" * 200} for _ in range(300)],
            },
        }
    }
    respx.get(url__startswith=BASE).mock(return_value=httpx.Response(200, json=upstream))

    payload = json.loads(await _call({"tenant_id": TENANT, "report_id": "rep-1"}))
    assert payload["error"]["code"] == "invalid_argument"
    assert "socActivity" in payload["error"]["message"]
    assert "tenant" in payload["error"]["message"]


@pytest.mark.asyncio
@respx.mock
async def test_section_returns_that_key_untouched():
    upstream = {
        "data": {
            "reportType": "MDR",
            "report": {"tenant": {"id": TENANT}, "siem": {"events": 17}},
        }
    }
    respx.get(url__startswith=BASE).mock(return_value=httpx.Response(200, json=upstream))

    payload = json.loads(
        await _call({"tenant_id": TENANT, "report_id": "rep-1", "section": "siem"})
    )
    assert payload == {"reportType": "MDR", "section": "siem", "report": {"siem": {"events": 17}}}


@pytest.mark.asyncio
@respx.mock
async def test_unknown_section_lists_the_real_ones():
    upstream = {"data": {"reportType": "Cloud", "report": {"tenant": {}, "eventTypes": {}}}}
    respx.get(url__startswith=BASE).mock(return_value=httpx.Response(200, json=upstream))

    payload = json.loads(
        await _call({"tenant_id": TENANT, "report_id": "rep-1", "section": "nope"})
    )
    assert payload["error"]["code"] == "invalid_argument"
    assert "eventTypes" in payload["error"]["message"]


@pytest.mark.asyncio
@respx.mock
async def test_report_within_budget_is_not_altered():
    upstream = {"data": {"reportType": "Cloud", "report": {"securityAnalysis": {"a": 1}}}}
    respx.get(url__startswith=BASE).mock(return_value=httpx.Response(200, json=upstream))

    body = await _call({"tenant_id": TENANT, "report_id": "rep-1"})
    assert len(body) <= MAX_CHARS
    assert json.loads(body) == upstream
