"""Upstream status -> error envelope, and outbound query encoding."""

import json

import httpx
import pytest
import respx

from compassone_mcp.config import Settings
from compassone_mcp.server import _gateway_token_var, create_mcp_server

BASE = "https://api.blackpointcyber.com"
TENANT = "tenant-uuid"


async def _call(tool_name, args):
    ctx_token = _gateway_token_var.set("test-token")
    try:
        result = await create_mcp_server(Settings(auth_mode="gateway")).call_tool(tool_name, args)
    finally:
        _gateway_token_var.reset(ctx_token)
    content = result[0] if isinstance(result, tuple) else result
    return content[0].text


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("status", "code", "retryable"),
    [
        (400, "invalid_argument", False),
        (401, "unauthorized", False),
        (403, "unauthorized", False),
        (404, "not_found", False),
        (422, "invalid_argument", False),
        (409, "invalid_argument", False),
    ],
)
@respx.mock
async def test_error_envelope_mapping(status, code, retryable):
    respx.get(url__startswith=BASE).mock(
        return_value=httpx.Response(status, json={"message": "boom"})
    )
    payload = json.loads(await _call("compassone_list_tenants", {}))
    assert payload["error"]["code"] == code
    assert payload["error"]["retryable"] is retryable


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [429, 500, 503])
@respx.mock
async def test_retryable_statuses_are_retried_then_reported(status):
    # _MAX_RETRIES=3 means 4 attempts total before the failure is reported.
    route = respx.get(url__startswith=BASE).mock(
        return_value=httpx.Response(status, headers={"Retry-After": "0"}, json={})
    )
    payload = json.loads(await _call("compassone_list_tenants", {}))
    assert route.call_count == 4
    assert payload["error"]["retryable"] is True
    assert payload["error"]["code"] == ("rate_limited" if status == 429 else "upstream_error")


@pytest.mark.asyncio
@respx.mock
async def test_none_valued_params_are_dropped_and_lists_repeat_the_key():
    """Unset optional params must not reach the vendor as empty strings, and a
    multi-valued param must serialize as repeated keys, not a Python repr."""
    route = respx.get(url__startswith=BASE).mock(
        return_value=httpx.Response(200, json={"data": []})
    )

    await _call(
        "compassone_list_assets",
        {"tenant_id": TENANT, "asset_class": ["DEVICE", "USER"]},
    )

    params = route.calls.last.request.url.params
    assert params.get_list("class") == ["DEVICE", "USER"]
    # search/filter/sortBy were never supplied, so they must be absent entirely.
    for absent in ("search", "filter", "sortBy", "sortOrder", "withDeleted"):
        assert absent not in params
