"""tools/list snapshot.

EXPECTED_REQUIRED is an exact-set assertion in both directions: a new tool, a
removed tool, or a changed required-parameter set all turn this red. That is
the point — every one of those is an externally visible change that downstream
agents can see, so it should never land silently (SOP §13).
"""

import pytest

from compassone_mcp.config import Settings
from compassone_mcp.server import create_mcp_server

# tool name -> exact set of required input parameters
EXPECTED_REQUIRED = {
    # The only unscoped tool: it is what produces a tenant id.
    "compassone_list_tenants": set(),
    "compassone_get_security_posture_rating": {"tenant_id"},
    "compassone_list_reports": {"tenant_id"},
    "compassone_get_report_json": {"tenant_id", "report_id"},
    "compassone_list_detections": {"tenant_id"},
    "compassone_get_detection": {"tenant_id", "alert_group_id"},
    "compassone_list_detection_alerts": {"tenant_id", "alert_group_id"},
    "compassone_count_detections": {"tenant_id"},
    "compassone_list_detections_by_week": {"tenant_id"},
    "compassone_top_detections_by_entity": {"tenant_id"},
    "compassone_top_detections_by_threat": {"tenant_id"},
    # class is required by the vendor — there is no "all assets" query.
    "compassone_list_assets": {"tenant_id", "asset_class"},
    "compassone_get_asset": {"tenant_id", "asset_id"},
    "compassone_list_asset_relationships": {
        "tenant_id",
        "asset_id",
        "related_class",
        "direction",
    },
    "compassone_list_vulnerabilities": {"tenant_id"},
    "compassone_list_vulnerability_scans": {"tenant_id"},
    "compassone_list_darkweb_exposures": {"tenant_id"},
    "compassone_get_external_scan_exposures": {"tenant_id", "scan_id"},
}

UNSCOPED_TOOLS = {"compassone_list_tenants"}


def _server():
    return create_mcp_server(Settings())


@pytest.mark.asyncio
async def test_tools_list_snapshot():
    tools = await _server().list_tools()
    assert {t.name for t in tools} == set(EXPECTED_REQUIRED)

    by_name = {t.name: t for t in tools}
    for name, expected_required in EXPECTED_REQUIRED.items():
        tool = by_name[name]
        assert set(tool.inputSchema.get("required", [])) == expected_required, name


@pytest.mark.asyncio
async def test_every_tool_is_read_only():
    # This service wraps GET endpoints only. If a write tool is ever added,
    # this assertion should be narrowed deliberately, not deleted.
    for tool in await _server().list_tools():
        assert tool.annotations is not None, tool.name
        assert tool.annotations.readOnlyHint is True, tool.name


@pytest.mark.asyncio
async def test_tenant_id_is_required_everywhere_but_the_tenant_directory():
    """The load-bearing assertion of PRD-19227.

    tenant_id must be *required*, not merely present. If it is ever relaxed to
    optional, a caller that omits it runs at partner scope and gets an answer
    about nobody in particular — see tools/_common.TENANT_ID_DESC.
    """
    for tool in await _server().list_tools():
        props = tool.inputSchema.get("properties", {})
        required = set(tool.inputSchema.get("required", []))
        if tool.name in UNSCOPED_TOOLS:
            assert "tenant_id" not in props, tool.name
        else:
            assert "tenant_id" in required, tool.name


@pytest.mark.asyncio
async def test_tool_descriptions_are_bounded():
    for tool in await _server().list_tools():
        description = tool.description or ""
        assert len(description) <= 500, f"{tool.name}: {len(description)} chars"
        first_line = description.strip().splitlines()[0]
        assert len(first_line) <= 100, f"{tool.name}: first line {len(first_line)} chars"


def test_service_instructions_present_and_bounded():
    instructions = _server().instructions or ""
    assert instructions
    assert len(instructions) <= 1500
