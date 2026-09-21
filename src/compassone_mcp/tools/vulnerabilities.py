"""Vulnerability management: findings, scans, and exposure results.

Tool naming convention: compassone_<action>_<resource>

⚠️ Tenant scoping on these four endpoints is NOT yet verified against the live
API. Toby's 2026-09-18 measurement covered /v1/alert-groups only. The vendor's
OpenAPI document declares no header parameters anywhere, so the spec cannot
settle it either; the circumstantial evidence is that /v1/vulnerability-
management/scans lets you sort by tenantId, so its rows are tenant-bearing.
These tools therefore send x-tenant-id exactly like every other scoped tool.
Before this module is relied on for client-facing numbers, run the with-header
/ without-header comparison from PRD-19227 §S6 against each of the four. If any
endpoint ignores the header, do not ship it silently — that is precisely the
quiet-empty failure this service exists to avoid.
"""

from collections.abc import Callable
from typing import Annotated, Literal

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations
from pydantic import Field

from .._json import dump_json_capped
from ..api_client import CompassOneClient, CompassOneError
from ._common import DATE_DESC, NO_CREDS, TENANT_ID_DESC, SortDirection, fetch_capped

_MAX_PAGE_SIZE = 200


def register(mcp: FastMCP, client_factory: Callable[[], CompassOneClient | None]) -> None:
    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
    async def compassone_list_vulnerabilities(
        tenant_id: Annotated[str, Field(description=TENANT_ID_DESC)],
        search: Annotated[str | None, Field(description="Free-text search over findings.")] = None,
        severity: Annotated[
            list[str] | None, Field(description="Severity filter values.")
        ] = None,
        status: Annotated[str | None, Field(description="Finding status filter.")] = None,
        cve_ids: Annotated[
            list[str] | None, Field(description="Restrict to these vulnerability ids.")
        ] = None,
        device_id: Annotated[
            str | None, Field(description="Restrict to findings on one device.")
        ] = None,
        exploitability: Annotated[
            Literal["Attacked", "Unreported"] | None,
            Field(description="Whether the vulnerability is known to be exploited in the wild."),
        ] = None,
        prioritized: Annotated[
            bool | None, Field(description="Only vendor-prioritized findings.")
        ] = None,
        has_affected_assets: Annotated[
            bool | None, Field(description="Only findings with at least one affected asset.")
        ] = None,
        hide_resolved: Annotated[
            bool | None, Field(description="Exclude resolved findings.")
        ] = None,
        found_after: Annotated[
            str | None, Field(description="First seen after. " + DATE_DESC)
        ] = None,
        found_before: Annotated[
            str | None, Field(description="First seen before. " + DATE_DESC)
        ] = None,
        page: Annotated[int, Field(description="1-based page number.", ge=1)] = 1,
        page_size: Annotated[int, Field(description="Rows per page (1-200).", ge=1)] = 50,
        sort_by: Annotated[
            str | None,
            Field(
                description=(
                    "Field to sort by (default name), e.g. baseScore, severity, "
                    "foundOn, lastSeenOn, assetsAmount, exploitability."
                )
            ),
        ] = None,
        sort_order: Annotated[SortDirection | None, Field(description="Sort direction.")] = None,
    ) -> str:
        """List vulnerability findings for a tenant.

        Findings are CVE-level rows with severity, scores and affected-asset
        counts. Use compassone_list_asset_relationships with
        related_class=VULNERABILITY to go the other way, from one machine to
        its findings.
        """
        client = client_factory()
        if client is None:
            return NO_CREDS

        async def fetch(size: int) -> object:
            return await client.get_scoped(
                "/v1/vulnerability-management/vulnerabilities",
                tenant_id,
                params={
                    "search": search,
                    "severity": severity,
                    "status": status,
                    "ids": cve_ids,
                    "deviceId": device_id,
                    "exploitability": exploitability,
                    "prioritized": prioritized,
                    "hasAffectedAssets": has_affected_assets,
                    "hideResolvedVulnerabilities": hide_resolved,
                    "foundAfter": found_after,
                    "foundBefore": found_before,
                    "page": page,
                    "pageSize": size,
                    "sortBy": sort_by,
                    "sortOrder": sort_order,
                },
            )

        try:
            return await fetch_capped(fetch, min(page_size, _MAX_PAGE_SIZE))
        except CompassOneError as e:
            return e.to_envelope()

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
    async def compassone_list_vulnerability_scans(
        tenant_id: Annotated[str, Field(description=TENANT_ID_DESC)],
        search: Annotated[str | None, Field(description="Free-text search over scans.")] = None,
        scan_type: Annotated[
            list[Literal["darkweb", "external", "local", "network"]] | None,
            Field(description="Restrict to these scan types."),
        ] = None,
        status: Annotated[
            list[Literal["canceled", "completed", "failed", "in-progress", "new"]] | None,
            Field(description="Restrict to these scan states."),
        ] = None,
        asset_ids: Annotated[
            list[str] | None, Field(description="Restrict to scans of these assets.")
        ] = None,
        created_on_start: Annotated[
            str | None, Field(description="Created at or after. " + DATE_DESC)
        ] = None,
        created_on_end: Annotated[
            str | None, Field(description="Created at or before. " + DATE_DESC)
        ] = None,
        page: Annotated[int, Field(description="1-based page number.", ge=1)] = 1,
        page_size: Annotated[int, Field(description="Rows per page (1-200).", ge=1)] = 50,
        sort_by: Annotated[
            str | None, Field(description="Field to sort by (default createdOn).")
        ] = None,
        sort_order: Annotated[SortDirection | None, Field(description="Sort direction.")] = None,
    ) -> str:
        """List vulnerability scan runs and their status.

        Use this to confirm a scan actually completed before reporting on its
        findings — a tenant with no recent completed scan has no coverage, not
        a clean bill of health. Scan ids from here feed
        compassone_get_external_scan_exposures.
        """
        client = client_factory()
        if client is None:
            return NO_CREDS

        async def fetch(size: int) -> object:
            return await client.get_scoped(
                "/v1/vulnerability-management/scans",
                tenant_id,
                params={
                    "search": search,
                    "type": scan_type,
                    "status": status,
                    "assetId": asset_ids,
                    "createdOnStart": created_on_start,
                    "createdOnEnd": created_on_end,
                    "page": page,
                    "pageSize": size,
                    "sortBy": sort_by,
                    "sortOrder": sort_order,
                },
            )

        try:
            return await fetch_capped(fetch, min(page_size, _MAX_PAGE_SIZE))
        except CompassOneError as e:
            return e.to_envelope()

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
    async def compassone_list_darkweb_exposures(
        tenant_id: Annotated[str, Field(description=TENANT_ID_DESC)],
        search: Annotated[str | None, Field(description="Free-text search over exposures.")] = None,
        domain: Annotated[str | None, Field(description="Restrict to one impacted domain.")] = None,
        password_exposed: Annotated[
            bool | None, Field(description="Only rows where a password was exposed.")
        ] = None,
        username_exposed: Annotated[
            bool | None, Field(description="Only rows where a username was exposed.")
        ] = None,
        page: Annotated[int, Field(description="1-based page number.", ge=1)] = 1,
        page_size: Annotated[int, Field(description="Rows per page (1-200).", ge=1)] = 50,
        sort_by: Annotated[
            Literal["breachCreatedAt", "password", "username", "impactedDomain", "breachName"]
            | None,
            Field(description="Field to sort by (default breachCreatedAt)."),
        ] = None,
        sort_order: Annotated[SortDirection | None, Field(description="Sort direction.")] = None,
    ) -> str:
        """Get the tenant's most recent dark-web credential exposure results.

        Returns rows from the last dark-web scan only — compromised credentials
        found in breach corpora. An empty result means the last scan found
        nothing; no scan at all is visible via
        compassone_list_vulnerability_scans with scan_type=darkweb.
        """
        client = client_factory()
        if client is None:
            return NO_CREDS

        async def fetch(size: int) -> object:
            return await client.get_scoped(
                "/v1/vulnerability-management/darkweb/scan/exposures",
                tenant_id,
                params={
                    "search": search,
                    "domain": domain,
                    "passwordExposed": password_exposed,
                    "usernameExposed": username_exposed,
                    "page": page,
                    "pageSize": size,
                    "sortBy": sort_by,
                    "sortOrder": sort_order,
                },
            )

        try:
            return await fetch_capped(fetch, min(page_size, _MAX_PAGE_SIZE))
        except CompassOneError as e:
            return e.to_envelope()

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
    async def compassone_get_external_scan_exposures(
        tenant_id: Annotated[str, Field(description=TENANT_ID_DESC)],
        scan_id: Annotated[
            str,
            Field(
                description=(
                    "External scan id, from compassone_list_vulnerability_scans "
                    "with scan_type=external."
                )
            ),
        ],
    ) -> str:
        """Get the findings from one external (perimeter) scan.

        External scans probe the tenant's internet-facing surface. Pair with
        compassone_list_vulnerability_scans to pick the run to report on.
        """
        client = client_factory()
        if client is None:
            return NO_CREDS
        try:
            result = await client.get_scoped(
                f"/v1/vulnerability-management/external/scan/exposures/{scan_id}", tenant_id
            )
        except CompassOneError as e:
            return e.to_envelope()
        return dump_json_capped(result)
