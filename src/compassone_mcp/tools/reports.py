"""Pre-generated report runs (the monthly client report source).

Tool naming convention: compassone_<action>_<resource>
"""

from collections.abc import Callable
from typing import Annotated, Literal

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations
from pydantic import Field

from .._json import MAX_CHARS, dump_json_capped, error_envelope, fits
from ..api_client import CompassOneClient, CompassOneError
from ._common import NO_CREDS, TENANT_ID_DESC, fetch_capped

_MAX_PAGE_SIZE = 200  # vendor allows up to 1000; capped for token economy


def register(mcp: FastMCP, client_factory: Callable[[], CompassOneClient | None]) -> None:
    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
    async def compassone_list_reports(
        tenant_id: Annotated[str, Field(description=TENANT_ID_DESC)],
        report_type: Annotated[
            Literal["Cloud", "Executive", "MDR"] | None,
            Field(description="Restrict to one report type."),
        ] = None,
        start_date: Annotated[
            str | None,
            Field(
                description=(
                    "Keep runs whose intervalStart is >= this ISO 8601 "
                    "date (inclusive)."
                )
            ),
        ] = None,
        end_date: Annotated[
            str | None,
            Field(
                description=(
                    "Keep runs whose intervalStart is <= this ISO 8601 "
                    "date (inclusive)."
                )
            ),
        ] = None,
        page: Annotated[int, Field(description="1-based page number.", ge=1)] = 1,
        page_size: Annotated[int, Field(description="Rows per page (1-200).", ge=1)] = 50,
        sort_order: Annotated[
            Literal["asc", "desc"] | None,
            Field(description="Sort direction on intervalStart (default desc)."),
        ] = None,
    ) -> str:
        """List available report runs for a tenant.

        Each row is one generated run: id, reportType, intervalStart,
        intervalEnd, created, updated. Use the id with
        compassone_get_report_json. intervalStart/intervalEnd are returned
        untouched so a caller can assert the run actually covers the month it
        is reporting on, rather than trusting the filter.
        """
        client = client_factory()
        if client is None:
            return NO_CREDS

        async def fetch(size: int) -> object:
            return await client.get_scoped(
                "/v1/reports",
                tenant_id,
                params={
                    "reportType": report_type,
                    "startDate": start_date,
                    "endDate": end_date,
                    "page": page,
                    "pageSize": size,
                    "sortOrder": sort_order,
                },
            )

        try:
            return await fetch_capped(fetch, min(page_size, _MAX_PAGE_SIZE))
        except CompassOneError as e:
            return e.to_envelope()

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
    async def compassone_get_report_json(
        tenant_id: Annotated[str, Field(description=TENANT_ID_DESC)],
        report_id: Annotated[
            str, Field(description="Report run id, from compassone_list_reports.")
        ],
        section: Annotated[
            str | None,
            Field(
                description=(
                    "Optional top-level key of `report` to return on its own, "
                    "e.g. securityPosture, incidents, threatTrends. Omit to get "
                    "the whole report. Use this when the full report is too "
                    "large to return in one call — the error message lists the "
                    "available keys."
                )
            ),
        ] = None,
    ) -> str:
        """Get one report run's JSON payload.

        `report` is polymorphic — its shape depends on reportType (Executive,
        MDR, Cloud, VulnerabilityManagement) — and is returned verbatim: keys
        are never renamed, flattened, or reduced to a subset. In particular the
        legacy Executive payload keyed executiveSummary is left alongside the
        current one keyed securityPosture rather than normalised into it, since
        consumers branch on which is present.
        """
        client = client_factory()
        if client is None:
            return NO_CREDS
        try:
            result = await client.get_scoped(f"/v1/reports/{report_id}/json", tenant_id)
        except CompassOneError as e:
            return e.to_envelope()

        data = result.get("data") if isinstance(result, dict) else None

        if section is not None:
            if not isinstance(data, dict) or not isinstance(data.get("report"), dict):
                return error_envelope(
                    "invalid_argument",
                    "report payload is not an object, so it has no sections to select",
                    False,
                )
            report = data["report"]
            if section not in report:
                return error_envelope(
                    "invalid_argument",
                    f"no section {section!r} in this report; available: "
                    f"{sorted(report)}",
                    False,
                )
            # Still the vendor's own value for that key, unmodified — the
            # consumer selected it, this service did not.
            return dump_json_capped(
                {
                    "reportType": data.get("reportType"),
                    "section": section,
                    "report": {section: report[section]},
                }
            )

        # No silent truncation here. A half-delivered monthly report looks like
        # a complete one to a consumer that cannot see what was dropped, so an
        # oversized report fails loudly and names the sections to fetch instead.
        #
        # NOTE (pending Toby's confirmation, PRD-19227): the alternative is to
        # return a dump_json_capped() page carrying truncated/original_count
        # markers. To switch, replace this block with `return
        # dump_json_capped(result)`.
        if not fits(result):
            available = sorted(data["report"]) if isinstance(data.get("report"), dict) else []
            return error_envelope(
                "invalid_argument",
                f"report is too large to return in one call "
                f"(exceeds {MAX_CHARS} chars). Re-call with section=<key>; "
                f"available sections: {available}",
                False,
            )
        return dump_json_capped(result)
