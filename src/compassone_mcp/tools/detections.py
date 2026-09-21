"""Detections (alert groups) — listing, detail, and the analytics rollups.

A detection aggregates multiple related alerts into a single entity; the
vendor's API calls them alert groups and its guides call them detections.

Tool naming convention: compassone_<action>_<resource>
"""

from collections.abc import Callable
from typing import Annotated, Literal

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations
from pydantic import Field

from .._json import dump_json_capped
from ..api_client import CompassOneClient, CompassOneError
from ._common import (
    DATE_DESC,
    DETECTION_TYPE_DESC,
    NO_CREDS,
    TENANT_ID_DESC,
    AlertStatus,
    DetectionType,
    SortDirection,
    fetch_capped,
)

_MAX_TAKE = 200
_WINDOW_DESC = (
    " Defaults to the last 90 days when omitted. " + DATE_DESC
)


def register(mcp: FastMCP, client_factory: Callable[[], CompassOneClient | None]) -> None:
    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
    async def compassone_list_detections(
        tenant_id: Annotated[str, Field(description=TENANT_ID_DESC)],
        take: Annotated[int, Field(description="Max rows to return (1-200).", ge=1)] = 50,
        skip: Annotated[int, Field(description="Rows to skip, for paging.", ge=0)] = 0,
        status: Annotated[
            list[AlertStatus] | None,
            Field(description="Group-level status filter. One or both of OPEN, RESOLVED."),
        ] = None,
        detection_type: Annotated[
            DetectionType | None, Field(description=DETECTION_TYPE_DESC)
        ] = None,
        search: Annotated[
            str | None,
            Field(
                description=(
                    "Free-text search over alertTypes, action, dataset, username "
                    "and hostname. Minimum 3 characters."
                )
            ),
        ] = None,
        tunnel_search: Annotated[
            str | None, Field(description="Vendor tunnel-specific search string.")
        ] = None,
        since: Annotated[
            str | None,
            Field(
                description=(
                    "Only detections created since this instant. Capped at 90 "
                    "days ago; future dates are rejected. " + DATE_DESC
                )
            ),
        ] = None,
        min_alerts_count: Annotated[
            int | None, Field(description="Only groups with at least this many alerts.")
        ] = None,
        max_alerts_count: Annotated[
            int | None, Field(description="Only groups with at most this many alerts.")
        ] = None,
        sort_by_column: Annotated[
            Literal["alertCount", "alertTypes", "created", "hostname", "status", "username"]
            | None,
            Field(description="Column to sort by (default created)."),
        ] = None,
        sort_direction: Annotated[
            SortDirection | None, Field(description="Sort direction.")
        ] = None,
    ) -> str:
        """List detections (alert groups) for a tenant.

        A detection bundles related alerts into one entity. status here is the
        group-level OPEN/RESOLVED; the nine-state lifecycle belongs to the
        ticket nested in each group, not to the group.
        """
        client = client_factory()
        if client is None:
            return NO_CREDS

        async def fetch(size: int) -> object:
            # The vendor also accepts a `tenantId` query parameter here, which
            # it has deprecated in favour of the x-tenant-id header. It is
            # deliberately not exposed: two ways to say the same thing invites
            # a caller to set one and not the other.
            return await client.get_scoped(
                "/v1/alert-groups",
                tenant_id,
                params={
                    "take": size,
                    "skip": skip,
                    "status": status,
                    "type": detection_type,
                    "search": search,
                    "tunnelSearch": tunnel_search,
                    "since": since,
                    "minAlertsCount": min_alerts_count,
                    "maxAlertsCount": max_alerts_count,
                    "sortByColumn": sort_by_column,
                    "sortDirection": sort_direction,
                },
            )

        try:
            return await fetch_capped(fetch, min(take, _MAX_TAKE))
        except CompassOneError as e:
            return e.to_envelope()

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
    async def compassone_get_detection(
        tenant_id: Annotated[str, Field(description=TENANT_ID_DESC)],
        alert_group_id: Annotated[
            str, Field(description="Detection (alert group) id, from compassone_list_detections.")
        ],
    ) -> str:
        """Get one detection (alert group) in full.

        Includes the nested ticket, whose own status carries the nine-state
        lifecycle (NEW, CLAIM, INVESTIGATE, ESCALATE, RESOLVE, CLOSE,
        INFORMATIONAL, NO_AGENT, SUGGEST_SUPPRESSION).
        """
        client = client_factory()
        if client is None:
            return NO_CREDS
        try:
            result = await client.get_scoped(f"/v1/alert-groups/{alert_group_id}", tenant_id)
        except CompassOneError as e:
            return e.to_envelope()
        return dump_json_capped(result)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
    async def compassone_list_detection_alerts(
        tenant_id: Annotated[str, Field(description=TENANT_ID_DESC)],
        alert_group_id: Annotated[
            str, Field(description="Detection (alert group) id whose alerts to list.")
        ],
        take: Annotated[int, Field(description="Max rows to return (1-200).", ge=1)] = 50,
        skip: Annotated[int, Field(description="Rows to skip, for paging.", ge=0)] = 0,
        sort_by_column: Annotated[
            Literal["attacker", "created", "dataset", "target", "updated"] | None,
            Field(description="Column to sort by."),
        ] = None,
        sort_direction: Annotated[
            SortDirection | None, Field(description="Sort direction.")
        ] = None,
    ) -> str:
        """List the individual alerts inside one detection.

        Use this to see the raw events a detection aggregated, after
        compassone_list_detections or compassone_get_detection identified it.
        """
        client = client_factory()
        if client is None:
            return NO_CREDS

        async def fetch(size: int) -> object:
            return await client.get_scoped(
                f"/v1/alert-groups/{alert_group_id}/alerts",
                tenant_id,
                params={
                    "take": size,
                    "skip": skip,
                    "sortByColumn": sort_by_column,
                    "sortDirection": sort_direction,
                },
            )

        try:
            return await fetch_capped(fetch, min(take, _MAX_TAKE))
        except CompassOneError as e:
            return e.to_envelope()

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
    async def compassone_count_detections(
        tenant_id: Annotated[str, Field(description=TENANT_ID_DESC)],
        start_date: Annotated[str | None, Field(description="Window start." + _WINDOW_DESC)] = None,
        end_date: Annotated[str | None, Field(description="Window end." + _WINDOW_DESC)] = None,
        detection_type: Annotated[
            DetectionType | None, Field(description=DETECTION_TYPE_DESC)
        ] = None,
        status: Annotated[
            AlertStatus | None, Field(description="Group-level status: OPEN or RESOLVED.")
        ] = None,
    ) -> str:
        """Count detections in a window, without listing them.

        Cheaper than compassone_list_detections when a report only needs the
        headline number.
        """
        client = client_factory()
        if client is None:
            return NO_CREDS
        try:
            result = await client.get_scoped(
                "/v1/alert-groups/count",
                tenant_id,
                params={
                    "startDate": start_date,
                    "endDate": end_date,
                    "type": detection_type,
                    "status": status,
                },
            )
        except CompassOneError as e:
            return e.to_envelope()
        return dump_json_capped(result)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
    async def compassone_list_detections_by_week(
        tenant_id: Annotated[str, Field(description=TENANT_ID_DESC)],
        start_date: Annotated[str | None, Field(description="Window start." + _WINDOW_DESC)] = None,
        end_date: Annotated[str | None, Field(description="Window end." + _WINDOW_DESC)] = None,
        detection_type: Annotated[
            DetectionType | None, Field(description=DETECTION_TYPE_DESC)
        ] = None,
    ) -> str:
        """Get detection counts bucketed by week.

        The trend series behind a monthly report's detections-over-time chart.
        """
        client = client_factory()
        if client is None:
            return NO_CREDS
        try:
            result = await client.get_scoped(
                "/v1/alert-groups/alert-groups-by-week",
                tenant_id,
                params={
                    "startDate": start_date,
                    "endDate": end_date,
                    "type": detection_type,
                },
            )
        except CompassOneError as e:
            return e.to_envelope()
        return dump_json_capped(result)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
    async def compassone_top_detections_by_entity(
        tenant_id: Annotated[str, Field(description=TENANT_ID_DESC)],
        start_date: Annotated[str | None, Field(description="Window start." + _WINDOW_DESC)] = None,
        end_date: Annotated[str | None, Field(description="Window end." + _WINDOW_DESC)] = None,
        detection_type: Annotated[
            DetectionType | None, Field(description=DETECTION_TYPE_DESC)
        ] = None,
        entity_name: Annotated[
            str | None, Field(description="Restrict to one entity (host or user).")
        ] = None,
        limit: Annotated[int, Field(description="Max entities to return (1-200).", ge=1)] = 10,
    ) -> str:
        """Rank the entities (hosts, users) with the most detections.

        Answers "which machines or accounts drove this month's volume".
        """
        client = client_factory()
        if client is None:
            return NO_CREDS
        try:
            result = await client.get_scoped(
                "/v1/alert-groups/top-detections-by-entity",
                tenant_id,
                params={
                    "startDate": start_date,
                    "endDate": end_date,
                    "detectionType": detection_type,
                    "entityName": entity_name,
                    "limit": min(limit, _MAX_TAKE),
                },
            )
        except CompassOneError as e:
            return e.to_envelope()
        return dump_json_capped(result)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
    async def compassone_top_detections_by_threat(
        tenant_id: Annotated[str, Field(description=TENANT_ID_DESC)],
        start_date: Annotated[str | None, Field(description="Window start." + _WINDOW_DESC)] = None,
        end_date: Annotated[str | None, Field(description="Window end." + _WINDOW_DESC)] = None,
        detection_type: Annotated[
            DetectionType | None, Field(description=DETECTION_TYPE_DESC)
        ] = None,
        limit: Annotated[int, Field(description="Max threat types to return (1-200).", ge=1)] = 10,
    ) -> str:
        """Rank the threat types behind the most detections.

        Answers "what kind of attack did this client see most" — the companion
        to compassone_top_detections_by_entity, which answers "against what".
        """
        client = client_factory()
        if client is None:
            return NO_CREDS
        try:
            result = await client.get_scoped(
                "/v1/alert-groups/top-detections-by-threat",
                tenant_id,
                params={
                    "startDate": start_date,
                    "endDate": end_date,
                    "detectionType": detection_type,
                    "limit": min(limit, _MAX_TAKE),
                },
            )
        except CompassOneError as e:
            return e.to_envelope()
        return dump_json_capped(result)
