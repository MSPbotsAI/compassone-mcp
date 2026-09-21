"""Asset inventory and the relationship graph between assets.

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
    NO_CREDS,
    TENANT_ID_DESC,
    AssetClass,
    RelationshipClass,
    SortDirection,
    fetch_capped,
)

_MAX_PAGE_SIZE = 200

# `class` is a Python keyword, so the tool parameter is asset_class and is
# mapped back to `class` on the wire.
_CLASS_DESC = (
    "Required — sent as the vendor's `class` query parameter. Classes live "
    "today are DEVICE, USER, SOFTWARE, SOURCE and SURVEY; SERVICE, PROCESS, "
    "CONTAINER, PERSON, FRAMEWORK and NETSTAT are declared but not yet "
    "populated. The response schema varies by class — a DEVICE row carries "
    "agent, OS, hardware and network fields a USER row does not."
)


def register(mcp: FastMCP, client_factory: Callable[[], CompassOneClient | None]) -> None:
    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
    async def compassone_list_assets(
        tenant_id: Annotated[str, Field(description=TENANT_ID_DESC)],
        asset_class: Annotated[list[AssetClass], Field(description=_CLASS_DESC)],
        search: Annotated[
            str | None, Field(description="Free-text search over asset names.")
        ] = None,
        query_filter: Annotated[
            str | None,
            Field(
                description=(
                    "Vendor WITH-clause filter, passed through verbatim (this "
                    "service does not parse or rewrite it), e.g. "
                    "\"WITH platform='WINDOWS'\" or "
                    "\"THAT HAS SOURCE WITH type='AGENTENDPOINT'\"."
                )
            ),
        ] = None,
        page: Annotated[int, Field(description="1-based page number.", ge=1)] = 1,
        page_size: Annotated[int, Field(description="Rows per page (1-200).", ge=1)] = 50,
        with_deleted: Annotated[
            bool | None, Field(description="Include deleted assets.")
        ] = None,
        sources: Annotated[
            list[str] | None, Field(description="Restrict to assets discovered by these sources.")
        ] = None,
        platform: Annotated[
            list[str] | None, Field(description="Restrict to these platforms, e.g. WINDOWS.")
        ] = None,
        asset_type: Annotated[
            list[str] | None, Field(description="Restrict to these asset types.")
        ] = None,
        decommissioned: Annotated[
            list[str] | None, Field(description="Decommissioned-state filter values.")
        ] = None,
        wd_status: Annotated[
            list[str] | None, Field(description="Windows Defender status filter values.")
        ] = None,
        sort_by: Annotated[
            str | None,
            Field(
                description=(
                    "Field to sort by (default name), e.g. lastSeenOn, criticality, "
                    "displayName, agentLastSeenOn."
                )
            ),
        ] = None,
        sort_order: Annotated[SortDirection | None, Field(description="Sort direction.")] = None,
    ) -> str:
        """List a tenant's assets of one or more classes.

        asset_class is required by the vendor — there is no "all assets" query.
        Rows are returned with whatever fields the vendor sends for the classes
        requested; nothing is dropped or normalised across classes.
        """
        client = client_factory()
        if client is None:
            return NO_CREDS

        async def fetch(size: int) -> object:
            return await client.get_scoped(
                "/v1/assets",
                tenant_id,
                params={
                    "class": asset_class,
                    "search": search,
                    "filter": query_filter,
                    "page": page,
                    "pageSize": size,
                    "withDeleted": with_deleted,
                    "sources": sources,
                    "platform": platform,
                    "type": asset_type,
                    "decommissioned": decommissioned,
                    "wdStatus": wd_status,
                    "sortBy": sort_by,
                    "sortOrder": sort_order,
                },
            )

        try:
            return await fetch_capped(fetch, min(page_size, _MAX_PAGE_SIZE))
        except CompassOneError as e:
            return e.to_envelope()

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
    async def compassone_get_asset(
        tenant_id: Annotated[str, Field(description=TENANT_ID_DESC)],
        asset_id: Annotated[str, Field(description="Asset id, from compassone_list_assets.")],
    ) -> str:
        """Get one asset in full.

        Which fields come back depends on the asset's class.
        """
        client = client_factory()
        if client is None:
            return NO_CREDS
        try:
            result = await client.get_scoped(f"/v1/assets/{asset_id}", tenant_id)
        except CompassOneError as e:
            return e.to_envelope()
        return dump_json_capped(result)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
    async def compassone_list_asset_relationships(
        tenant_id: Annotated[str, Field(description=TENANT_ID_DESC)],
        asset_id: Annotated[str, Field(description="Asset id whose relationships to list.")],
        related_class: Annotated[
            RelationshipClass,
            Field(
                description=(
                    "Required — sent as the vendor's `class` query parameter, "
                    "naming the class at the far end of the relationship. Wider "
                    "than compassone_list_assets: also accepts the finding "
                    "classes ALERT, ALERTGROUP, EVENT, INCIDENT and VULNERABILITY."
                )
            ),
        ],
        direction: Annotated[
            Literal["in", "out"],
            Field(
                description=(
                    "Required. `out` follows edges from this asset, `in` "
                    "follows edges to it."
                )
            ),
        ],
        page: Annotated[int, Field(description="1-based page number.", ge=1)] = 1,
        page_size: Annotated[int, Field(description="Rows per page (1-200).", ge=1)] = 50,
        with_deleted: Annotated[
            bool | None, Field(description="Include deleted related records.")
        ] = None,
        sort_order: Annotated[SortDirection | None, Field(description="Sort direction.")] = None,
    ) -> str:
        """List what one asset is connected to, in one direction.

        Both related_class and direction are required by the vendor. Use the
        finding classes (ALERT, ALERTGROUP, INCIDENT, VULNERABILITY) to answer
        "what has been found on this machine".
        """
        client = client_factory()
        if client is None:
            return NO_CREDS

        async def fetch(size: int) -> object:
            return await client.get_scoped(
                f"/v1/assets/{asset_id}/relationships",
                tenant_id,
                params={
                    "class": related_class,
                    "direction": direction,
                    "page": page,
                    "pageSize": size,
                    "withDeleted": with_deleted,
                    "sortOrder": sort_order,
                },
            )

        try:
            return await fetch_capped(fetch, min(page_size, _MAX_PAGE_SIZE))
        except CompassOneError as e:
            return e.to_envelope()
