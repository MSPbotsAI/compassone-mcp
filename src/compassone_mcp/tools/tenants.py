"""Tenant directory — the call that produces a tenant id.

Tool naming convention: compassone_<action>_<resource>
"""

from collections.abc import Callable
from typing import Annotated, Literal

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations
from pydantic import Field

from ..api_client import CompassOneClient, CompassOneError
from ._common import NO_CREDS, SortDirection, fetch_capped

_MAX_PAGE_SIZE = 200


def register(mcp: FastMCP, client_factory: Callable[[], CompassOneClient | None]) -> None:
    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
    async def compassone_list_tenants(
        search: Annotated[
            str | None,
            Field(
                description=(
                    "Match against both tenant id and tenant name (the vendor "
                    "searches both fields)."
                )
            ),
        ] = None,
        account_id: Annotated[
            str | None, Field(description="Restrict results to one partner account.")
        ] = None,
        page: Annotated[int, Field(description="1-based page number.", ge=1)] = 1,
        page_size: Annotated[int, Field(description="Rows per page (1-200).", ge=1)] = 50,
        sort_by: Annotated[
            Literal["id", "name", "created", "type", "description", "domain"] | None,
            Field(description="Field to sort by (default name)."),
        ] = None,
        sort_order: Annotated[SortDirection | None, Field(description="Sort direction.")] = None,
    ) -> str:
        """List the customer tenants this partner credential can reach.

        Start here. Every other tool needs a tenant_id, and this is the only
        call that produces one — it is also the only one that does not take
        one. Each row's `type` (MDR / MDR ONBOARD / POC / SELF / UNSET)
        distinguishes real customers from the MSP's own tenant; check it
        before running a customer report against SELF.
        """
        client = client_factory()
        if client is None:
            return NO_CREDS

        async def fetch(size: int) -> object:
            # The only unscoped call in this service: no x-tenant-id header,
            # because this is what produces the tenant id in the first place.
            return await client.get_unscoped(
                "/v1/tenants",
                params={
                    "search": search,
                    "accountId": account_id,
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
