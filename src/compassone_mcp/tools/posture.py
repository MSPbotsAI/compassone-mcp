"""Security posture rating.

Tool naming convention: compassone_<action>_<resource>
"""

from collections.abc import Callable
from typing import Annotated

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations
from pydantic import Field

from .._json import dump_json_capped
from ..api_client import CompassOneClient, CompassOneError
from ._common import NO_CREDS, TENANT_ID_DESC


def register(mcp: FastMCP, client_factory: Callable[[], CompassOneClient | None]) -> None:
    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
    async def compassone_get_security_posture_rating(
        tenant_id: Annotated[str, Field(description=TENANT_ID_DESC)],
        include_non_deductions: Annotated[
            bool | None,
            Field(
                description=(
                    "Include metric rows that produced no deduction. Off by "
                    "default on the vendor side."
                )
            ),
        ] = None,
    ) -> str:
        """Get the tenant's security posture rating and metric breakdown.

        Returns score, maximumScore, maturityLevel and every
        metricCalculationResults row verbatim. Two fields matter when
        summarising: maximumScore varies by CompassOne edition (50 and 120 both
        observed), so never hard-code a denominator; and a row with
        metricApplied false carries a deduction value but deducts nothing, so
        reporting it overstates the client's loss.
        """
        client = client_factory()
        if client is None:
            return NO_CREDS
        try:
            result = await client.get_scoped(
                "/v1/security-posture/rating",
                tenant_id,
                params={"includeNonDeductions": include_non_deductions},
            )
        except CompassOneError as e:
            return e.to_envelope()
        return dump_json_capped(result)
