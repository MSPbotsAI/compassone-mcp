"""Shared helpers and parameter prose for the CompassOne tool modules."""

import json
from collections.abc import Awaitable, Callable
from typing import Literal

from .._json import MAX_CHARS, dump_json_capped, fit_count, fits
from .._json import error_envelope as error_envelope

NO_CREDS = error_envelope(
    "not_configured",
    "No CompassOne credentials configured. Send the X-Blackpoint-API-Token header.",
    False,
)

# ── The tenant contract ─────────────────────────────────────────────────────
#
# Every tool but compassone_list_tenants takes this parameter, and it is
# REQUIRED — deliberately not optional-with-a-default. The credential is the
# MSP's partner token, so a call with no tenant is not a broader query; it is
# a query whose answer belongs to nobody in particular. Cisco Umbrella's MCP
# had the same gap and answered 200 with an empty array, which downstream is
# indistinguishable from "this customer had a quiet month". These findings get
# stated to end clients, so a loud failure beats a quiet empty.
#
# If this description and api_client.get_scoped ever disagree, the code wins
# and this text is the bug: descriptions ship to the model, so a stale one
# actively misinforms the caller.
TENANT_ID_DESC = (
    "Required. The customer tenant's UUID, sent as the x-tenant-id header. "
    "Resolve it with compassone_list_tenants — never guess one, and never "
    "carry one over from an unrelated request. Omitting it is not a wider "
    "query: the call is refused rather than retried unscoped. A tenant this "
    "credential cannot reach returns an `unauthorized` error, never an empty "
    "result."
)

# Detections are typed by which product family raised them. The vendor's
# OpenAPI document leaves this enum empty on some endpoints; the values come
# from the vendor's Detections guide.
DetectionType = Literal["CR", "MDR"]
DETECTION_TYPE_DESC = (
    "Detection family: CR (Cloud Response — M365, Google Workspace, Cisco Duo) "
    "or MDR (endpoint products — SentinelOne, CrowdStrike, Windows Defender, "
    "Bitdefender, Sophos and others)."
)

# Group-level status only. The nine-state lifecycle (NEW/CLAIM/INVESTIGATE/
# ESCALATE/RESOLVE/CLOSE/INFORMATIONAL/NO_AGENT/SUGGEST_SUPPRESSION) belongs to
# the ticket nested inside each detection, not to the detection itself.
AlertStatus = Literal["OPEN", "RESOLVED"]

SortDirection = Literal["ASC", "DESC"]

AssetClass = Literal[
    "CONTAINER",
    "DEVICE",
    "FRAMEWORK",
    "NETSTAT",
    "PERSON",
    "PROCESS",
    "SERVICE",
    "SOFTWARE",
    "SOURCE",
    "SURVEY",
    "USER",
]

# /v1/assets/{id}/relationships accepts everything /v1/assets does plus the
# finding classes, which are only ever reachable as the far end of a
# relationship.
RelationshipClass = Literal[
    "CONTAINER",
    "DEVICE",
    "FRAMEWORK",
    "NETSTAT",
    "PERSON",
    "PROCESS",
    "SERVICE",
    "SOFTWARE",
    "SOURCE",
    "SURVEY",
    "USER",
    "ALERT",
    "ALERTGROUP",
    "EVENT",
    "INCIDENT",
    "VULNERABILITY",
]

DATE_DESC = "ISO 8601 date-time, e.g. 2026-09-01T00:00:00Z."


async def fetch_capped(
    fetch: Callable[[int], Awaitable[object]],
    page_size: int,
    max_chars: int = MAX_CHARS,
) -> str:
    """Run a paged fetch and serialize it within the size budget.

    `fetch(page_size)` performs the actual GET at that page size. If the
    response would overflow, re-fetch once at the largest page size known to
    fit rather than slicing locally: CompassOne echoes pagination state back in
    `meta`/`pagination`, and a locally-sliced list paired with the original
    page size would misreport how many rows the page actually holds.

    Truncation, when it still happens, is explicit — dump_json_capped adds
    `truncated` / `truncated_field` / `original_count`. Fields are never
    dropped from individual rows.
    """
    result = await fetch(page_size)
    if isinstance(result, dict) and not fits(result, max_chars):
        list_keys = [k for k, v in result.items() if isinstance(v, list)]
        if list_keys:
            key = max(list_keys, key=lambda k: len(json.dumps(result[k], default=str)))
            k = fit_count(result, key, max_chars)
            if 0 < k < page_size:
                result = await fetch(k)
    return dump_json_capped(result, max_chars)
