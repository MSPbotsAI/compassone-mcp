"""Token-economical JSON serialization for tool return values.

Compact (no indent), non-ASCII-preserving, and size-capped so a single
tool call can never blow past the ~20,000-char budget an agent's context
can reasonably absorb.
"""

import json
from typing import Any

MAX_CHARS = 20_000


def _compact(data: Any) -> str:
    return json.dumps(data, separators=(",", ":"), ensure_ascii=False)


def fits(data: Any, max_chars: int = MAX_CHARS) -> bool:
    """Pure/sync check: would data serialize within max_chars as-is."""
    return len(_compact(data)) <= max_chars


def fit_count(data: dict, list_key: str, max_chars: int = MAX_CHARS) -> int:
    """Binary-search the largest prefix of data[list_key] whose serialized
    form (with the standard truncation envelope fields added) still fits
    max_chars. Pure/sync, no network IO — exposed so a caller (e.g. a tool
    function re-requesting a smaller page from CompassOne) can learn the safe
    row count *before* deciding whether to truncate locally or re-fetch at
    that size. Re-fetching is preferred: CompassOne echoes pagination state
    back in `meta`, and a locally-sliced list paired with the original
    `meta.pageSize` would misreport how many rows the page actually holds.
    """
    items = data[list_key]
    lo, hi = 0, len(items)
    while lo < hi:
        mid = (lo + hi + 1) // 2
        candidate = dict(data)
        candidate[list_key] = items[:mid]
        candidate["truncated"] = True
        candidate["truncated_field"] = list_key
        candidate["original_count"] = len(items)
        if len(_compact(candidate)) <= max_chars:
            lo = mid
        else:
            hi = mid - 1
    return lo


def dump_json_capped(data: Any, max_chars: int = MAX_CHARS) -> str:
    """Serialize data compactly, truncating the largest list field (or the
    top-level list) if the result would exceed max_chars, rather than ever
    returning an unbounded blob.
    """
    s = _compact(data)
    if len(s) <= max_chars:
        return s

    if isinstance(data, list):
        return _truncate_list(data, max_chars, wrap_key="items")

    if isinstance(data, dict):
        list_keys = [k for k, v in data.items() if isinstance(v, list)]
        if list_keys:
            key = max(list_keys, key=lambda k: len(_compact(data[k])))
            items = data[key]
            lo = fit_count(data, key, max_chars)
            candidate = dict(data)
            candidate[key] = items[:lo]
            candidate["truncated"] = True
            candidate["truncated_field"] = key
            candidate["original_count"] = len(items)
            return _compact(candidate)

    # Not list-shaped and still too big — return a short notice instead of
    # a giant unbounded string.
    return _compact(
        {
            "truncated": True,
            "note": (
                f"Result too large ({len(s)} chars) to return in full and "
                "not list-shaped; narrow your query."
            ),
        }
    )


def _truncate_list(items: list, max_chars: int, wrap_key: str) -> str:
    lo, hi = 0, len(items)
    while lo < hi:
        mid = (lo + hi + 1) // 2
        candidate = {wrap_key: items[:mid], "truncated": True, "original_count": len(items)}
        if len(_compact(candidate)) <= max_chars:
            lo = mid
        else:
            hi = mid - 1
    return _compact({wrap_key: items[:lo], "truncated": True, "original_count": len(items)})


def error_envelope(code: str, message: str, retryable: bool) -> str:
    return _compact({"error": {"code": code, "message": message, "retryable": retryable}})
