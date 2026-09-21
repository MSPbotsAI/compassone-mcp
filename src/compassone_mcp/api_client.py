import asyncio
from typing import Any

import httpx

from ._json import error_envelope

_TIMEOUT = httpx.Timeout(connect=5.0, read=30.0, write=10.0, pool=5.0)
_RETRYABLE_STATUS = {429, 500, 502, 503, 504}
_MAX_RETRIES = 3
_MAX_BACKOFF_SECONDS = 20.0

TENANT_HEADER = "x-tenant-id"

# One shared connection pool for the process lifetime. No credentials are
# ever stored on it — the API token is passed per-request via headers built
# by each CompassOneClient instance, so this is safe to share across
# tenants/requests (see server.py's contextvar-based credential isolation,
# which is what actually keeps tenants apart).
_http_client: httpx.AsyncClient | None = None


def _get_http_client() -> httpx.AsyncClient:
    global _http_client
    if _http_client is None:
        _http_client = httpx.AsyncClient(timeout=_TIMEOUT, follow_redirects=True)
    return _http_client


# status_code -> (error code, retryable). status_code 0 means a network/
# connection-level failure (no response at all).
_STATUS_TO_CODE: dict[int, tuple[str, bool]] = {
    0: ("upstream_error", True),
    400: ("invalid_argument", False),
    401: ("unauthorized", False),
    403: ("unauthorized", False),
    404: ("not_found", False),
    422: ("invalid_argument", False),
    429: ("rate_limited", True),
}


def _classify(status_code: int) -> tuple[str, bool]:
    if status_code in _STATUS_TO_CODE:
        return _STATUS_TO_CODE[status_code]
    if status_code >= 500:
        return "upstream_error", True
    return "invalid_argument", False


class CompassOneError(Exception):
    def __init__(self, status_code: int, message: str):
        self.status_code = status_code
        self.message = message
        super().__init__(f"CompassOne API error {status_code}: {message}")

    def to_envelope(self) -> str:
        code, retryable = _classify(self.status_code)
        return error_envelope(code, self.message, retryable)


class CompassOneClient:
    """Async httpx client wrapping the CompassOne API v1.

    Auth: bearer token (Authorization: Bearer <token>), where the token is the
    MSP's *partner* credential — it spans every customer tenant the partner can
    see. Tenant scoping is therefore NOT part of the credential; it is the
    per-call x-tenant-id header (see get_scoped).

    Reuses the module-level connection pool (see _get_http_client) across
    every call made through this instance, rather than opening a new
    connection per request.
    """

    def __init__(self, api_token: str, base_url: str):
        self._base_url = base_url.rstrip("/")
        self._headers = {"Authorization": f"Bearer {api_token}"}

    def _clean_params(self, params: dict | None) -> dict:
        if not params:
            return {}
        return {k: v for k, v in params.items() if v is not None}

    async def get_scoped(self, path: str, tenant_id: str, params: dict | None = None) -> Any:
        """GET a tenant-scoped resource, sending tenant_id as x-tenant-id.

        x-tenant-id is the entire isolation story for CompassOne. The credential
        is the MSP's partner token, so a call without this header is not a
        "wider" query — it is wrong about whose data it returns. Consequences
        that this method exists to enforce:

          - There is NO unscoped fallback and NO default. An empty tenant_id
            fails here, before any request reaches the vendor, rather than
            silently running at partner scope.
          - A 403 from the vendor means the credential has no access to that
            tenant. It propagates as CompassOneError -> `unauthorized`, and is
            never converted into an empty result. A well-formed empty answer
            reads exactly like a quiet month, which is the specific failure
            this design refuses to reproduce (see docs/tickets/PRD-19227-*.md,
            and the same gap previously found on the Cisco Umbrella MCP).

        The vendor's own OpenAPI document declares no header parameters at all;
        the mechanism is documented only in the guides and in the deprecation
        note on /v1/alert-groups' tenantId query parameter. Verified against the
        live API on 2026-09-18: with the header, every returned row's customerId
        equals it; without it, the call fails loudly with
        "400: x-tenant-id header required".
        """
        if not tenant_id or not tenant_id.strip():
            raise CompassOneError(
                400,
                "tenant_id is required and must be non-empty — resolve one via "
                "compassone_list_tenants. This tool will not retry unscoped.",
            )
        return await self._request(
            "GET",
            path,
            params=self._clean_params(params),
            extra_headers={TENANT_HEADER: tenant_id.strip()},
        )

    async def get_unscoped(self, path: str, params: dict | None = None) -> Any:
        """GET a partner-level resource, with no x-tenant-id header.

        Only legitimate for GET /v1/tenants, which is the call that *produces*
        a tenant id. Every other endpoint must go through get_scoped.
        """
        return await self._request("GET", path, params=self._clean_params(params))

    async def _request(
        self,
        method: str,
        path: str,
        params: dict | None = None,
        extra_headers: dict[str, str] | None = None,
    ) -> Any:
        client = _get_http_client()
        url = f"{self._base_url}{path}"
        headers = {**self._headers, **(extra_headers or {})}

        last_exc: Exception | None = None
        for attempt in range(_MAX_RETRIES + 1):
            try:
                resp = await client.request(method, url, headers=headers, params=params)
            except httpx.RequestError as e:
                last_exc = e
                if attempt < _MAX_RETRIES:
                    await asyncio.sleep(min(2**attempt, _MAX_BACKOFF_SECONDS))
                    continue
                raise CompassOneError(0, f"{e or type(e).__name__} (url={url})") from e

            if resp.status_code in _RETRYABLE_STATUS and attempt < _MAX_RETRIES:
                delay = self._retry_delay(resp, attempt)
                await asyncio.sleep(delay)
                continue

            self._raise_for_status(resp)
            return self._parse_body(resp)

        # Unreachable in practice (loop always returns or raises above), but
        # keeps type checkers happy and guards against future edits.
        if last_exc:
            raise CompassOneError(0, f"{last_exc}") from last_exc
        raise CompassOneError(0, "request failed with no response")

    def _retry_delay(self, resp: httpx.Response, attempt: int) -> float:
        retry_after = resp.headers.get("Retry-After")
        if retry_after:
            try:
                return min(float(retry_after), _MAX_BACKOFF_SECONDS)
            except ValueError:
                pass
        return min(2**attempt, _MAX_BACKOFF_SECONDS)

    def _parse_body(self, resp: httpx.Response) -> Any:
        if not resp.content:
            return None
        try:
            return resp.json()
        except ValueError:
            return {"raw_response": resp.text}

    def _raise_for_status(self, resp: httpx.Response) -> None:
        if resp.status_code >= 400:
            try:
                detail = resp.json()
                if isinstance(detail, dict):
                    msg = detail.get("message") or detail.get("error") or str(detail)
                else:
                    msg = str(detail)
            except Exception:
                msg = resp.text
            raise CompassOneError(resp.status_code, msg)
