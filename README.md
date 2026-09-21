# compassone-mcp

MCP service for **CompassOne** (Blackpoint Cyber) — an MDR security platform. It wraps the
CompassOne API v1 (`https://api.blackpointcyber.com`) as 18 read-only tools for the MSPbots Agent
platform, built for the monthly client report's Security Overview page.

Stateless HTTP MCP server: `POST /mcp` (Streamable HTTP) + `GET /health`. One container serves
every tenant; the credential arrives per request in a header and is never stored.

## Multi-tenancy: `x-tenant-id` is the whole isolation story

The credential is the **MSP's partner token** — it spans every customer tenant the partner can
see. Scoping is therefore not part of the credential; it is the `x-tenant-id` header, and it is
sent per call.

**Every tool except `compassone_list_tenants` takes a required `tenant_id` parameter**, which is
sent as `x-tenant-id`. Deliberately:

- Not optional, not defaulted, not inherited from configuration, not remembered between calls.
- **No unscoped fallback.** An empty `tenant_id` fails in `api_client.get_scoped` before any
  request leaves the process; the tool never retries without the header.
- **`403` surfaces as `unauthorized`, never as an empty result.** A well-formed empty answer reads
  exactly like a quiet month. The Cisco Umbrella MCP had the same gap and answered `200` with
  `[]`; these findings get stated to end clients, so a loud failure beats a quiet empty.

`GET /v1/tenants` is the one call that does not take the header — it is what produces a tenant id.

> The vendor's OpenAPI document declares **no header parameters at all**. The mechanism is
> documented only in the vendor guides and in the deprecation note on `/v1/alert-groups`'
> `tenantId` query parameter (*"deprecated: use `x-tenant-id` header instead"*). Measured against
> the live API on 2026-09-18 with a read-only credential: with the header, every returned row's
> `customerId` equals it; without it, the call fails with `400: x-tenant-id header required`.

## Credentials

Sent as an HTTP header on every `/mcp` request. A missing header returns `401` listing what was
required.

| Header | Required | Meaning | Where to get it |
|---|---|---|---|
| `X-Blackpoint-API-Token` | yes | CompassOne partner API token, forwarded verbatim as `Authorization: Bearer <token>`. Read-only scope is sufficient — every tool in this service is a GET. | CompassOne portal (`https://docs.blackpointcyber.com`, SSO behind `login.bpsnap.com`) → API tokens |

The header name is `X-Blackpoint-*`, not `X-CompassOne-*`, because that is the name already
declared in the platform's vendor registry for the `blackpoint` vendor. Renaming it would
invalidate every provisioned credential.

No tenant header is declared as a credential field, and that is intentional: a credential field is
fixed per authorization, which would pin one connection to one customer.

## Tools (18, all read-only)

| Tool | Endpoint | `tenant_id` |
|---|---|---|
| `compassone_list_tenants` | `GET /v1/tenants` | — |
| `compassone_get_security_posture_rating` | `GET /v1/security-posture/rating` | required |
| `compassone_list_reports` | `GET /v1/reports` | required |
| `compassone_get_report_json` | `GET /v1/reports/{id}/json` | required |
| `compassone_list_detections` | `GET /v1/alert-groups` | required |
| `compassone_get_detection` | `GET /v1/alert-groups/{id}` | required |
| `compassone_list_detection_alerts` | `GET /v1/alert-groups/{id}/alerts` | required |
| `compassone_count_detections` | `GET /v1/alert-groups/count` | required |
| `compassone_list_detections_by_week` | `GET /v1/alert-groups/alert-groups-by-week` | required |
| `compassone_top_detections_by_entity` | `GET /v1/alert-groups/top-detections-by-entity` | required |
| `compassone_top_detections_by_threat` | `GET /v1/alert-groups/top-detections-by-threat` | required |
| `compassone_list_assets` | `GET /v1/assets` | required |
| `compassone_get_asset` | `GET /v1/assets/{id}` | required |
| `compassone_list_asset_relationships` | `GET /v1/assets/{id}/relationships` | required |
| `compassone_list_vulnerabilities` | `GET /v1/vulnerability-management/vulnerabilities` | required |
| `compassone_list_vulnerability_scans` | `GET /v1/vulnerability-management/scans` | required |
| `compassone_list_darkweb_exposures` | `GET /v1/vulnerability-management/darkweb/scan/exposures` | required |
| `compassone_get_external_scan_exposures` | `GET /v1/vulnerability-management/external/scan/exposures/{id}` | required |

### Verbatim pass-through

Responses are returned as the vendor sent them. No aggregation, no derivation, no normalising; no
key is renamed, flattened, or dropped from a row. In particular `compassone_get_report_json`
returns the polymorphic `report` object as-is, including the legacy Executive payload keyed
`executiveSummary` alongside the current one keyed `securityPosture` — consumers branch on which
is present, so merging them would destroy information.

Size is bounded without dropping fields: list tools cap page size at 200 and, when a page would
overflow the 20,000-char budget, re-fetch once at a size known to fit (so the echoed pagination
state still matches the rows returned) before falling back to explicit
`truncated`/`truncated_field`/`original_count` markers.

`compassone_get_report_json` is the exception — it never truncates. A half-delivered monthly report
looks complete to a consumer that cannot see what was dropped, so an oversized report returns an
error naming the available sections; re-call with `section=<key>` to fetch one. *(Pending Toby's
confirmation, PRD-19227 — the alternative is a truncation-marked page.)*

## Known gaps

- **Tenant scoping on the four `compassone_*vulnerab*` / `*darkweb*` / `*external_scan*` tools is
  not yet verified against the live API.** The 2026-09-18 measurement covered `/v1/alert-groups`
  only, and the spec declares no headers anywhere. These tools send `x-tenant-id` like every other
  scoped tool, and `/v1/vulnerability-management/scans` does let you sort by `tenantId`, but the
  with-header / without-header comparison has not been run. Do not rely on them for client-facing
  numbers until it has.

## Development

```bash
uv sync
uv run --frozen pytest -q
uv run --frozen ruff check .
```

Local run (stdio):

```bash
AUTH_MODE=env COMPASSONE_API_TOKEN=... uv run compassone-mcp
```

Container (gateway mode is the default):

```bash
docker build --platform linux/amd64 -t compassone-mcp:local .
docker run --rm -p 8080:8080 compassone-mcp:local
curl -fsS http://localhost:8080/health          # {"status":"ok"}
```

Behind mcp-gateway the container is on `mcp-net` and publishes no host port, so verify with
`docker exec` rather than `curl` from the host:

```bash
NAME=$(docker ps --format '{{.Names}}' | grep -E '^blackpoint-mcp-(a|b)$')
docker exec $NAME curl -s http://127.0.0.1:8080/health
docker exec $NAME curl -s -X POST http://127.0.0.1:8080/mcp \
  -H 'Accept: application/json, text/event-stream' -H 'Content-Type: application/json' \
  -H 'X-Blackpoint-API-Token: dummy' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
```

## Environment variables

| Variable | Default | Meaning |
|---|---|---|
| `MCP_TRANSPORT` | `stdio` (Dockerfile sets `http`) | Transport |
| `MCP_HTTP_HOST` / `MCP_HTTP_PORT` | `0.0.0.0` / `8080` | Listen address |
| `AUTH_MODE` | `gateway` | `gateway` reads the credential header per request; `env` uses `COMPASSONE_API_TOKEN` (local dev only) |
| `COMPASSONE_API_TOKEN` | — | Only used when `AUTH_MODE=env` |
| `COMPASSONE_BASE_URL` | `https://api.blackpointcyber.com` | Vendor API base URL |

Unknown environment variables are ignored rather than fatal.

## Ticket

PRD-19227 — see [`docs/tickets/PRD-19227-change-request.md`](docs/tickets/PRD-19227-change-request.md)
for the original requirement.
