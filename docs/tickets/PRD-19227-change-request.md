# CompassOne MCP — change request: fourteen tools, and one header that decides everything

**Repo:** the CompassOne MCP. The name is not recorded here — the only CompassOne tools present in
our environment are `blackpoint_navigate` and `blackpoint_status`, which are a menu rather than
data, so this may be a new server rather than a change to an existing one.

**Requested by:** the monthly client report work (Security Overview page)
**Vendor API:** `CompassOne API` 1.7.0, `https://api.blackpointcyber.com`, `bearerAuth`
**Reference:** `https://docs.blackpointcyber.com` (Redocly portal, SSO behind `login.bpsnap.com`).
The OpenAPI document is downloadable from there; the `/guides/*` pages carry material the
specification does not, and two of them are quoted below.

**Size:** fourteen tools, one per endpoint. No aggregation, no derivation, no normalising — every
tool passes parameters through and returns the vendor's response unmodified.

---

## 1. `x-tenant-id` is the whole isolation story — read this first

Every data call is scoped by an **`x-tenant-id` header** carrying the client tenant's UUID. The
credential is the MSP's partner credential, so without that header a call is not "wider" — it is
wrong about whose data it returns.

The OpenAPI document **declares no header parameters at all**. The mechanism appears once, in a
deprecation note on `/v1/alert-groups`' `tenantId` query parameter: *"deprecated: use `x-tenant-id`
header instead"*. The guides state it plainly — the Assets guide: *"Assets are tenant-scoped —
omitting this header returns a `400: x-tenant-id header required` error"*; the Reports guide gives
it a required row in its header table.

**Measured against the live API, 2026-09-18, read-only credential, `/v1/alert-groups`:**

| Call | Result |
|---|---|
| with `x-tenant-id: <a client tenant>` | rows returned, and **every row's `customerId` equals the header** |
| without it | **error stating the header is required**; no data |

So the failure is loud, which is the good case. What this request needs from the implementation:

- **Every tool takes a required `tenant_id` parameter and sends it as `x-tenant-id`.** Not optional
  with a default, not inherited from configuration, not remembered between calls.
- **Never fall back to calling without it.** If a caller omits it the tool refuses; it does not
  retry unscoped and return whatever comes back.
- `403 Forbidden` means the credential has no access to that tenant. Surface it as itself — do not
  convert it into an empty result.

Why this is worth a section: on the Cisco Umbrella MCP the same gap produced a well-formed empty
answer that reads exactly like a quiet month. Here the vendor fails loudly, and the only way to
lose that property is for the MCP to paper over it.

---

## 2. The tools

### 2.1 List tenants — resolves the client

```
GET /v1/tenants

query:    search      matches BOTH id and name (per the vendor's own description)
          accountId   restrict to one account
          page, pageSize, sortBy, sortOrder
returns:  data[] of { id, name, description, accountId, type, industryType,
                      snapAgentUrl, enableDeliveryEmail, contactGroupId, domain, ... }
          meta
```

This is the only call that does not take `x-tenant-id` — it is what produces the tenant id.

`type` is `MDR | MDR ONBOARD | POC | SELF | UNSET`. Pass it through; the consumer uses it to refuse
a run pointed at the MSP's own tenant.

### 2.2 Security posture rating

```
GET /v1/security-posture/rating

header:   x-tenant-id
query:    includeNonDeductions   boolean
returns:  { id, customerId, score, maximumScore, status, maturityLevel,
            metricCalculationSetId, created,
            metricCalculationResults[] }
```

`metricCalculationResults[]` rows carry `description`, `deduction`, `possibleDeduction`,
`recommendation`, `metricApplied`, `metricPassed`, `rawValue`, `nistFunction`,
`operationalCategory`, plus four `recommendation*` navigation fields.

**Return every field.** The consumer selects; the MCP does not. In particular do not drop
`metricApplied` — a row the vendor did not apply carries a deduction value and deducts nothing, and
a consumer that cannot see the flag will overstate what the client is losing.

Measured: `maximumScore` is **50** for one client tenant and **120** for the MSP's own. It varies by
CompassOne edition and must never be hard-coded.

### 2.3 List reports

```
GET /v1/reports

header:   x-tenant-id   (required — 400 without it)
query:    reportType    Cloud | Executive | MDR
          startDate     filters on intervalStart >=   (ISO 8601, inclusive)
          endDate       filters on intervalStart <=   (ISO 8601, inclusive)
          page, pageSize (default 100, max 1000), sortBy (intervalStart only), sortOrder
returns:  data[] of { id, reportType, intervalStart, intervalEnd, created, updated }
          meta { currentPage, pageSize, totalItems, totalPages }
```

`intervalStart` / `intervalEnd` must reach the consumer untouched — it asserts them against the
reporting month and refuses a run that declares a different window.

### 2.4 Get report JSON

```
GET /v1/reports/{id}/json

header:   x-tenant-id   (required)
path:     id            the report run id from 2.3
returns:  { data: { reportType, report } }
```

**`report` is polymorphic and must be returned verbatim.** Its shape depends on `reportType`, the
OpenAPI document marks it `additionalProperties: true`, and the guide documents the top-level keys:

| reportType | top-level keys in `report` |
|---|---|
| Executive | `tenant` `period` `securityAnalysis` `securityPosture` `securityInsights` `featureProgress` `incidents` `protectedDevices` `protectedUsers` |
| MDR | `tenant` `period` `services` `securityAnalysis` `threatTrends` `privilegedRemoteActivity` `cloudResponse` `managedEdrActivity` `socActivity` `siem` |
| Cloud | `tenant` `period` `securityAnalysis` `threatTrends` `eventTypes` |

Do not flatten it, do not rename keys, do not pick a subset, and do not normalise the two Executive
variants into one — the vendor ships a legacy Executive payload keyed `executiveSummary` alongside
the current one keyed `securityPosture`, and the consumer branches on which is present.


### 2.5 Detections (alert groups) — seven endpoints

The vendor's own guide calls these **detections**: *"Detections, also known as alert groups, are
foundational entities... Each detection aggregates multiple related alerts into a single entity."*

```
GET /v1/alert-groups
    query:  take, skip, status, type, search, tunnelSearch,
            sortByColumn, sortDirection, since, minAlertsCount, maxAlertsCount
    NOTE:   a `tenantId` query parameter also exists and is DEPRECATED — send the header instead

GET /v1/alert-groups/{alertGroupId}
GET /v1/alert-groups/{alertGroupId}/alerts
    query:  take, skip, sortByColumn, sortDirection

GET /v1/alert-groups/count
    query:  startDate, endDate, type, status

GET /v1/alert-groups/alert-groups-by-week
    query:  startDate, endDate, type

GET /v1/alert-groups/top-detections-by-entity
    query:  startDate, endDate, detectionType, entityName, limit

GET /v1/alert-groups/top-detections-by-threat
    query:  startDate, endDate, detectionType, limit
```

Three things the OpenAPI document does not say, and the guide does:

- **`type` is `CR | MDR`.** CR is Cloud Response (M365, Google Workspace, Cisco Duo); MDR covers the
  endpoint products (SentinelOne, CrowdStrike, Windows Defender, Bitdefender, Sophos and others).
  The specification leaves this enum empty.
- **`status` is `OPEN | RESOLVED`** at the group level. The nine-state lifecycle
  (`NEW / CLAIM / INVESTIGATE / ESCALATE / RESOLVE / CLOSE / INFORMATIONAL / NO_AGENT /
  SUGGEST_SUPPRESSION`) belongs to the ticket nested in each group, not to the group.
- **`since` is capped at 90 days** and future dates are rejected. `startDate`/`endDate` on the
  analytics endpoints default to the last 90 days when omitted.

`search` requires at least three characters and matches `alertTypes`, `action`, `dataset`,
`username` and `hostname`.

### 2.6 Assets — three endpoints

```
GET /v1/assets
    query:  class (REQUIRED), search, filter, page, pageSize, withDeleted,
            sources, platform, type, foundOn, lastSeenOn, decommissioned,
            decommissionDate, wdStatus, sortBy, sortOrder

GET /v1/assets/{id}

GET /v1/assets/{id}/relationships
    query:  class (REQUIRED), direction (REQUIRED: in | out),
            page, pageSize, withDeleted, sortBy, sortOrder
```

- **`class` is required on both list and relationships.** On `/v1/assets` the classes live today are
  `DEVICE`, `USER`, `SOFTWARE`, `SOURCE`, `SURVEY`; the guide lists `SERVICE`, `PROCESS`,
  `CONTAINER`, `PERSON`, `FRAMEWORK`, `NETSTAT` as future. On `/relationships` the enum is wider and
  includes the finding classes `ALERT`, `ALERTGROUP`, `EVENT`, `INCIDENT`, `VULNERABILITY`.
- **The response schema varies by class** — a `DEVICE` row carries agent, OS, hardware and network
  fields that a `USER` row does not. Return whatever the vendor sends for the class requested.
- **`filter` takes a `WITH` clause and must be URL-encoded**, e.g.
  `filter=WITH platform='WINDOWS'` or `filter=THAT HAS SOURCE WITH type='AGENTENDPOINT'`. Pass the
  string through; do not parse or rewrite it.

---

## 3. Done when

- Fourteen tools callable, each taking a required tenant id and sending it as `x-tenant-id`
  — except `GET /v1/tenants`, which is what produces one.
- A call with no tenant id is refused by the tool, not retried unscoped.
- `report` is returned verbatim, including the legacy Executive shape.
