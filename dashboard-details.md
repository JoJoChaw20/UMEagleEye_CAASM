# UMEagleEye 2.0 — Dashboard & Alerts Reference

This document covers every section on the **Security Posture Dashboard** and the **Alerts Dashboard**: where each number comes from, how it is calculated, and how thresholds and colours are determined.

---

## Security Posture Dashboard (`/dashboard`)

### API calls made on load

| Call | Endpoint | Purpose |
|---|---|---|
| 1 | `GET /posture/current` | Posture score + asset counts |
| 2 | `GET /posture/history?limit=30` | 30-day daily score history |
| 3 | `GET /events?page_size=10` | 10 most recent events (table) |
| 4 | `GET /events/stats/summary` | Full-history severity counts (pie chart) |

All four calls include `tenant_id` when a tenant filter is active.

---

### Stat Card 1 — Posture Score

**Source:** `GET /posture/current` → `overall_score`

**Formula (workers/src/routes/posture.ts):**

```
Start = 100

Step 1 — Critical event deduction
  deduction = min(critical_event_count × 5, 40)
  (max deduction: 8 critical events → −40)

Step 2 — High event deduction
  deduction = min(high_event_count × 2, 20)
  (max deduction: 10 high events → −20)

Step 3 — Critical asset concentration penalty
  if (assets_with_criticality ≥ 8) / total_assets > 0.20:
    deduction = −10

Final = max(0, min(100, 100 − all deductions))
```

**What counts as an "event":** Any row in the `events` table for this tenant's assets. Events are never auto-cleared — they accumulate until explicitly acknowledged or deleted. Medium and low severity events have **zero** effect on the score.

**Colour thresholds:**

| Score | Colour |
|---|---|
| ≥ 80 | Green (`#00e676`) |
| ≥ 50 | Amber (`#ffc400`) |
| < 50 | Red (`#ff5252`) |

---

### Stat Card 2 — Total Assets

**Source:** `GET /posture/current` → `total_assets`

**Calculation:** `COUNT(*)` from the `assets` table scoped to the tenant. Includes every device in your inventory regardless of how it was added (manual entry, CSV import, active scan, passive scan). A device appears here only after it is accepted into the inventory — scan results that have not been accepted are not counted.

---

### Stat Card 3 — Critical Alerts

**Source:** `GET /posture/current` → `open_critical_events`

**Calculation:**
```sql
SELECT COUNT(*) FROM events
WHERE severity = 'critical'
AND asset_id IN (tenant asset IDs)
```

**Important:** Only **critical** severity events are counted here. High, medium, and low are excluded. The name "Critical Alerts" reflects exactly what the number means — it is not a count of all open alerts.

---

### Stat Card 4 — Critical Assets

**Source:** `GET /posture/current` → `total_critical_assets`

**Calculation:** Count of assets where `criticality_score >= 8`.

**How criticality_score is assigned (workers/src/lib/criticality.ts):**

```
Base score by device type:
  network      = 6
  server       = 5
  iot          = 4
  workstation  = 3
  unknown      = 3

Additions:
  +2  internet-facing (is_internet_facing = true)
  +1  high-risk port open: FTP(21), Telnet(23), SMB(445), MSSQL(1433),
        RDP(3389), Metasploit(4444), VNC(5900)  — max +2 (first 2 found)
  +1  database port open: Oracle(1521), MySQL(3306), Postgres(5432),
        CouchDB(5984), Redis(6379), Elasticsearch(9200), MongoDB(27017)
  +1  10 or more open ports (wide attack surface)
  +1  hostname contains: prod, production, live, critical
  +1  hostname contains: db, sql, database, mysql, postgres, oracle, redis, mongo
  +1  hostname contains: gw, gateway, fw, firewall, core, border, dmz, proxy
  −1  hostname contains: dev, develop, test, staging, lab, sandbox, qa
  +3  topology layer 1 (internet-facing gateway)
  +2  topology layer 2 (core network node)
  +1  topology layer 3 (distribution node)
  +1  no owner assigned (unowned asset penalty)

Score = max(1, min(10, sum of all above))
```

A score of **8, 9, or 10** is flagged as "critical asset". The `criticality_score >= 8` threshold used in the posture score step 3 and this card are the same value.

---

### Chart 1 — Posture Score Trend (30-day area chart)

**Source:** `GET /posture/history?limit=30` → `items[]`

**What it shows:** The posture score as it would have been calculated at the end of each of the last 30 days.

**How it is calculated (per day):** The same formula as the current posture score is re-applied using only data that existed up to 23:59:59 of that day:

```
For each day D in the last 30 days:
  total_assets[D]          = assets with createdAt ≤ end_of_D
  critical_assets[D]       = assets with criticality ≥ 8 AND createdAt ≤ end_of_D
  critical_event_count[D]  = critical severity events with timestamp ≤ end_of_D
  high_event_count[D]      = high severity events with timestamp ≤ end_of_D

  score[D] = posture formula applied to above values
```

**Note:** This is a **reconstructed** history, not stored snapshots. It is re-derived from current data on every request. The X-axis shows the date (`Mon DD`), the Y-axis is 0–100.

---

### Chart 2 — Threat Distribution (donut chart)

**Source:** `GET /events/stats/summary` → `by_severity`

**What it shows:** Count of **all security events ever recorded** for this tenant, broken down by severity. This covers the full history, not just recent events.

**Calculation:**
```sql
SELECT severity, COUNT(*) FROM events
WHERE asset_id IN (tenant asset IDs)
GROUP BY severity
```

Segments with a count of 0 are hidden. The legend below the donut shows the exact count for each severity level.

---

### Table — Recent Security Events

**Source:** `GET /events?page_size=10`

**What it shows:** The 10 most recent events ordered by `timestamp DESC`.

| Column | Field | Notes |
|---|---|---|
| Type | `event_type` | Raw enum value displayed as-is |
| Severity | `severity` | Coloured badge |
| Asset | `asset_id` | First 8 characters of the UUID |
| Risk Score | `composite_risk_score` | Only populated for CVE events; `—` for drift/CTI events |
| Time | `timestamp` | Local date and time |

---

---

## Alerts Dashboard (`/alerts`)

### API calls made on load

| Call | Endpoint | Purpose |
|---|---|---|
| 1 | `GET /events?page=N&page_size=15` | Paginated event list (table) |
| 2 | `GET /events/stats/summary` | All summary stats + chart data |

Both calls support `severity`, `event_type`, and `tenant_id` filter parameters. The stats summary always covers the full unfiltered tenant scope; only the table respects the active severity/type filters.

---

### Stat Card 1 — Total Alerts

**Source:** `GET /events/stats/summary` → `total_alerts`

**Calculation:**
```sql
SELECT COUNT(*) FROM events
WHERE asset_id IN (tenant asset IDs)
```

Counts every event ever recorded for this tenant: CVE detections, drift events, CTI matches, all types and all severities. Never decreases unless events are deleted (e.g. via the acknowledge action).

---

### Stat Card 2 — Critical

**Source:** `GET /events/stats/summary` → `by_severity.critical`

**Calculation:**
```sql
SELECT COUNT(*) FROM events
WHERE severity = 'critical'
AND asset_id IN (tenant asset IDs)
```

All critical-severity events ever, regardless of type. Includes CVE detections with CVSS ≥ 9, exposure changes (`config_change` with `is_internet_facing` set to true), and CTI matches classified as critical. This is a total-ever count, not an "open/unresolved" count.

---

### Stat Card 3 — Resolution Rate

**Source:** `GET /events/stats/summary` → `resolution_rate`

**Calculation:**
```
total_advisories    = COUNT(*) from advisories where event_id IN (tenant event IDs)
resolved_advisories = COUNT(*) from advisories where status = 'resolved'

resolution_rate = ROUND(resolved_advisories / total_advisories × 100)
                  Default: 100% if no advisories exist
```

**What this measures:** Advisory resolution, not event resolution. An advisory is created by clicking the ⚡ button on an event. It starts as `open` and must be manually moved to `resolved` from the Advisories page. Events that were never given an advisory are not counted at all. A `resolved` advisory means the remediation has been completed for that specific event.

Advisory status lifecycle: `open → acknowledged → in_progress → resolved`

---

### Stat Card 4 — Avg Risk Score

**Source:** `GET /events/stats/summary` → `avg_risk_score`

**Calculation:**
```sql
SELECT ROUND(AVG(composite_risk_score), 1)
FROM events
WHERE composite_risk_score IS NOT NULL
AND asset_id IN (tenant asset IDs)
```

**Important:** Only **CVE (`cve_detected`) events** have a `composite_risk_score`. Drift events and CTI match events have `NULL` for this field and are excluded from the average. The subtitle reads "CVE events only (EPSS-weighted)" to reflect this.

---

### Chart 1 — Severity Breakdown (donut chart)

**Source:** `GET /events/stats/summary` → `by_severity`

Same data as the Dashboard's Threat Distribution donut. Groups all tenant events by severity across full history. Only segments with count > 0 are rendered.

---

### Chart 2 — Alerts Over Time (7-day area chart)

**Source:** `GET /events/stats/summary` → `daily_trend`

**Calculation:**
```sql
SELECT DATE_TRUNC('day', timestamp) AS day, COUNT(*) AS count
FROM events
WHERE timestamp >= NOW() - INTERVAL '7 days'
AND asset_id IN (tenant asset IDs)
GROUP BY day
ORDER BY day
```

Days with no events are filled with `count = 0` so the chart always shows exactly 7 data points. X-axis format: `MM-DD`. Y-axis: event count per day. Covers all event types and all severities combined.

---

### Chart 3 — Alert Types (horizontal bar chart)

**Source:** `GET /events/stats/summary` → `by_type`

**Calculation:**
```sql
SELECT event_type, COUNT(*) FROM events
WHERE asset_id IN (tenant asset IDs)
GROUP BY event_type
```

Each distinct event type in the tenant's history gets a bar. The raw enum values are mapped to human-readable labels:

| Internal enum | Displayed label |
|---|---|
| `cve_detected` | CVE Detected |
| `cti_match` | Threat Intel Match |
| `port_opened` | Port Opened |
| `port_closed` | Port Closed |
| `version_downgrade` | Version Downgrade |
| `version_upgrade` | Version Upgrade |
| `config_change` | Config Change |
| `new_package` | New Package |
| `removed_package` | Removed Package |
| `new_device` | New Device |

---

### Alerts Table — Column Reference

**Source:** `GET /events?page=N&page_size=15` (with optional `severity` and `event_type` filters). Results are ordered by `timestamp DESC`. 15 rows per page with previous/next pagination.

#### Severity

Set at event creation time. Cannot be changed after the fact. Colour-coded badge:

| Severity | Badge colour | Meaning |
|---|---|---|
| `critical` | Red | CVSS ≥ 9.0, or internet-exposure change, or CTI-confirmed malware |
| `high` | Orange | CVSS ≥ 7.0, or port < 1024 opened, or MAC address changed |
| `medium` | Yellow | CVSS ≥ 4.0, new device, hostname change, new package |
| `low` | Green | CVSS < 4.0, port closed, version upgrade, package removed |

For CVE events specifically, severity is derived from CVSS score (CVSS → severity mapping):

| CVSS | Severity |
|---|---|
| ≥ 9.0 | critical |
| ≥ 7.0 | high |
| ≥ 4.0 | medium |
| 0 (no score) | falls back to Grype's own label |
| otherwise | low |

#### Type

The `event_type` enum. `config_change` events are sub-labelled by `details.changed_attribute`:

| `changed_attribute` | Displayed type label |
|---|---|
| `availability` | Asset Offline |
| `internet_facing` | Exposure Changed |
| `os_version` | OS Version Changed |
| `hostname` | Hostname Changed |
| `mac_address` | MAC Address Changed |
| `device_type` | Device Type Changed |
| `package_version` | Package Updated |

#### Detail

Human-readable summary derived from the event's `details` JSON field:

| Event type | What is displayed |
|---|---|
| `cve_detected` | CVE ID as a clickable NVD link (opens `nvd.nist.gov/vuln/detail/<CVE-ID>`) |
| `cti_match` | The matched indicator value (IP, domain, hash, etc.) |
| `port_opened` / `port_closed` | `Port 443/tcp` |
| `version_downgrade` / `version_upgrade` | `nginx: 1.18.0 → 1.24.0` |
| `config_change` (internet_facing) | `Internal → Internet-facing` or `Internet-facing → Internal` |
| `config_change` (other) | `<old_value> → <new_value>` |
| `new_package` | `+package_name version` |
| `removed_package` | `−package_name` |
| `new_device` | `New: 192.168.1.50 (aa:bb:cc:dd:ee:ff)` |

#### Asset

Joined from the `assets` table via a `LEFT JOIN`. Display priority:

1. `hostname` (if set) — shown as plain text
2. `ip_address` (if no hostname) — shown in monospace cyan
3. First 8 chars of `asset_id` UUID (if neither) — shown dimmed

When both hostname and IP are present, IP is shown as a smaller line below the hostname. For package-related events, the package name and version appear below the asset identifier.

#### CVSS

`details.cvss_base_score` from NVD via Grype. Only present on `cve_detected` events. Colour-coded inline:

| CVSS | Colour |
|---|---|
| ≥ 9 | Red |
| ≥ 7 | Orange |
| ≥ 4 | Amber |
| < 4 | Green |
| absent | `—` |

#### EPSS

`details.epss_score` fetched at SBOM scan time from FIRST.org API. Displayed as a percentage (e.g. `3.2%`). Meaning: probability that this specific CVE will be exploited in the wild within the next 30 days. Only present on `cve_detected` events.

#### Risk Score

`composite_risk_score` — calculated when the SBOM CVE ingest runs (workers/src/routes/sbom.ts). Formula:

```
Risk Score = (CVSS × 10 × 0.40)
           + (EPSS × 100 × 0.35)
           + (Asset Criticality × 10 × 0.15)
           + (CTI match ? 10 : 0)

Capped at 100.
```

| Component | Source | Weight | Rationale |
|---|---|---|---|
| CVSS base score (0–10) | NVD via Grype | 40% | Technical exploitability |
| EPSS probability (0–1) | FIRST.org batch API (live at scan time) | 35% | Real-world exploit likelihood |
| Asset criticality (1–10) | Computed by criticality engine | 15% | Business impact if exploited |
| CTI match (boolean) | CVE ID found in `cti_indicators` table | flat +10 | Active threat-intel confirmation |

Colour thresholds in the table:

| Risk Score | Colour |
|---|---|
| ≥ 50 | Red |
| ≥ 25 | Amber |
| < 25 | Green |
| absent (non-CVE events) | `—` |

#### Actions

**⚡ (Generate Advisory)** — Queues AI advisory generation for this event via `POST /events/{eventId}/advisory`. The request is sent to the `advisory-queue`; the advisory appears on the Advisories page within seconds.

- Button is **blue** (`text-eagle-400`) when no advisory exists for this event yet.
- Button is **green** (`text-accent-green`) with a small green dot badge when an advisory already exists (`has_advisory = true`). Tooltip changes to "Advisory exists — regenerate?" to prevent accidental duplicates.
- Not shown for `superadmin` role (platform-level admins do not manage tenant-specific advisories).

**✓ (Acknowledge)** — Only shown for drift-type events (`port_opened`, `port_closed`, `version_downgrade`, `version_upgrade`, `config_change`, `new_package`, `removed_package`, `new_device`).

Clicking it:
1. Re-baselines the asset: captures its current state (ports, OS info, hostname, MAC, exposure, device type) as the new `baseline_state` in the `assets` table.
2. Deletes the acknowledged event from the `events` table.
3. The event disappears from the Alerts page and the posture score updates on next load.

Meaning: "This change is intentional. Accept it as the new normal." Future drift audits will compare against the updated baseline, so this specific change will not re-trigger.

Not shown for `superadmin` or `business_owner` roles.

---

## Shared Notes

### How events are created

| Event type | Created by |
|---|---|
| `cve_detected` | SBOM CVE ingest (`POST /sboms/ingest-cve`) — triggered after every Grype scan |
| `cti_match` | CTI route when an asset's IP/hostname matches a known indicator |
| `port_opened`, `port_closed`, `version_*`, `config_change`, `new_package`, `removed_package`, `new_device` | Drift audit (cron every 15 min, or on-demand "Run Drift Audit" button) |

### 24-hour drift deduplication

Identical drift events within a 24-hour window are suppressed. If port 22 opened on `192.168.1.10` is detected at 09:00, the 09:15 cron run will not create a second `port_opened` event for the same port on the same asset. This prevents alert flooding from repeated baseline comparisons.

### Tenant scoping

All queries use an intermediate step: resolve `asset_id` list for the tenant, then filter events by that list. `superadmin` can optionally pass a `tenant_id` query parameter to scope to a specific tenant; without it, superadmin sees all tenants combined. All other roles are always scoped to their own tenant.
