# Plan: threat sightings (the agent sees its computer contact a known-bad domain or IP)

Status: **built on staging** (17 Nov 2026), S1 to S6 as recommended; lab evaluation pending. Changes from the plan
below, found while building:
- Endpoints are `GET /sightings/indicators` and `POST /sightings` (agent auth by `X-Agent-ID`, as `routes/network.ts`),
  not under `/agents/:agentId`. Code: `workers/src/lib/sightings.ts` (pure, 11 tests), `routes/sightings.ts`.
- The list has two parts: **feeds** (paged by cursor, delta every 6 h, full every 7 days into a fresh copy that is
  swapped in) and **events** (the tenant's published events, fetched whole every 30 min, so an analyst's new event
  reaches the agents quickly). Event attributes keep their creation time, so a cursor over them would miss an event
  published later. No 90-day local expiry: the weekly full sync replaces the list.
- A **URL** indicator counts only when its host is an IPv4 address (3,435 of 17,399 feed URLs), one severity step
  lower than a listed IP. Counting URL hosts by name gave 7 false alerts in the lab (t.me, telegram.me,
  steamcommunity.com, discord.com, gitlab.com, github.com, 0xrpc.io: shared platforms malware uses as dead drops; a
  lookup never shows the path). The server sends a list-rules number (`LIST_RULES`); an agent that sees a new one
  fetches the whole list again.
- The DNS capture listens on **every adapter** (Linux unbound packet socket, Windows every NDIS interface; macOS the
  default-route adapter): in the lab, passive listening's adapter was the lab network while DNS went through NAT.
- Lab result (round 3, both VMs): 20/20 planted domains and the planted IP detected, 0 false alerts from the Tranco
  top 1,000, first contact to alert median 26–37 s. Details: `C:\FYP\AP2\eval\sightings\RESULTS.md`.
- Connections being opened (SYN sent) count too: an attempt a firewall blocks is still a contact. A connection is
  counted once, when it first appears.
- Sightings has its **own capture** (DNS answers only): its own ETW session `EagleEye-Sightings` on Windows, its own
  packet socket / BPF device with a `udp src port 53` filter elsewhere; it starts and stops apart from passive
  listening. Without Administrator/root it still checks connections.
- A contact after an alert was resolved reopens it; one from before (a late upload) does not. False positives and
  accepted risks stay closed but keep counting.
- Migration `0034_sightings_list_index` (feed entries by `(last_seen, indicator_id)`). Measured on staging: 88,567
  values, 52 pages, 823 KB gzip for a full sync, ~2 ms CPU per page (`scripts/sightings-list.ts`).
- Evaluation: `scripts/sightings-eval.ts` (plant / measure / remove) and `scripts/sightings-eval/lookups.py|.ps1`.

## Why

The threat-intel usefulness check (`workers/scripts/ti-usefulness.ts`, staging, 16 Nov) found that of ~157,000
ThreatFox and OTX indicators **none ever matched an asset**: the only rule (R5) fires when an asset's own public IP or
hostname is listed, and UMEagleEye never sees where machines connect. All real value came from CISA KEV (5 CVE
alerts). A **sighting** (MISP/OpenCTI term: an indicator observed in your own environment) turns the feed into
detection: a laptop resolving a known C2 domain becomes a high-priority alert.

## What the agent will observe

| Signal | How | Windows | Linux | macOS |
|---|---|---|---|---|
| **DNS answers** (name asked, CNAME chain, A/AAAA addresses) | built-in capture, UDP 53 added to the filter | queries and answers (NDIS sees both directions) | answers only (own sent frames are dropped) | answers only (BIOCSSEESENT 0) |
| **Outbound connections** (remote public IP:port) | poll the OS connection table every 30 s | `GetExtendedTcpTable` via ctypes (IPv4 + IPv6, with PID) | `/proc/net/tcp`, `tcp6` (ESTABLISHED) | `netstat -an -p tcp` |
| **Process** (only for a hit, so polling stays cheap) | PID → image name | `QueryFullProcessImageNameW` | `/proc/*/fd` inode search (root) | `lsof -nP -i @ip:port` |

Answers are enough on every OS: an answer repeats the question, so the name looked up and the addresses it resolved
to are both seen; an NXDOMAIN answer still names the domain.

**Blind spots (stated in the evaluation, not hidden):** DNS over HTTPS/TLS (browser secure DNS, Windows 11 DoH,
iCloud Private Relay); DNS over TCP; VPN tunnels (raw-IP `tun`/`utun`/Wintun frames); repeat lookups served from the
OS resolver cache; connections that open and close between two polls; Windows outbound UDP (its UDP table has no
remote address, so QUIC is invisible there). The connection poll covers the DoH gap for **IP** indicators.

## Privacy model

- **Matching happens on the computer.** The agent keeps a copy of the tenant's matchable bad domains and IPs and
  compares locally; **only hits leave the machine** (indicator, how seen, count, first/last time, process name).
  Lookups and connections that match nothing are never stored or sent.
- New dashboard setting **"Threat sightings", off by default** (S2), per agent kind `host` only.
- Privacy notice **version 7**: the passive-listening text ("reads only broadcast discovery messages … never reads
  the contents of anyone's traffic") and the "never collected: browsing history" line are reworded to say exactly
  this: with sightings on, the agent reads this computer's DNS answers and connection list, checks them against your
  organisation's threat list on the computer, and reports only matches.

## Indicator list sync (server → agent)

Measured on staging: **88,658 matchable values** (19,850 IPs, 68,808 domains incl. URL hosts), 1.6 MB raw, 684 KB
gzip. Too big to build in one free-plan request (~10 ms CPU), so it is **paged and incremental**:

- `GET /agents/:agentId/indicators?after=<cursor>&limit=2000` → `{ items: [{ k: 'd'|'i', v, seen }], next, done }`.
  Keyset on `(last_seen, indicator_id)`; values are the agent tenant's matchable `ip`, `domain` and URL-host rows
  (same rule as `matchableSql`: feeds + own/platform published events, `to_ids`, not warninglisted).
- First sync ≈ 45 pages; then a daily delta (rows re-seen or added since the cursor: ThreatFox re-sees ~17k a day,
  so ≈ 9 pages). A **weekly full resync** (cursor reset) drops entries removed server-side (unpublished events,
  `to_ids` off); between resyncs the agent also drops entries not seen for 90 days (server retention).
- Agent stores the list in `machine_dir()` (`sightings-list.json.gz`), domains and IPs as Python sets (~10 MB RAM);
  a domain matches when the name or any parent domain is listed (same rule as R5 suffix matching).
- No ETag needed (the agent's HTTP client treats 304 as an error today; the cursor avoids it).

## Hits (agent → server)

- `POST /agents/:agentId/sightings` `{ hits: [{ value, type: 'domain'|'ip', via: 'dns'|'connection', observed,
  count, first_seen, last_seen, process?, port? }] }`, max 200 per call.
- A new hit is uploaded within a minute; repeats are counted locally and sent with the next batch (every 5 minutes).
- The server **re-checks every hit** against the current matchable indicators (a hit on something no longer listed
  is dropped), then upserts one `cti_match` alert per (asset, indicator): `match_kind 'sighting'`, `rule 'R7'`,
  details `{ indicator_type, indicator_value, matched_on: 'dns'|'connection', observed, count, first_seen_at,
  last_seen_at, process, port, sources, ti_event_titles, ti_event_ids }`. Severity: S1.
- `services/iocMatch.ts`: its reconciliation (`ex` CTE) **excludes sightings**, so the R5/R6 run on every scan never
  overwrites or auto-resolves them. Indicator links (`linkMatchIndicators`) work as they are.
- Priority: `cti_match` that is not watchlist already gets **+200** and counts as the `threat_intel` concern, so a
  sighting ranks first with no change.

## Dashboard

| Place | Change |
|---|---|
| Agents page (`components/agents/policy.jsx` GROUPS) | "Threat sightings" switch with help text; capability warning when the agent cannot capture |
| `alertMeta.jsx` | label "Threat Contacted"; summary "looked up bad.example.net (DNS) 14×, last 10:32" / "connected to 203.0.113.9:443 (msedge.exe)"; playbook (isolate, check the process, escalate) |
| `WhyAlert.jsx` | R7 branch: evidence = what this computer did; knowledge = who lists it; rule text |
| `AlertsPage.jsx` drawer | "Matched" row for `dns` / `connection`; process, port, count, first/last contact |
| `MatchesPanel.jsx`, `/cti/stats` | a "Seen in traffic" kind next to listed IOC / watchlist; split counts |

## Evaluation (Objective 3)

On both lab VMs, sightings on, staging:
1. A tenant threat-intel event with 20 planted domains (unregistered random names under a real TLD: the resolver
   returns NXDOMAIN, harmless, still seen) and one public IP (a benign test host's current address).
2. A script on each VM looks up the 20 planted names mixed into 1,000 normal domains (a public top-sites list), and
   opens one connection to the planted IP.
3. Measure: **detection** (planted names and IP alerted / planted), **false alerts** (alerts not planted, over the run
   and 24 h of normal use), **time from lookup to alert**, agent **CPU, memory, bytes down/up**.
4. Repeat with browser secure DNS (DoH) on: DNS sightings drop, the connection poll still catches the planted IP.

## Decisions needed

| # | Question | Recommended |
|---|---|---|
| S1 | Severity of a sighting | **critical** for a feed indicator or a high-level event (a contact is stronger evidence than R5's listing); high for a medium event, medium for a low one |
| S2 | Default of the setting | **off**, switched on per tenant or agent on the Agents page |
| S3 | Process name | **looked up only on a hit** (no per-poll process scan) |
| S4 | Closing | **people close sightings** (never auto-resolved); the alert shows the last contact and keeps counting |
| S5 | Which indicators | **the same as R5**: feeds plus the tenant's own and platform published events, `to_ids`, not warninglisted |
| S6 | Privacy notice | **version 7** with the wording above, shown again to users before the agent's next start in app mode |

## Order of work

1. Server: list endpoint + pure paging/filter helpers with tests; sightings endpoint + pure planner (severity,
   dedupe, reopen rules) with tests; `iocMatch` exclusion; policy keys; staging deploy.
2. Agent: DNS decoder CNAME fix + tests; DNS sniffer (port 53, own frames kept) + tests on the scapy and native
   paths; connection pollers per OS + parser tests (fixtures of `/proc/net/tcp`, `netstat`, a fake TCP table);
   matcher (sets, suffix rule) + tests; list sync (cursor, weekly reset, expiry) + tests; hit batching/upload;
   setting wiring (config, policy, service start/stop separate from passive discovery); privacy notice v7; GUI rows.
3. Dashboard (table above).
4. Lab evaluation on both VMs, then the macOS tester guide gets a sightings step.
5. Production after the owner approves.

## Risks

- **Windows NDIS duplicates** (one packet at several layers) → count by (name, minute), not per frame.
- **Free-plan limits**: the list endpoint is the heaviest new request (2,000 rows per call; measure CPU on staging and
  lower the page size if needed); sighting uploads are rare and small. No new queue messages.
- **Expectations**: on a typical clean machine there will be **zero** sightings; usefulness is shown by the planted
  test, not by organic alerts.
