# UMEagleEye 2.0 — AI-Driven CAASM Platform

UMEagleEye is an AI-Driven **Cyber Asset Attack Surface Management (CAASM)** platform developed as a Final Year Project at the Faculty of Computer Science & Information Technology, University of Malaya. It provides comprehensive visibility into cyber assets, automates threat detection, delivers intelligent remediation guidance, and generates automated posture scoring and reporting — all hosted serverlessly with no always-on infrastructure.

## Live Deployment

| Service | URL |
|---------|-----|
| Frontend | https://umeagleeye.csnet.my |
| Backend API | https://umeagleeye-api.syntaxch404.workers.dev/api/v1 |

`umeagleeye.pages.dev` permanently redirects (301) to the csnet.my site, and every host serves `X-Robots-Tag: noindex`, so the application is not indexed by search engines. A separate **staging** environment (own Worker, KV/R2/queues and a sanitised copy of the database) is used to test changes before release; see [Environments](#environments).

## Core Features

### Asset Management
- **Asset Inventory (My Assets)** — Manual asset registry with criticality scoring, baseline snapshots, and drift detection
- **CSV Bulk Import** — Import assets from CSV with OS, port, and criticality data; identity-resolved on import so re-importing the same file does not create duplicates
- **All Assets** — Combined view of all discovered and manually added assets across the tenant
- **Duplicate Detection & Merge** — Legacy IP-keyed duplicates are grouped (`SAFE` auto-mergeable vs `REVIEW`) and merged into one survivor from the Asset Inventory "Duplicates" panel; merge moves addresses/events/SBOMs/relationships/topology, merges fields, and writes an audit log — all in one atomic batch ([Asset Identity & Deduplication](#asset-identity--deduplication))

### Network Discovery
- **Active Scanning** — EagleEye agent dispatches Nmap (`-sV -T4` + NSE scripts: `smb-os-discovery`, `banner`) on demand; discovered hosts are AI-enriched and upserted as assets. Hosts that are up but expose none of the scanned ports are still reported (no `--open`), so port-less devices (phones, many IoT) appear in active results and a host that closes its last port correctly records `ports: []`
- **SNMPv3 Device Detection** — When authPriv credentials are configured, the agent polls each active-scan host over UDP 161 for `sysDescr`/`sysObjectID` and walks the interface table; the backend classifies routers/switches (Cisco IOS/NX-OS/ASA, JunOS, Arista, MikroTik, FortiGate, PAN-OS, Aruba) as `network` devices — signal Nmap's TCP-only port list cannot see
- **Passive Scanning (ARP + mDNS/NetBIOS + DHCP)** — Three parallel daemon sniffers on the agent: ARP for host discovery, mDNS/NetBIOS for hostname resolution, DHCP fingerprinting for OS/device classification; no active probing required
- **Autonomous Passive Flush** — Agent drains the ARP buffer every `--passive-interval` seconds (default 60 s) and auto-creates scan records without dashboard interaction; dashboard-triggered passive scans flush the buffer on demand
- **MAC Vendor Live Lookup** — Real-time OUI resolution via `api.macvendors.com` at ingest time; feeds the AI classification prompt
- **DHCP Fingerprinting** — Captures option 12 (hostname), option 60 (vendor class), and option 55 (parameter list); optional Fingerbank API integration for confident device-type identification
- **AI Asset Classification** — DeepSeek (via OpenRouter) analyses port, OS, MAC vendor, DHCP, and existing context to produce a human-readable description and `Accept / Ignore / Investigate` suggestion for each discovered host

### Topology & Relationships
- **Network Topology** — Interactive collapsible tree view with subnet-aware inference: classifies assets by device type and hostname pattern into gateway → router → switch → access_point → host hierarchy; per-tenant sections for superadmin; DMZ badge, criticality dot, IP inline display
- **Asset Relationship Graph** — Force-directed canvas graph showing asset connectivity; device type and relationship type filter pills; tenant-scoped view; BFS blast-radius highlighting; drag, zoom, and pan controls

### Security Operations
- **Continuous Posture Management** — Automated drift detection (port changes, OS/package version drift, hostname/MAC/exposure/device-type changes, new device discovery) with 24-hour deduplication and an acknowledge workflow that re-baselines an asset in one click; posture score computed live on demand (start at 100, −5 per critical event capped at −40, −2 per high event capped at −20, −10 if >20% of assets have criticality ≥ 8) with 30-day reconstructed history
- **Threat Intelligence Integration** — Ingests live IoC feeds (AlienVault OTX, ThreatFox) every morning (MYT); each indicator is correlated to a MITRE ATT&CK tactic via a three-level derivation cascade; IoC Lookup cross-references any IP/domain/hash against the internal asset table in real time; MITRE ATT&CK heatmap visualises tactic coverage across all ingested indicators
- **Threat-intel events (MISP-style)** — Threat Intel page > *Threat-intel events*: analysts (tenant superadmin/admin) create an event, paste its indicators (IPs, domains, URLs, hashes, emails, CVE IDs; type detected, defanged values such as `hxxp://evil[.]com` refanged), and publish it. Sharing: *only our organisation*, *all tenants*, or *platform* (superadmin, every tenant). Business owners read. Each indicator can be context only (`to_ids` off); values on the built-in warninglist (public DNS, private/special ranges, big platform domains) are kept but never alert. Published CVE indicators flag the matching CVE alerts of every tenant that can see the event ("In threat intel: <event>", +100 priority, like KEV) and are cleared again when the event is unpublished, made private, edited or deleted; drafts and other tenants' private events never touch your alerts. API: `/cti/events` (`routes/tiEvents.ts`); rules in `services/threatIntel.ts`; feeds and event attributes share `cti_indicators` (`ti_event_id` NULL = feed). The create/edit dialog takes indicators too, and warns when a tag looks like one (tags are labels only)
- **Threat-intel matching against assets** (`services/iocMatch.ts`) — **R5, possible compromise:** a *public* IP of an asset (private and special ranges never match), its full hostname or a parent domain of it, or the host of a URL indicator, is listed by a feed or a visible published event → a *Threat Intel Match* alert (+200 priority, "Threat-intel matches"). **R6, watched software:** a `software` indicator of an event (`MOVEit Transfer`, `log4j-core@2.14.1`; a version matches its sub-versions, e.g. `@118` matches 118.0.5993) is installed (agent inventory) or in the SBOM → *Watched Software Found* (+100, "Exploitable"). One alert per asset and indicator. Re-checked after every scan, inventory, SBOM and asset edit (those assets), nightly after the feeds, and after any event change (the tenants that can see it); a match that disappears is auto-resolved, one that comes back reopens, false positives and accepted risks stay closed. Hashes and emails are stored for reference: no agent data can match them. Every alert's drawer has a **Why this alert** panel (evidence → compared with → rule → what ranked it up); the Threat Intel page has a **Matches** tab
- **AI-Driven Advisory Pipeline** — Triggering an advisory via the Alerts page sends a message to `advisory-queue` (Cloudflare Queues); the queue consumer fetches the event + asset context, builds a structured prompt, and calls DeepSeek; the resulting advisory is stored with `status = 'open'`; the pipeline is fully async so the HTTP request returns instantly; queue configured with max batch size 10, 30-second timeout, 2 retries on failure; advisory lifecycle managed as a state machine: `open → acknowledged → in_progress → resolved` with optional analyst assignment; `has_advisory` flag returned on every event row prevents accidental duplicate advisory generation from the UI
- **SLA Monitoring** — Open advisories older than 72 hours are counted whenever the Notification Centre loads (no scheduled job needed); breaches are surfaced as a distinct alert type

### SBOM & CVE Detection
- **Software Bill of Materials** — The EagleEye agent (2.1+) builds a CycloneDX SBOM of the computer it runs on with [Syft](https://github.com/anchore/syft): once a day, and when an admin presses *Run SBOM scan* on that computer's asset page. Folders: on Linux the whole system except volatile and home folders (so OS packages such as openssl are found); on Windows `Program Files`, `Program Files (x86)`, `ProgramData` and the agent account's npm/Python folders; plus any extra folders set in the agent. Syft's readers for compiled programs (Go binaries, .exe/.dll, Linux kernel images) are off by default: on a test PC they made about 90% of the findings, nearly all fixable only by the program's vendor (Docker Desktop, WSL). Program folders are scanned one at a time (two at once, 10 minutes each), so one huge folder is skipped instead of failing the SBOM, and Windows' own folders (WindowsApps, Defender, ProgramData\Microsoft…) are left out. The dashboard cannot choose a path. At most 1,500 findings per computer become alerts (KEV first, then EPSS, then CVSS). The job always goes to the agent bound to that asset (`agents.host_asset_id`); the server rejects an SBOM for any other asset
- **Automatic CVE Correlation** — After each SBOM, [Grype](https://github.com/anchore/grype) matches its packages against known vulnerabilities (NVD, GitHub Advisory, and more) on the agent. When Grype matches a GitHub advisory (GHSA), the agent reports its CVE ID so EPSS and KEV can match it
- **Coverage limits of CVE checks** — CVEs are checked for the packages Syft finds: language and framework packages in the scanned folders on Windows, and every dpkg/rpm package on Linux. Windows programs from the "Installed apps" list (for example Chrome or 7-Zip) are inventoried but **not CVE-checked**: Windows has no package database, and mapping program names to NVD products (CPEs) automatically proved unreliable in testing. Devices without an agent get no CVE check
- **CVE alerts grouped by fix** — the Alerts page's *All CVEs* tab shows one row per vulnerable package on an asset (`GET /events/cve-groups`), for example "Upgrade aiohttp 3.10.5 → 3.14.1: fixes 137 of 138 CVEs (1 KEV)". The target is, for each CVE, the smallest fixed version above the installed one (so it stays on the installed release line: Python 3.13.3 → 3.13.12, not 3.14), and the highest of those across the package's CVEs. Clicking a row lists its CVEs; selecting rows assigns, starts, resolves or accepts all their alerts at once (`POST /events/group-update`). Each CVE stays its own alert, so priority, KEV and auto-resolve work as before. On staging this showed 2,730 open CVE alerts as 194 fixes. Bulk updates (`POST /events/bulk` and group updates) run as a few set-based statements, so they fit the Workers free plan's 50-subrequest limit at any size
- **CISA KEV** — The nightly CTI cron loads CISA's [Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) list as `cve` indicators. CVE alerts on that list get a **KEV** badge, count as *Likely-exploited CVEs*, and rank as P1 (+100 priority; an indicator match on the asset itself stays +200, possible compromise). Alerts raised before a CVE joined KEV are flagged the next night
- **Storage** — The full SBOM document is stored in R2 (`sboms/<assetId>.json`, downloadable from the SBOM page); Neon keeps a summary and one row per package
- **Composite Risk Scoring** — Each CVE finding is scored using a weighted formula: `(CVSS × 10 × 0.40) + (EPSS × 100 × 0.35) + (Criticality × 10 × 0.15) + (CTI match ? 10 : 0)`, capped at 100
- **EPSS Enrichment** — Exploit Prediction Scoring System scores come from Grype's report (or, if missing, from the FIRST.org API in batch) and are incorporated into the risk formula at ingest time
- **CTI Enrichment** — CVE IDs cross-referenced against the platform's `cve` indicators (CISA KEV today); confirmed threat-intel matches add 10 points to the risk score
- **CWE on CVE alerts** — the weakness class of each CVE (for example CWE-787 Out-of-bounds Write) comes from Grype's own output (about 9 in 10 findings carry one) and is shown on the alert with its name from MITRE's CWE list
- **Deduplication** — Re-scanning the same asset updates existing alerts (refreshing CVSS, EPSS, fix versions, description) rather than creating duplicates; dedup key is `cve_id + package_name`
- **Dependency Inventory** — Expandable per-SBOM dependency table with package manager filter and search; counts by manager visualised as a bar chart
- **Superadmin Delete** — Superadmins can delete all SBOM records for an asset directly from the SBOM page

> **Note on SBOM scope:** Syft and Grype run on the machine where the agent is installed, so only computers with the agent get an SBOM and CVE check. Devices that cannot run it (printers, routers, IoT, phones) are discovered and monitored for changes, but not checked for CVEs. Syft and Grype are not bundled: install them on each agent computer (`winget install Anchore.Syft` / `Anchore.Grype`); Grype keeps a local vulnerability database of about 3 GB (downloaded on its first run).

### Reporting & Notifications
- **Automated Reporting** — Report generation is queued via `report-queue` (Cloudflare Queues) so large reports never block the HTTP response; the consumer builds the PDF and writes it to Cloudflare R2; download is served via a backend-signed blob endpoint — the R2 object key is never exposed in the URL, preventing enumeration; accessible to all roles
- **Notification Centre** — In-app notification bell with unread count badge; the `/notifications` endpoint runs three parallel queries: recent open/acknowledged advisories, advisories open > 72 h (SLA breach), and agents with `status = 'degraded'` or `lastHeartbeat` older than 5 minutes (offline); results are merged and sorted by recency; last-seen timestamp persisted in localStorage so the unread badge resets per-device without a backend read-tracking table

### Platform
- **Multi-Tenant Support** — SuperAdmin role manages multiple tenant organisations; all data scoped by tenant; tenant filter shared between inventory and graph tabs
- **Tenant Self-Management** — `tenant_superadmin` can edit their tenant name and status; invite new users by email (auto-creates a Google-linked account if none exists) or assign by username; manage roles for `tenant_admin` and `business_owner` users within their own tenant; accessible at `/users`
- **Agent Management** — Register one EagleEye agent per computer and hand it a one-paste **connection code** (API URL, agent ID and key); status from heartbeats, the computer each agent runs on with its last inventory, **rotate key**, retired 1.x agents listed apart with their history; SHA-256 hashed API keys
- **MFA / TOTP** — Per-user two-factor authentication via any TOTP authenticator app (Google Authenticator, Authy, Microsoft Authenticator); three-step backend flow: `POST /mfa/setup` generates a secret and a SVG QR code (built from the raw module matrix as filled `<rect>` elements — no canvas, fully compatible with Cloudflare Workers and phone scanners); `POST /mfa/enable` verifies the first TOTP code and activates MFA; at login, if MFA is enabled the API returns `mfa_required: true` and the frontend prompts for a 6-digit code before issuing the JWT; Settings page provides a manual secret copy fallback for users who cannot scan the QR code
- **Google OAuth** — Sign in with Google via `@react-oauth/google`; the frontend receives a short-lived Google access token and sends it to the backend; the Workers API validates it by calling Google's `userinfo` endpoint (not by decoding client-side) — this prevents token forgery; if the Google email matches an existing account it is linked automatically; if not, a new account is created with the Google profile data; JWT is issued on success using the same HS256 flow as password login
- **Global Search** — Live asset search in the top header bar (hostname + IP); debounced 300 ms; results dropdown with device type; navigates to Asset Inventory
- **Collapsible Sidebar** — Sidebar collapses to icon-only mode (64 px) or expands to full labels (256 px); logo click navigates to Dashboard; state persists via localStorage
- **Customisable Theme** — Dark, Light, and System theme modes; colours driven by CSS custom properties so the entire UI switches without touching component code; preference persists via localStorage
- **Profile Dropdown** — Header avatar opens a dropdown with username, role, tenant name, email; links to Profile & Settings; logout

### AI Security Chatbot
- **Natural Language Interface** — Accessible to all roles via the `/chatbot` route; understands plain-language queries in addition to slash-style commands
- **Structured Commands** — `status` (system overview), `posture` (security score), `assets` (top assets by criticality), `alerts` (recent critical/high events), `advisories` (open advisory list)
- **AI Assistant** — Any free-text question is routed to DeepSeek with injected live context (posture score, top critical alerts, open advisories with recommended actions); multi-session conversation history persisted in localStorage per user (up to 50 messages per session); sessions survive page navigation and browser refresh
- **SSE Streaming** — AI responses stream word-by-word via Server-Sent Events (`TransformStream` on the Worker, native fetch reader on the frontend) so answers appear instantly and the 30-second Worker wall-clock limit is never reached
- **Advisory Debug** — Selecting an advisory from the left sidebar opens a dedicated session; DeepSeek expands the recommended action into a full step-by-step remediation guide; streaming continues even if the user navigates away and returns
- **Advisory Fix** — `fix <advisory_id>` marks an advisory as resolved directly from the chat interface; available to `tenant_superadmin` and `tenant_admin`
- **Role-Filtered Access** — `business_owner` is limited to `status` and `posture`; all other roles have full chatbot capabilities
- **Dual AI Backend** — Uses `DEEPSEEK_API_KEY` (direct DeepSeek API) when set; falls back to OpenRouter (`OPENROUTER_API_KEY`) when only that is configured; current model: `deepseek/deepseek-v4-pro` via OpenRouter; `max_tokens: 2048` (safe limit that completes within the 30-second edge timeout)
- **Rich Message Rendering** — Bot responses render full markdown: `**bold**` as white semibold, `` `inline code` `` as teal pill badges (theme-aware: bright in dark mode, dark in light mode), bullet lists, and paragraph-spaced answers — no `dangerouslySetInnerHTML`

## Technology Stack

### Backend — Cloudflare Workers (Hono / TypeScript)
| Component | Technology |
|-----------|------------|
| Runtime | Cloudflare Workers (edge, serverless) |
| Framework | Hono 4 |
| Database | Neon PostgreSQL (serverless, HTTP protocol) |
| ORM | Drizzle ORM + `@neondatabase/serverless` |
| Auth | JWT (jose / HS256), PBKDF2 Web Crypto, TOTP (otplib) |
| Google OAuth | Access-token verification via Google userinfo endpoint |
| Async Jobs | Cloudflare Queues (advisory generation, PDF reports) |
| Scheduled Tasks | Cloudflare Cron Triggers (drift audit, CTI ingestion, posture snapshot + data retention) |
| Object Storage | Cloudflare R2 (PDF reports) |
| KV Store | Cloudflare KV (rate-limit locks, report metadata) |
| AI Advisory | DeepSeek via OpenRouter API |

### Frontend — Cloudflare Pages (React / Vite)
| Component | Technology |
|-----------|------------|
| Framework | React 18 + Vite 5 |
| Styling | Tailwind CSS + CSS custom properties (theme tokens) |
| State | React Context API (Auth, Theme, Chatbot) |
| HTTP | Axios |
| Charts | Recharts |
| Icons | Lucide React |
| Google Login | @react-oauth/google |

### EagleEye Agent — Python (`agent-gui/`)
| Component | Technology |
|-----------|------------|
| Runtime | Python 3.12+; Windows desktop app (PySide6, system tray) and `eagleeye` command line; packaged with PyInstaller + Inno Setup |
| Active Scanner | Nmap CLI (`-oX -`, own XML parser); built-in ping/port sweep when Nmap is missing |
| SNMPv3 Polling | pysnmp (authPriv — SHA/MD5/SHA-2 auth, AES/DES priv); network-device detection during active scans |
| Passive Sniffers | scapy (ARP, mDNS/NetBIOS-NS UDP 137/5353, DHCP UDP 67/68) on the adapter the OS routes through |
| Endpoint Inventory | Windows (PowerShell/CIM) and Linux collectors: hardware, OS and patches, security settings, interfaces, listening services, installed software |
| Transport | standard-library HTTPS client (no redirects, per-address timeouts) |
| Auth | Bearer API key + agent ID (SHA-256 verified); key kept in the OS credential store |
| Optional | Fingerbank API (DHCP-based device fingerprinting) |

## Architecture

```
Browser ──HTTPS──► Cloudflare Pages  (React SPA)
                          │
                          ▼ HTTPS /api/v1
                   Cloudflare Workers  (Hono API)
                    ├── Neon PostgreSQL  (15 tables)
                    ├── Cloudflare KV    (cache / locks)
                    ├── Cloudflare R2    (PDF reports)
                    └── Cloudflare Queues (async jobs)

Local Network ──► EagleEye Agent (Python, one per computer)
                    ├── POST /agents/:id/heartbeat     (every 30 s)
                    ├── Active scans
                    │     ├── GET  /scans/pending       (poll every 30 s) or POST /scans/agent-start
                    │     └── POST /scans/ingest        (Nmap / built-in sweep + SNMPv3 results)
                    ├── Passive listening
                    │     ├── ARP, mDNS/NetBIOS, DHCP sniffers on the adapter the OS uses
                    │     └── POST /scans/ingest        (one Discovery record per agent per hour)
                    └── Endpoint inventory of its own computer
                          └── POST /agents/:id/inventory (every 6 h and on demand)
```

## Project Structure

```
UMEagleEye2.0/
├── workers/                     # Cloudflare Workers backend
│   ├── src/
│   │   ├── db/
│   │   │   ├── schema.ts        # Drizzle schema (15 tables, incl. asset_addresses)
│   │   │   └── client.ts        # Neon + Drizzle client
│   │   ├── lib/
│   │   │   ├── auth.ts          # PBKDF2, JWT, TOTP, Google OAuth
│   │   │   ├── criticality.ts   # Criticality scoring (device type, owner, internet-facing)
│   │   │   ├── mac.ts           # MAC normalisation (lowercase colon form)
│   │   │   ├── identity.ts      # Device/address resolver: classifyMac, network key, matching rules, prefetch
│   │   │   ├── ingest-plan.ts   # Pure batch planner for scan ingest (chunked db.batch)
│   │   │   ├── duplicates.ts    # Pure duplicate-group detection (union-find; safe/review)
│   │   │   ├── merge.ts         # Pure merge planner (one atomic db.batch)
│   │   │   └── permissions.ts   # Centralised RBAC role constants + feature permission groups
│   │   ├── middleware/
│   │   │   └── auth.ts          # JWT middleware + requireRoles / requireTenantAccess guards
│   │   ├── routes/
│   │   │   ├── auth.ts          # register, login, MFA, Google, change-password, /me
│   │   │   ├── assets.ts        # Asset CRUD, baseline, CSV import, SBOM trigger, search, duplicates + merge
│   │   │   ├── scans.ts         # Scan dispatch, agent poll, agent ingest (active + passive), auto-expire
│   │   │   ├── sbom.ts          # SBOM ingest, list, dependencies, stats; CVE ingest + risk scoring
│   │   │   ├── events.ts        # Security events; acknowledge endpoint re-baselines asset + deletes event
│   │   │   ├── advisories.ts    # AI advisory management
│   │   │   ├── posture.ts       # Posture score + history
│   │   │   ├── cti.ts           # Threat indicators, MITRE
│   │   │   ├── reports.ts       # PDF report queue + secure blob download
│   │   │   ├── relationships.ts # Asset graph (tenant filter) + subnet inference + BFS blast-radius
│   │   │   ├── notifications.ts # Aggregated notification feed (advisories, SLA, agents)
│   │   │   ├── agents.ts        # EagleEye agent registry
│   │   │   ├── topology.ts      # Network topology tree with subnet-aware inference
│   │   │   ├── chatbot.ts       # AI chatbot — structured commands + free-text AI; SSE streaming via TransformStream; live context injection (posture, alerts, advisories)
│   │   │   └── tenants.ts       # Multi-tenant management; superadmin full + tenant_superadmin own-tenant
│   │   ├── services/            # Business logic (drift, posture, CTI)
│   │   │   ├── drift.ts         # Drift detection + baseline comparison
│   │   │   ├── posture.ts       # Daily posture snapshot calculation
│   │   │   ├── cti.ts           # OTX + ThreatFox ingestion, MITRE tactic derivation
│   │   │   ├── tiEvents.ts      # Threat-intel events (MISP-style): CRUD, attributes, publish
│   │   │   │                    #   (matching: services/threatIntel.ts CVEs, services/iocMatch.ts assets)
│   │   │   └── retention.ts     # Nightly purge of stale CTI indicators and old closed events
│   │   ├── queues/
│   │   │   └── consumer.ts      # Queue handler (advisory + PDF report jobs)
│   │   ├── cron/
│   │   │   └── triggers.ts      # Cron handler (4 scheduled tasks)
│   │   └── index.ts             # Entry point, CORS, route mounting
│   ├── drizzle/                 # SQL migrations (0000_baseline, ...) + snapshots; legacy/ = archived hand-applied SQL
│   ├── scripts/db/              # Guarded migration wrapper + staging sanitiser (see Database migrations)
│   ├── wrangler.toml            # Worker config (KV, R2, Queues, Crons) + [env.staging]
│   ├── drizzle.config.ts        # Drizzle Kit config
│   └── package.json
├── frontend/                    # React SPA
│   ├── src/
│   │   ├── components/
│   │   │   ├── layout/
│   │   │   │   ├── Sidebar.jsx      # Collapsible nav; logo = dashboard link
│   │   │   │   ├── Header.jsx       # Search bar, notification bell, profile dropdown
│   │   │   │   └── MainLayout.jsx
│   │   │   └── common/
│   │   │       ├── AssetGraph.jsx       # Canvas force-graph with device/rel-type filter pills
│   │   │       ├── BlastRadiusModal.jsx
│   │   │       └── TenantSelector.jsx   # Shared tenant-filter dropdown (superadmin only)
│   │   ├── context/             # AuthContext, ThemeContext (dark/light/system), ChatbotContext (sessions + streaming state)
│   │   ├── pages/
│   │   │   ├── LoginPage.jsx
│   │   │   ├── DashboardPage.jsx
│   │   │   ├── InventoryPage.jsx        # Asset inventory: My Assets / Discovered, filters, add, import CSV, graph
│   │   │   ├── AssetDetailPage.jsx      # One asset: identity, criticality, endpoint inventory, posture, alerts
│   │   │   ├── DiscoveryPage.jsx        # Scan dispatch (active + passive) + scan history
│   │   │   ├── SBOMPage.jsx             # SBOM inventory, dependency explorer, charts
│   │   │   ├── AlertsPage.jsx           # Security events with severity/type filters
│   │   │   ├── AdvisoriesPage.jsx       # AI advisories with status filter
│   │   │   ├── ThreatIntelPage.jsx      # CTI indicators + MITRE heatmap
│   │   │   ├── ReportsPage.jsx          # Report generation + secure blob download
│   │   │   ├── SettingsPage.jsx         # Profile, password change, integrations
│   │   │   ├── AgentsPage.jsx           # Agents: register (connection code), status, host computer, rotate key, retired list
│   │   │   ├── TenantsPage.jsx          # SuperAdmin only — platform-wide tenant + user management
│   │   │   ├── TenantSettingsPage.jsx   # Tenant self-management (tenant_superadmin edits own tenant/users)
│   │   │   └── ChatbotPage.jsx          # AI chatbot — SSE streaming, multi-session localStorage persistence, advisory debug, context-aware AI
│   │   └── App.jsx
│   ├── .env.production          # VITE_API_URL + VITE_GOOGLE_CLIENT_ID (git-ignored)
│   ├── .env.staging.example     # Template for the staging build
│   ├── public/_headers          # noindex + security headers served by Cloudflare Pages
│   └── package.json
├── agent-gui/                   # EagleEye Agent 2: desktop app + CLI (see agent-gui/README.md)
│   ├── eagleeye/                # pipeline, stages, collectors, passive sniffers, GUI
│   ├── packaging/               # PyInstaller spec, Inno Setup installer, build.ps1
│   └── tests/
├── AGENT_SETUP_GUIDE.md         # Rolling the agent out to computers (for IT administrators)
└── STAGING.md                   # Staging environment runbook
```

Secrets are not kept in files in the repository: the Worker's secrets live in Cloudflare (`wrangler secret put`), and the only local credential files are the git-ignored `workers/.env.staging` / `workers/.env.production` (database URLs for migrations) and `frontend/.env.production` / `.env.staging` (public build settings).

## Role-Based Access Control (RBAC)

| Role | Description |
|------|-------------|
| `superadmin` | Platform-wide access — manages all tenants, users, and data; sees all tenants in topology, graph, inventory, and SBOM |
| `tenant_superadmin` | Full operational access within their own tenant — scans, assets, SBOM, reports, advisories, agent config, and tenant user management |
| `tenant_admin` | Operational access within their own tenant — scans, assets, SBOM, reports, advisories; view-only tenant users; no discovery write restrictions |
| `business_owner` | Executive overview — posture metrics, reports, advisories, and read-only asset/SBOM/CTI/alerts; no discovery or topology access |

> **Discovery and Topology** are restricted to `superadmin`, `tenant_superadmin`, and `tenant_admin`. All other modules are available to `business_owner` in read-only mode.
>
> RBAC is enforced at the **API layer**, not just the UI — hiding a button in React is not security; every route is gated by `requireRoles()` or `requireTenantAccess()` middleware in the Workers backend before any query runs. Multi-tenant data isolation is enforced at the query level: every request first resolves the caller's tenant-scoped asset ID list, then filters all downstream queries through that list — a `tenant_admin` cannot read another tenant's events, assets, or advisories even with a valid JWT. Role constants and feature permission groups are centralised in `permissions.ts` so access rules have a single source of truth.

## Scheduled Tasks (Cron Triggers)

| Schedule (UTC) | MYT Equivalent | Task |
|---|---|---|
| `0 */6 * * *` | Every 6 h (2, 8, 14, 20) | Drift audit — safety-net pass comparing asset state to baseline snapshots (scans already run drift for the assets they touch) |
| `0 22 * * *` | 6:00 AM | CTI ingestion — pulls AlienVault OTX + ThreatFox feeds |
| `0 16 * * *` | Midnight | Posture snapshot — saves daily posture score to history, then runs data retention |

**Data retention** (runs with the midnight job, in batches, followed by the alert hygiene described under Drift Detection): CTI indicators not re-seen by any feed for 90 days and not linked to an event are deleted, as are resolved / false-positive events older than 365 days. Open alerts are never purged. The windows are constants in `workers/src/services/retention.ts`. Staging has no cron triggers.

> SLA breaches are not a cron job: they are computed when the Notification Centre is read.
>
> There is no scheduled active scan. Active scans (Nmap) are triggered manually from the Discovery page. Passive scanning runs autonomously on the agent at a configurable interval.

## Network Topology Inference

The `POST /topology/infer` endpoint rebuilds the topology tree from the asset inventory using device classification and subnet-aware parent assignment.

### Classification rules (priority order)

| Condition | Node Type | Layer |
|-----------|-----------|-------|
| `network` + `is_internet_facing` | gateway | L1 |
| `network` + hostname matches `fw-`, `gw-`, `firewall-` | router | L2 |
| `network` + hostname matches `core-sw`, `core-router` | switch | L2 |
| `network` + hostname matches `router-`, `lab-router` | router | L2 |
| `network` + hostname matches `dist-sw` | switch | L3 |
| `network` + hostname matches `wifi`, `ap-`, `wap-` | access_point | L3 |
| `network` (default) | switch | L3 |
| `server` + `is_internet_facing` | host | L2 (DMZ) |
| `server` | host | L4 |
| `workstation` | host | L5 |
| `iot` | host | L6 |

### Parent assignment (3-step resolution)

1. **Same-subnet candidates** with strictly lower layer — prefers highest layer number (closest parent), then switch > router > gateway type score
2. **Cross-subnet candidates** at `target_layer = this_layer - 1` — chosen deterministically: lowest layer first, then lowest IP (same input always yields the same parent)
3. **Fallback** — any node with lower layer

## Asset Relationship Inference

The `POST /relationships/infer` endpoint builds a star-topology relationship graph per `/24` subnet:

- **`connects_to`** edges — a network/infrastructure parent to a host child (downstream impact), and infrastructure-to-infrastructure uplinks
- **`depends_on`** edges — host-to-host dependencies
- **`same_subnet`** edges — informational peer links (not traversed by blast radius)

Runs per tenant; clears existing relationships before reinferring.

## Criticality Scoring

Criticality scores (1–10) are derived **only from the asset's own facts** — never from topology (layers, nodes or relationships). The relationship graph is a downstream view that may read this score; the score never reads the graph.

| Factor | Effect |
|--------|--------|
| Device type: `server` | Higher base score |
| `is_internet_facing: true` | +2 |
| No `owner` set | +1 penalty (unowned assets are higher risk) |
| High-risk / DB / wide-surface ports | up to +4 |
| Production / DB / perimeter hostname hints | ±1 each |
| Device type: `iot` | Moderate base |
| Device type: `workstation` | Lower base |
| Device type: `network` | Higher base |

`device_type_source` tracks whether the type was set by a user (`manual`) or inferred (`auto`). A `manual` **known** type is never changed by a scan; a `manual` **unknown** type (a hand-created/CSV asset with no type yet) is filled by the first scan that infers a concrete type, which then takes ownership (`→ auto`). An `auto` type may be corrected by a later **active** scan that infers a different non-`unknown` type (an `unknown` result never overwrites a known type). Any Rescore overwrites a manually-set criticality score.

## EagleEye Agent

The agent (`agent-gui/`) runs on each computer: it scans that computer's network (active Nmap scans, optional
passive listening and SNMPv3 polling) and reports the computer's own endpoint inventory and security settings.
Rolling it out is described in [AGENT_SETUP_GUIDE.md](AGENT_SETUP_GUIDE.md); its design, settings, privacy rules and
command line in [agent-gui/README.md](agent-gui/README.md).

In short: register an agent on the **Agents** page, install `EagleEyeAgent-Setup-<version>.exe` on the computer,
and paste the **connection code** into the agent's Settings (or, on a server or Linux, run
`eagleeye config init --connection-code <code>` then `eagleeye run`).

The original 1.x agent (`agent/eagleeye_agent.py`) and its bridge relay were retired in agent 2.0.2: migration
`0009_retire_old_agents` revoked their keys (the records and their Discovery history are kept and shown as
retired), and `0008_drop_bridges` removed the bridge table. The code remains in git history under the
`legacy-archive` tag.

## CVE Detection & Risk Scoring

Each SBOM run ends with a CVE check (Grype) on the agent; findings are sent to `POST /sboms/ingest-cve` on the Workers API, where they are enriched, scored and stored as `cve_detected` events. The agent sends the findings even when there are none, so alerts for CVEs that are gone are resolved.

### Ingest pipeline (Workers API)

1. **Resolve asset** — the uploading agent's host asset; the scan record (`subnet` carries the `assetId`) must belong to that agent and that asset
2. **EPSS** — Grype's value when present, otherwise fetched from FIRST.org in chunks of 30 CVE IDs
3. **CTI cross-reference** — CVE IDs looked up against `cve` indicators (`CISA KEV`); matches add 10 pts to the risk score, set `has_cti_match` (and `kev`), and link the alert to the indicator (`event_cti_indicators`, shown on the alert)
4. **Deduplication** — all existing `cve_detected` events for the asset fetched in one query; dedup key is `cve_id::package_name`
5. **Upsert** — existing events are updated (refreshed CVSS, EPSS, fix versions, description); new findings batch-inserted in groups of 50
6. **CWE** — the agent sends each finding's CWE IDs from Grype's output (`cwe_ids`); the alert shows them with their names (`workers/src/data/cwe.json`, built from MITRE's CWE list by `workers/scripts/cwe/build-cwe.mjs`). A nightly NVD job used to back-fill missing ones; it was removed because Grype already covers about 9 in 10 findings

### Composite Risk Score formula

```
score = (CVSS × 10 × 0.40)          // CVSS 0–10 normalised to 0–100, 40% weight
      + (EPSS × 100 × 0.35)          // EPSS 0–1 probability, 35% weight
      + (Criticality × 10 × 0.15)    // asset criticality 1–10, 15% weight
      + (CTI match ? 10 : 0)         // flat 10 pts if CVE is in threat intel feed

score = min(score, 100)
```

### Severity mapping

| CVSS score | Grype label | Stored severity |
|---|---|---|
| ≥ 9.0 | any | `critical` |
| ≥ 7.0 | any | `high` |
| ≥ 4.0 | any | `medium` |
| 0 (no score) | Critical | `critical` |
| 0 (no score) | High | `high` |
| 0 (no score) | Medium | `medium` |
| anything else | any | `low` |

## Threat Intelligence (CTI)

Two live IoC feeds are ingested daily at 6:00 AM MYT via a Cloudflare Cron Trigger. All rows are upserted — re-ingesting the same indicator value refreshes `last_seen`, `confidence_score` and the malware family without creating duplicates (a feed that names no family keeps the one another feed gave). Indicators that no feed has re-seen for 90 days (and that no event references) are purged nightly, which keeps the table bounded on a free-tier database.

### Data sources

| Source | API | Fetch scope | Confidence |
|--------|-----|-------------|------------|
| AlienVault OTX | `/pulses/activity?limit=50&page=1` | 50 latest community pulses | Hardcoded `0.70` (OTX provides no per-indicator score) |
| ThreatFox (abuse.ch) | `get_iocs` | Last 7 days of IoCs | From `confidence_level` field, normalised: `confidence_level / 100` |

### MITRE ATT&CK techniques

Techniques come from MITRE ATT&CK's own data, not from guesses about an indicator's type or tags.

- `workers/scripts/attack/build-attack.mjs` downloads MITRE's official STIX 2.1 file (`mitre-attack/attack-stix-data`, Enterprise) and writes `workers/src/data/attack.json` (about 190 KB): the tactics in matrix order, every technique and sub-technique with its tactics, and every ATT&CK software entry (malware and tools) with the techniques MITRE documents for it ("uses" relationships), plus its names and aliases. Rerun it when MITRE publishes a new release, then deploy.
- At ingest each indicator records its **malware family** (`malware_family`): ThreatFox's `malware_printable`, or an OTX pulse's `malware_families`. If ATT&CK documents the family (matched on name or alias, ignoring case and punctuation; for ThreatFox also its aliases and Malpedia key), its ATT&CK software id is stored in `attack_software`, for example `S0154` for Cobalt Strike.
- Techniques an OTX pulse author tagged (`attack_ids`, all of them) are stored in `attack_techniques`.
- An indicator's techniques are its family's techniques plus the ones the feed named. They are looked up at read time, so a new ATT&CK release applies without re-ingesting.
- Indicators whose family ATT&CK does not document (Mirai, for example), or whose feed names no family, have no techniques. The ATT&CK tab says how many.

### Indicator type normalisation

Raw type strings from both APIs are mapped to the platform's internal enum:

| Internal type | OTX raw types | ThreatFox raw types |
|---|---|---|
| `ip` | `IPv4`, `IPv6` | `ip:port` (port stripped), `ip` |
| `domain` | `domain`, `hostname` | `domain`, `domain_regex` |
| `hash` | `FileHash-MD5`, `FileHash-SHA256`, `FileHash-SHA1` | `*md5_hash`, `*sha256_hash` |
| `url` | `URL` | `url` |
| `email` | `email` | — |

For ThreatFox `ip:port` indicators, the port is stripped so the stored IP can be cross-referenced against internal asset IPs.

### IoC Feed UI

The Threat Intelligence page IoC Feed tab uses server-side pagination and filtering:

- **Page size:** 15 rows per page (consistent with Alerts page)
- **Filters:** Source (AlienVault OTX / ThreatFox), Indicator Type (ip / domain / hash / url / email), free-text search on indicator value
- **Filter option population:** Derived from the `/cti/stats` full-table aggregation, so all source and type options are always visible regardless of current filter state

### IoC Lookup

The Lookup tab accepts any IP, domain, hash, URL, or email and queries `GET /cti/lookup?value=`. If the value matches a stored indicator, full details are returned. Simultaneously, if the value is an IP address, it is cross-referenced against the internal `assets` table — a match surfaces the internal asset's hostname, criticality score, and internet-facing status, flagging confirmed threat-intel overlap with the internal environment.

### MITRE ATT&CK Matrix

`GET /cti/matrix` groups the feed indicators (CISA KEV CVEs left out) by family, ATT&CK software and named techniques, and the Worker expands each group into techniques. The tab shows:

- **Coverage:** the share of feed indicators with ATT&CK techniques, families matched, and the largest families ATT&CK does not document. The ATT&CK version and date come from the data file.
- **Matrix:** one column per tactic of the current ATT&CK release (v20 has 15, with Stealth and Defense Impairment in place of Defense Evasion), listing the techniques seen. Sub-techniques roll up to their parent. Shading is by indicator count or by number of families: a family with many techniques counts towards all of them, so the families view stops a few big families from dominating.
- **Technique detail:** families that use it, sub-techniques, links to attack.mitre.org, and "View indicators" (the IoC Feed filtered with `?technique=` or `?family=`).
- **Navigator layer:** a layer file (format 4.5) to open in MITRE's ATT&CK Navigator.
- **Scope** (`?scope=`):
  - `feeds` (default): the global feeds.
  - `matched`: indicators behind open threat-intel alerts on your own assets, from feeds and events.
  - `events`: your events and the published ones shared with you, each event counted as one "family".

Threat-intel events take ATT&CK too: an optional malware family (resolved to ATT&CK software like the feeds) and techniques picked from MITRE's catalogue (`GET /cti/attack`). Unknown technique ids are dropped. The event's ATT&CK fields are copied to its attributes, so lookups and alert details show them.

## Asset Source Hierarchy

Assets have a `source` field that controls upsert precedence:

| Source | Set by | Description |
|--------|--------|-------------|
| `manual` | My Assets page or CSV import | User-managed; shown in My Assets count |
| `scan_active` | Active Nmap scan | Discovered by active scanning |
| `scan_passive` | Passive ARP/mDNS/DHCP scan | Discovered by passive sniffing |

`manual` is **sticky / terminal** — once a human accepts a host into My Assets (via the Discovery scan modal's *Accept* action) or imports it via CSV, later rescans never flip it back to `scan_active`/`scan_passive`, so accepted assets are never silently evicted from My Assets. `scan_active` and `scan_passive` freely update each other on rescans of not-yet-accepted hosts. Accepting an asset also **merges** the incoming `os_info` onto the existing record — scan-derived fields (SNMP `sysDescr`/interfaces, product/version data) are preserved rather than overwritten. The Tenants page asset count shows only `source = 'manual'` assets.

## Asset Identity & Deduplication

Identity is **device-based, not IP-based**. DHCP reuse and randomized MACs mean one IP can host different devices over time and one device can hold many IPs, so assets are keyed by a device/address split:

- **`assets`** = the device (latest-seen `ip_address`/`mac_address`, `host_key`, criticality, baseline).
- **`asset_addresses`** = every address a device has had; the row with `ended_at IS NULL` is current. A partial unique index `(tenant_id, network_key, ip_address) WHERE ended_at IS NULL` keeps at most one current scoped address per network. `network_key` is the host IP's `/24` (unscoped/NULL for manual & CSV assets).

### Resolver matching (scan ingest)

Each ingested host is resolved to an existing device or a new one, first match wins (MAC classified via the shared `classifyMac`):

| Rule | Match | Result |
|---|---|---|
| 1 | Global (burned-in) MAC on any network | same device (unless two `network`/`server` devices share it across different non-null networks → treated as a possible duplicate, not merged) |
| 2 | Local/random MAC + same network (or unscoped row with same IP) | same device |
| 3 | `host_key` (SMB computer name) + same network | same device |
| 4 | No usable MAC, or the matched address has none | same device; fill in MAC/network |
| 5 | Same network + IP but a different valid MAC | new device; end the old address |
| 6 | otherwise | new device |

Shared/virtual MACs (VMware, VRRP, HSRP, MS-NLB) and invalid/broadcast/multicast MACs never identify a device. Ingest **prefetches** candidates in 3 queries for the whole batch and writes in chunked `db.batch` calls, so Cloudflare subrequests stay roughly constant regardless of host count.

### Duplicate detection & merge (legacy cleanup)

`GET /assets/duplicates` groups existing duplicates (union-find) and labels each group:

- **SAFE** — same global MAC (any network), or same local MAC on the same network / same unscoped IP. Auto-mergeable.
- **REVIEW** — `network`/`server` devices sharing a global MAC across different networks, same specific hostname with different MACs, or same `host_key` on different networks. Human decides; never auto-merged.

`POST /assets/merge` (and `POST /assets/duplicates/merge-safe` for up to 4 SAFE groups/request) merge losers into a chosen survivor in one atomic `db.batch`: end colliding current addresses → move `asset_addresses`/`events`/`sboms`/`dependencies` → dedupe & remap `asset_relationships` (honouring the `(source,target,type)` unique index, dropping self-loops) → keep one `topology_nodes` row per asset → merge fields into the survivor (source `manual` if any; latest-seen IP/MAC; max criticality; OR of internet-facing; shallow `os_info` merge) → write one `audit_logs` row per removed asset → delete losers. Both are tenant-scoped and gated to `tenant_superadmin` (same as delete); `?dry_run=true` returns the move counts and resulting fields without writing.

## UI / UX

### Top Header Bar

| Element | Behaviour |
|---------|-----------|
| Sidebar toggle (PanelLeft) | Collapses/expands sidebar |
| Global search | Live asset search (hostname + IP); 300 ms debounce; results dropdown with device type |
| Theme picker | Dark / Light / System; stored in localStorage |
| Notification bell | Fetches `/notifications`; shows unread count badge; dropdown lists advisories, SLA breaches, agent alerts |
| Profile avatar | Dropdown: username, role, tenant name, email; links to Settings; Logout |

### Theme System

| Mode | Behaviour |
|------|-----------|
| `dark` | Default dark palette (dark-950 body, dark-900 surfaces) |
| `light` | Inverted light palette (white surfaces, near-black text) |
| `system` | Follows OS `prefers-color-scheme`; updates automatically |

All `dark-XXX` Tailwind colours are backed by CSS custom properties in `index.css`. Adding `html.light` swaps every variable — no JSX needs conditional class logic. Chart tooltips use `--dark-700` background (one step above card surface) so they are visible and elevated in both modes.

### Network Topology View

- Superadmin sees one collapsible card per tenant; each shows node count and collapses independently
- Per-node: coloured icon by type, hostname, IP, layer badge, type badge
- **DMZ** badge for `is_internet_facing` assets
- Criticality dot (red ≥10, orange ≥9, yellow ≥8) for high-risk nodes
- Tenant filter dropdown (superadmin) also filters the topology tree

### Asset Relationship Graph Filters

- **Device type pills** — Server / Workstation / Network / IoT; click to show/hide that node type
- **Relationship type pills** — Subnet / Connects / Depends / Auth / Exposes; click to show/hide that edge type

Filters apply instantly without re-running the force simulation.

## Asset Import (CSV)

Tenants can bulk-import assets via **My Assets → Import CSV**.

### Supported columns

| Column | Required | Description |
|--------|----------|-------------|
| `ip_address` | **Yes** | IPv4 or IPv6 address |
| `hostname` | No | Device hostname |
| `mac_address` | No | MAC address (AA:BB:CC:DD:EE:FF) |
| `owner` | No | Owner name / email |
| `device_type` | No | `server`, `workstation`, `network`, `iot`, `unknown` |
| `criticality_score` | No | Integer 1–10 (default: 5) |
| `is_internet_facing` | No | `true` or `false` |
| `hardware_vendor` | No | Hardware manufacturer |
| `os_name` | No | OS name (e.g. `Ubuntu`, `Windows Server`) |
| `os_version` | No | OS version string |
| `open_ports` | No | Space or comma-separated ports (e.g. `22/tcp 80/tcp 443/tcp`) |

- Existing assets (matched by IP + tenant) are **updated**; new IPs are **inserted**
- Upserts use `ON CONFLICT (ip_address, tenant_id) DO UPDATE` — concurrent agents never create duplicates

Sample datasets included in the repository root:

| File | Tenant | Assets |
|------|--------|--------|
| `cyberforce_corporation_assets.csv` | CyberForce Corporation | 33 |
| `vanilla_corporation_assets.csv` | Vanilla Corporation | 30 |

## Baseline Snapshots & Drift Detection

Setting a baseline via **Assets → Bookmark icon** captures a point-in-time Golden Image snapshot:

```json
{
  "ports": [22, 80, 443],
  "os_version": "22.04",
  "packages": { "nginx": "1.24.0", "openssl": "3.0.2" },
  "hostname": "web-server-01",
  "mac_address": "AA:BB:CC:DD:EE:FF",
  "is_internet_facing": false,
  "device_type": "server",
  "captured_at": "2026-05-15T10:00:00.000Z",
  "auto_set": false,
  "ports_known": true,
  "packages_known": true
}
```

**Auto-baseline:** The first scan of a previously-unseen asset automatically sets its baseline so future scans can detect drift immediately. Manually overriding the baseline (Bookmark icon) sets `auto_set: false`.

**`ports_known` / `packages_known`:** A baseline only records what the capture could actually see. A passive scan has no port visibility (`ports_known: false`) and no scan collects installed packages, so a baseline set before an SBOM has `packages_known: false` and omits the `packages` key entirely — never an empty `{}`. The drift audit skips the ports (or packages) comparison while that flag is false, so the first active scan / first SBOM **completes** the baseline for that attribute instead of raising drift for every port/package at once. Package completion rides on the same atomic write as the SBOM ingest.

The drift audit (run for the affected assets after every scan and every agent inventory, plus a 6-hourly cron as a safety net) compares each asset's current `os_info` and fields against its `baseline_state` and generates typed security events:

| Event type | Trigger | Severity |
|---|---|---|
| `port_opened` | New port seen in an active scan | Risky service (FTP, Telnet, SMB, RDP, VNC, databases…) High, Critical if internet-facing; other ports below 1024 Medium (High if internet-facing); others Low (Medium if internet-facing) |
| `version_downgrade` | OS version decreased (rollback to an older build) | High |
| `config_change` (hostname) | Hostname changed | Medium |
| `config_change` (mac_address) | MAC address changed, and the new MAC is not one of the machine's own adapters reported by its agent | High |
| `config_change` (internet_facing) | Asset became internet-facing | Critical |
| `config_change` (internet_facing) | Asset became internal | Medium |
| `config_change` (device_type) | Device type reclassified | Medium |
| `config_change` (firmware) | SNMP sysDescr changed (network devices) | Medium |
| `new_device` | A network scan finds a host never seen before (an agent registering its own computer does not alert: IT installed it) | High if internet-facing, else Medium |

**What does not alert** (each was mostly noise in production data):
- **A port closing.** It lowers risk; it only resolves the matching `port_opened` alert. There is no `port_closed` alert.
- **A scan that saw no open port at all** on a host whose baseline has ports. That is almost always a missed scan (asleep, firewalled, timed out), so port drift is not judged on it and open port alerts stay as they are.
- **An OS upgrade.** The audit moves the baseline's `os_version` to the new version instead.
- **Package changes.** Packages are not compared: they change with every update, and the ones that matter raise CVE alerts from the SBOM.

**One alert per condition:** The audit does not raise a fresh event every run. Each distinct condition (e.g. "port 3389 open on asset X") maps to a single alert — re-detecting it bumps `last_seen` and an `occurrences` counter on the existing open alert, a condition that is no longer detected (port closed again, hostname reverted) is auto-resolved, and a condition an analyst marked a false positive stays suppressed. A condition that comes back within 14 days of being auto-resolved **reopens** its alert instead of raising a new one, so a port that flaps between scans stays one alert.

**Alert hygiene** (nightly, and with the manual drift audit for the tenant; `workers/src/services/alertHygiene.ts`):
- CVE alerts on an asset that has no SBOM are resolved: no scan can confirm or clear them. This also closed the alerts left by the retired pre-2.1.0 SBOM pipeline.
- Open new-device alerts are resolved once the device is added to My Assets or given an owner (immediately, from the asset edit), or when it has not been seen for 14 days. Alerts someone set to *in progress* are left alone.

**Accept-into-baseline workflow:** Accepting a drift alert as *accepted risk* in the Alerts page treats that change as the new normal — only the single attribute the alert is about is re-baselined (accepting "port 22 opened" never silently accepts an unrelated MAC or package change), and the alert is closed. Accepting a package change while the asset's baseline packages are still unknown leaves them unknown and just closes the alert; the first full SBOM is what establishes the package baseline.

## Deployment

### Prerequisites
- [Node.js 18+](https://nodejs.org)
- [Cloudflare account](https://cloudflare.com) (free tier sufficient)
- [Neon account](https://neon.tech) (free tier sufficient)
- Cloudflare Queues `advisory-queue` and `report-queue` created
- Cloudflare R2 bucket `umeagleeye-reports` created
- Cloudflare KV namespace created

### Environments

| | Production | Staging |
|---|---|---|
| Frontend | `umeagleeye.csnet.my` (Pages branch `main`) | Pages branch `staging` (alias `staging.<project>.pages.dev`) |
| API | Worker `umeagleeye-api` | Worker `umeagleeye-api-staging` (no cron triggers) |
| Database | Neon `production` branch | Neon `staging` branch: a copy of production with personal data and credentials stripped |
| KV / R2 / Queues | production resources | separate `*-staging` resources |

Staging exists so changes can be tested against realistic data while production stays live. Setup and commands are in [STAGING.md](STAGING.md).

### First-time deployment

```powershell
# 1. Install Workers dependencies (wrangler logged in: npx wrangler login)
cd workers ; npm install

# 2. Create the schema on an empty Neon database (see Database migrations)
cp .env.production.example .env.production   # set DB_TARGET=production and DATABASE_URL
npm run db:migrate:prod

# 3. Set the Worker's secrets; each command prompts for the value (see Environment Variables)
npx wrangler secret put DATABASE_URL
npx wrangler secret put JWT_SECRET_KEY
npx wrangler secret put GOOGLE_CLIENT_ID
npx wrangler secret put OPENROUTER_API_KEY      # and/or DEEPSEEK_API_KEY
npx wrangler secret put OTX_API_KEY
npx wrangler secret put THREATFOX_API_KEY
npx wrangler secret put NVD_API_KEY            # optional, not used by any job at present

# 4. Deploy the Worker, then the frontend
npm run deploy
cd ../frontend
# frontend/.env.production: VITE_API_URL=https://umeagleeye-api.<subdomain>.workers.dev/api/v1
#                           VITE_GOOGLE_CLIENT_ID=<same client id>
npm install ; npm run deploy
```

Secrets are entered once per secret and never stored in the repository. To change one later, run its `wrangler secret put` again; nothing else is re-uploaded. A random `JWT_SECRET_KEY`: `node -e "console.log(require('crypto').randomBytes(48).toString('base64url'))"`.

### Releasing a change

```powershell
# 1. Test on staging
cd workers  ; npm run deploy:staging
cd ../frontend ; npm run deploy:staging

# 2. Back up production, then apply any new migrations (see below)
cd ../workers ; npm run db:migrate:prod

# 3. Deploy to production: Worker first, then frontend
npm run deploy
cd ../frontend ; npm run deploy
```

### Database migrations

The schema lives in `workers/src/db/schema.ts`; changes are shipped as numbered SQL files in `workers/drizzle/` and applied by a guarded wrapper (`workers/scripts/db/db.mjs`). `drizzle-kit push` is intentionally **not** exposed, because it rewrites a live schema with no history.

```powershell
cd workers
npm run db:generate          # diff schema.ts against the last snapshot -> new SQL file in drizzle/ (review it)
npm run db:status:staging    # show target + pending migrations (read-only)
npm run db:migrate:staging   # apply to staging, then test
npm run db:status:prod
npm run db:migrate:prod      # asks you to type "production" before writing
```

- Credentials come from `workers/.env.staging` and `workers/.env.production` (git-ignored; templates are the `*.example` files). Each file declares `DB_TARGET`, and the wrapper refuses to run if it does not match the target you asked for. Use `postgresql://` URLs (not `postgresql+asyncpg://`).
- `0000_baseline.sql` creates the whole schema on an empty database. The existing production database was brought under management by *recording* the baseline as applied (`db:baseline:prod`), not by re-running it. Earlier hand-applied SQL is archived in `drizzle/legacy/`.
- Prefer additive changes (add columns, then drop later) so the previous Worker version keeps working while a release rolls out, and take a `pg_dump` of production before every production migration.

### Staging data

Staging is created as a Neon branch of production and then sanitised so no personal data is copied:

```powershell
cd workers
npm run db:staging:mark              # creates the staging_marker table on the branch
npm run db:staging:sanitize          # dry run: counts what would change
npm run db:staging:sanitize:apply    # pseudonymise users, revoke agent keys, mask owners, clear audit logs
```

Accounts listed in `KEEP_EMAILS` (in `workers/.env.staging`) keep their login; all other users become `user_xxxx@staging.invalid` with no way to sign in. The sanitiser refuses to run unless the staging marker exists and the host differs from the production host.

## Environment Variables

Worker secrets (set with `npx wrangler secret put <NAME>`; add `--env staging` for staging). Non-secret settings such as `OPENROUTER_MODEL`, `JWT_EXPIRE_MINUTES`, `FRONTEND_URL` and `SCAN_DEFAULT_SUBNET` are `[vars]` in `workers/wrangler.toml`.

| Variable | Description |
|----------|-------------|
| `DATABASE_URL` | Plain Neon PostgreSQL connection string (`postgresql://…`) used by the Cloudflare Worker; do not point this to Hyperdrive |
| `JWT_SECRET_KEY` | HS256 signing secret (min 32 chars) |
| `GOOGLE_CLIENT_ID` | Google OAuth Client ID |
| `OPENROUTER_API_KEY` | DeepSeek AI via OpenRouter (used if `DEEPSEEK_API_KEY` is not set) |
| `OPENROUTER_MODEL` | Model ID for OpenRouter (currently `deepseek/deepseek-v4-pro`; set in `wrangler.toml` `[vars]`) |
| `DEEPSEEK_API_KEY` | Direct DeepSeek API key — optional; takes priority over OpenRouter when set |
| `OTX_API_KEY` | AlienVault OTX threat intelligence |
| `THREATFOX_API_KEY` | ThreatFox threat intelligence |
| `NVD_API_KEY` | NIST NVD API key — optional; no job uses it at present (kept for NVD lookups; raises NVD's rate limit from 5 to 50 requests per 30 s) |
| `CLOUDFLARE_API_TOKEN` | Optional, in your shell (not a Worker secret): lets wrangler deploy without `wrangler login` |

Per-environment database credentials for migrations live in `workers/.env.staging` and `workers/.env.production` (`DB_TARGET`, `DATABASE_URL`, and optionally `KEEP_EMAILS` for staging). The staging Worker has its own secrets, set with `wrangler secret put <NAME> --env staging`; use a different `JWT_SECRET_KEY` there.

All variables are stored as **Cloudflare Workers secrets** (never in code). The frontend needs `VITE_API_URL` and `VITE_GOOGLE_CLIENT_ID` in `frontend/.env.production` (git-ignored; staging uses `frontend/.env.staging`, template `.env.staging.example`).

## Local Development

```powershell
# Backend (Workers dev server). Put a NON-production DATABASE_URL in workers/.dev.vars
# (e.g. the staging branch) so local testing never touches live data
cd workers && npx wrangler dev

# Frontend
cd frontend
cp .env.staging.example .env.local
# In .env.local set VITE_API_URL=http://localhost:8787/api/v1
npm run dev
```

> The earlier FastAPI/Python/Docker backend was removed in Phase D; it is kept in git history under the `legacy-archive` tag.

---

*Final Year Project — University of Malaya, Faculty of Computer Science & Information Technology*
*Supervisor: Dr. Badrul Hisham*
