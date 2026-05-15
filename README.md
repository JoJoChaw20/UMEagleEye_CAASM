# UMEagleEye 2.0 — AI-Driven CAASM Platform

UMEagleEye is an AI-Driven **Cyber Asset Attack Surface Management (CAASM)** platform developed as a Final Year Project at the Faculty of Computer Science & Information Technology, University of Malaya. It provides comprehensive visibility into cyber assets, automates threat detection, delivers intelligent remediation guidance, and generates automated posture scoring and reporting — all hosted serverlessly with no always-on infrastructure.

## Live Deployment

| Service | URL |
|---------|-----|
| Frontend | https://umeagleeye.pages.dev |
| Frontend (University) | https://umeagleeye.csnet.my |
| Backend API | https://umeagleeye-api.syntaxch404.workers.dev/api/v1 |

## Core Features

- **Asset Inventory (My Assets)** — Manual asset registry with criticality scoring, baseline snapshots, and drift detection
- **CSV Bulk Import** — Import assets from CSV with OS, port, and criticality data; upserts by IP per tenant
- **Network Discovery** — EagleEye scanning agents push Nmap scan results to the platform; discovered hosts can be promoted to the asset registry
- **Network Topology** — Interactive tree view (gateway → router → switch → host) with BFS-based relationship inference
- **Continuous Posture Management** — Automated drift detection and ongoing posture scoring tracked over time
- **Threat Intelligence Integration** — Ingests live feeds (AlienVault OTX, ThreatFox, NVD) to identify vulnerable assets proactively
- **AI-Driven Advisory Pipeline** — DeepSeek (via OpenRouter) generates actionable remediation instructions for security events
- **Asset Relationship Graph** — Visualises asset dependencies and lateral movement blast-radius via BFS
- **Automated Reporting** — Queued PDF report generation stored in Cloudflare R2; secure blob download (no token in URL)
- **ChatOps Integration** — Telegram bot with role-based filtering and real-time security alerts
- **Multi-Tenant Support** — SuperAdmin role manages multiple tenant organisations; all data scoped by tenant
- **Agent Management** — Register and monitor EagleEye scanning agents; SHA-256 hashed API keys; read-only config view for non-admin roles
- **MFA / TOTP** — Per-user two-factor authentication via authenticator apps
- **Google OAuth** — Sign in with Google; auto-links to existing account by email
- **Collapsible Sidebar** — Sidebar collapses to icon-only mode (64 px) or expands to full labels (256 px); toggle via header button or in-sidebar chevron; state persists via localStorage
- **Customisable Theme** — Dark, Light, and System theme modes; colours driven by CSS custom properties so the entire UI switches without touching component code; preference persists via localStorage

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
| Scheduled Tasks | Cloudflare Cron Triggers (drift audit, SLA monitor, CTI ingestion, posture snapshot, NVD update) |
| Object Storage | Cloudflare R2 (PDF reports) |
| KV Store | Cloudflare KV (rate-limit locks, report metadata) |
| AI Advisory | DeepSeek via OpenRouter API |
| Notifications | Telegram Bot API |

### Frontend — Cloudflare Pages (React / Vite)
| Component | Technology |
|-----------|------------|
| Framework | React 18 + Vite 5 |
| Styling | Tailwind CSS + CSS custom properties (theme tokens) |
| State | React Context API (Auth, Theme) |
| HTTP | Axios |
| Charts | Recharts |
| Icons | Lucide React |
| Google Login | @react-oauth/google |

### EagleEye Agent — Python
| Component | Technology |
|-----------|------------|
| Runtime | Python 3.10+ |
| Scanner | python-nmap (falls back to nmap CLI) |
| Transport | requests (HTTPS to Workers API) |
| Auth | Bearer API key + X-Agent-ID header (SHA-256 verified) |

## Architecture

```
Browser ──HTTPS──► Cloudflare Pages  (React SPA)
                          │
                          ▼ HTTPS /api/v1
                   Cloudflare Workers  (Hono API)
                    ├── Neon PostgreSQL  (13 tables)
                    ├── Cloudflare KV    (cache / locks)
                    ├── Cloudflare R2    (PDF reports)
                    └── Cloudflare Queues (async jobs)

Local Network ──► EagleEye Agent (Python)
                    ├── GET  /scans/pending  (poll every 30s)
                    └── POST /scans/ingest   (push nmap results)
```

## Project Structure

```
UMEagleEye2.0/
├── workers/                     # Cloudflare Workers backend (primary)
│   ├── src/
│   │   ├── db/
│   │   │   ├── schema.ts        # Drizzle schema (13 tables)
│   │   │   └── client.ts        # Neon + Drizzle client
│   │   ├── lib/
│   │   │   └── auth.ts          # PBKDF2, JWT, TOTP, Google OAuth
│   │   ├── middleware/
│   │   │   └── auth.ts          # JWT middleware + role guard
│   │   ├── routes/              # API route handlers
│   │   │   ├── auth.ts          # register, login, MFA, Google, change-password
│   │   │   ├── assets.ts        # Asset CRUD + baseline + CSV import
│   │   │   ├── scans.ts         # Trigger scan, agent poll, agent ingest, status
│   │   │   ├── events.ts        # Security events
│   │   │   ├── advisories.ts    # AI advisory management
│   │   │   ├── posture.ts       # Posture score + history
│   │   │   ├── cti.ts           # Threat indicators, MITRE
│   │   │   ├── reports.ts       # PDF report queue + download
│   │   │   ├── relationships.ts # Asset graph + BFS blast-radius
│   │   │   ├── agents.ts        # EagleEye agent registry
│   │   │   ├── topology.ts      # Network topology tree
│   │   │   └── tenants.ts       # Multi-tenant management (superadmin)
│   │   ├── services/            # Business logic
│   │   ├── queues/
│   │   │   └── consumer.ts      # Queue handler (advisory + report jobs)
│   │   ├── cron/
│   │   │   └── triggers.ts      # Cron handler (5 scheduled tasks)
│   │   └── index.ts             # Entry point, CORS, route mounting
│   ├── drizzle/                 # Generated migration snapshots
│   ├── wrangler.toml            # Worker config (KV, R2, Queues, Crons)
│   ├── drizzle.config.ts        # Drizzle Kit config (reads ../.env)
│   └── package.json
├── frontend/                    # React SPA
│   ├── src/
│   │   ├── components/layout/   # Sidebar (collapsible), Header (theme toggle), MainLayout
│   │   ├── context/             # AuthContext (login, Google login, logout), ThemeContext (dark/light/system)
│   │   ├── pages/
│   │   │   ├── LoginPage.jsx
│   │   │   ├── DashboardPage.jsx
│   │   │   ├── AssetsPage.jsx       # All assets — inventory + graph view
│   │   │   ├── MyAssetsPage.jsx     # Manual assets — add, import CSV, baseline
│   │   │   ├── DiscoveryPage.jsx    # Scan dispatch + discovered host panel
│   │   │   ├── AlertsPage.jsx       # Security events with severity/type filters
│   │   │   ├── AdvisoriesPage.jsx   # AI advisories with status filter
│   │   │   ├── ThreatIntelPage.jsx  # CTI indicators + MITRE heatmap
│   │   │   ├── ReportsPage.jsx      # Report generation + secure blob download
│   │   │   ├── SettingsPage.jsx     # Profile, password change, integrations
│   │   │   ├── TopologyPage.jsx
│   │   │   ├── AgentsPage.jsx       # Agent registry + RBAC config modal
│   │   │   └── TenantsPage.jsx      # SuperAdmin only
│   │   └── App.jsx
│   ├── .env.production          # VITE_API_URL + VITE_GOOGLE_CLIENT_ID (git-ignored)
│   └── package.json
├── agent/                       # EagleEye network scanning agent
│   ├── eagleeye_agent.py        # Poll → Nmap → ingest loop
│   ├── requirements.txt         # requests, python-nmap
│   └── README.md
├── data/
│   ├── test_assets_import.csv   # 28 sample assets for import testing
│   └── reports/
├── backend/                     # Legacy FastAPI backend (retained for reference)
├── deploy-workers.ps1           # One-shot full deployment script
├── .env                         # All secrets (git-ignored)
└── .env.example                 # Template for required variables
```

## Role-Based Access Control (RBAC)

| Role | Description |
|------|-------------|
| `superadmin` | Full platform access + tenant management |
| `ops_lead` | Full operational access — scans, assets, reports, advisories, agent config |
| `security_engineer` | Discovery, threat intel, drift management, advisory pipeline; read-only agent config |
| `mssp_analyst` | Read-only operational modules, advisories, posture reports |
| `business_owner` | Executive overview — posture metrics and executive reports only; read-only assets |

## EagleEye Agent

The agent is a lightweight Python script deployed on a host inside the target network.

### Setup

```bash
cd agent
pip install -r requirements.txt
```

### Usage

```bash
python eagleeye_agent.py \
  --api-url https://umeagleeye-api.syntaxch404.workers.dev/api/v1 \
  --api-key <key-from-dashboard> \
  --agent-id <uuid-from-dashboard>
```

Or via environment variables:

```bash
export EAGLEEYE_API_URL=https://umeagleeye-api.syntaxch404.workers.dev/api/v1
export EAGLEEYE_API_KEY=<key>
export EAGLEEYE_AGENT_ID=<uuid>
python eagleeye_agent.py
```

### Workflow

1. Agent polls `GET /scans/pending` every 30 seconds (sends heartbeat on each poll)
2. For each pending scan: runs `nmap -sV -T4` on the configured subnet
3. POSTs discovered hosts to `POST /scans/ingest`
4. Backend upserts assets and queues AI advisory generation for each discovered host

## Asset Import (CSV)

Tenants can bulk-import assets from a CSV file via **My Assets → Import CSV**.

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
- Port data is stored in `osInfo.ports` and included in baseline snapshots
- Download the template from within the Import modal

## Baseline Snapshots

Setting a baseline via **My Assets → Bookmark icon** captures a point-in-time snapshot of:

```json
{
  "os": { "name": "Ubuntu", "version": "22.04", "ports": ["22/tcp", "80/tcp", "443/tcp"] },
  "criticality_score": 8,
  "is_internet_facing": false,
  "hostname": "web-server-01",
  "captured_at": "2026-05-15T10:00:00.000Z"
}
```

The advisory worker (`drift_check` queue messages) compares incoming scan results against this snapshot to detect configuration drift.

## UI / UX

### Collapsible Sidebar

The sidebar can be toggled between expanded (256 px, icons + labels) and collapsed (64 px, icons only):

- Click the **`PanelLeft`** button in the top-left of the header bar to toggle at any time
- Click the **`ChevronLeft`** button inside the sidebar logo row to collapse
- When collapsed, all nav items show a native browser tooltip (the route label) on hover
- The main content area transitions smoothly with `transition-all duration-300`
- Collapsed state persists across page reloads via `localStorage('sidebar-collapsed')`

### Theme System

A three-way theme selector (Moon / Sun / Monitor icons) is in the header bar:

| Mode | Behaviour |
|------|-----------|
| `dark` | Default dark palette (dark-950 body, dark-900 surfaces) |
| `light` | Inverted light palette (white surfaces, near-black text) |
| `system` | Follows OS `prefers-color-scheme`; updates automatically |

**Implementation** — All `dark-XXX` Tailwind colours are backed by CSS custom properties (`--dark-50` … `--dark-950`) defined in `index.css`. Adding `html.light` class swaps every variable to its light-mode counterpart, so no JSX component needs conditional class logic. Preference persists via `localStorage('theme')`.

## Deployment

### Prerequisites
- [Node.js 18+](https://nodejs.org)
- [Cloudflare account](https://cloudflare.com) (free tier sufficient)
- [Neon account](https://neon.tech) (free tier sufficient)
- Cloudflare Queues `advisory-queue` and `report-queue` created
- Cloudflare R2 enabled and bucket `umeagleeye-reports` created
- Cloudflare KV namespace created

### First-time full deployment

```powershell
# 1. Copy and fill in all secrets
cp .env.example .env

# 2. Install Workers dependencies
cd workers && npm install && cd ..

# 3. Push database schema to Neon
cd workers && npx drizzle-kit push && cd ..

# 4. Deploy everything (secrets + Worker + frontend)
.\deploy-workers.ps1
```

The `deploy-workers.ps1` script:
1. Pushes all secrets from `.env` to Cloudflare Workers via `wrangler secret put`
2. Deploys the Worker to `https://umeagleeye-api.<subdomain>.workers.dev`
3. Updates `frontend/.env.production` with the Workers URL
4. Builds and deploys the frontend to Cloudflare Pages

### Redeploy after code changes

```powershell
# Worker only
cd workers && npx wrangler deploy

# Frontend only
cd frontend && npm run build
npx wrangler pages deploy dist --project-name umeagleeye-caasm

# Both (recommended)
.\deploy-workers.ps1
```

### Database schema changes

```powershell
cd workers
npx drizzle-kit push
```

## Environment Variables

See `.env.example` for the full list. Key variables:

| Variable | Description |
|----------|-------------|
| `DATABASE_URL` | Neon PostgreSQL connection string |
| `JWT_SECRET_KEY` | HS256 signing secret (min 32 chars) |
| `GOOGLE_CLIENT_ID` | Google OAuth Client ID |
| `OPENROUTER_API_KEY` | DeepSeek AI via OpenRouter |
| `TELEGRAM_BOT_TOKEN` | Telegram ChatOps bot token |
| `TELEGRAM_CHAT_ID` | Telegram chat/user ID for notifications |
| `OTX_API_KEY` | AlienVault OTX threat intelligence |
| `THREATFOX_API_KEY` | ThreatFox threat intelligence |
| `NVD_API_KEY` | NIST NVD vulnerability database |
| `CLOUDFLARE_API_TOKEN` | Cloudflare API token (for wrangler deployments) |

All variables are stored as **Cloudflare Workers secrets** (never in code). The frontend needs `VITE_API_URL` and `VITE_GOOGLE_CLIENT_ID` in `frontend/.env.production` (git-ignored; set by deploy script).

## Local Development

```powershell
# Backend (Workers dev server — proxies to Neon)
cd workers && npx wrangler dev

# Frontend
cd frontend
cp .env.example .env.local
# Set VITE_API_URL=http://localhost:8787/api/v1
npm run dev
```

> The legacy `backend/` directory (FastAPI/Python/Docker) is retained for reference but is no longer the active backend.

---

*Final Year Project — University of Malaya, Faculty of Computer Science & Information Technology*
*Supervisor: Dr. Badrul Hisham*
