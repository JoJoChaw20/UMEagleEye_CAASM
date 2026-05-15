# UMEagleEye 2.0 — AI-Driven CAASM Platform

UMEagleEye is an AI-Driven **Cyber Asset Attack Surface Management (CAASM)** platform developed as a Final Year Project at the Faculty of Computer Science & Information Technology, University of Malaya. It provides comprehensive visibility into cyber assets, automates threat detection, delivers intelligent remediation guidance, and generates automated posture scoring and reporting — all hosted serverlessly with no always-on infrastructure.

## Live Deployment

| Service | URL |
|---------|-----|
| Frontend | https://umeagleeye.pages.dev |
| Backend API | https://umeagleeye-api.syntaxch404.workers.dev/api/v1 |

## Core Features

- **Asset Inventory (My Assets)** — Manual asset registry with criticality scoring, baseline snapshots, and drift detection
- **Network Discovery** — EagleEye scanning agents push Nmap/Masscan scan results to the platform; discovered hosts can be promoted to the asset registry
- **Network Topology** — Interactive tree view (gateway → router → switch → host) with BFS-based relationship inference
- **Continuous Posture Management** — Automated drift detection and ongoing posture scoring tracked over time
- **Threat Intelligence Integration** — Ingests live feeds (AlienVault OTX, ThreatFox, NVD) to identify vulnerable assets proactively
- **AI-Driven Advisory Pipeline** — DeepSeek (via OpenRouter) generates actionable remediation instructions for security events
- **Asset Relationship Graph** — Visualises asset dependencies and lateral movement blast-radius via BFS
- **Automated Reporting** — Queued PDF report generation stored in Cloudflare R2
- **ChatOps Integration** — Telegram bot with role-based filtering and real-time security alerts
- **Multi-Tenant Support** — SuperAdmin role manages multiple tenant organisations; all data scoped by tenant
- **Agent Management** — Register and monitor EagleEye scanning agents; SHA-256 hashed API keys
- **MFA / TOTP** — Per-user two-factor authentication via authenticator apps
- **Google OAuth** — Sign in with Google; auto-links to existing account by email

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
| Styling | Tailwind CSS |
| State | React Context API |
| HTTP | Axios |
| Charts | Recharts |
| Icons | Lucide React |
| Google Login | @react-oauth/google |

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
                    └── HTTPS POST /scans/ingest ──► Workers
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
│   │   │   ├── assets.ts        # Asset CRUD + baseline
│   │   │   ├── scans.ts         # Trigger scan, agent ingest, status
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
│   │   ├── components/layout/   # Sidebar, Navbar
│   │   ├── context/             # AuthContext (login, Google login, logout)
│   │   ├── pages/               # All page views
│   │   │   ├── LoginPage.jsx
│   │   │   ├── DashboardPage.jsx
│   │   │   ├── MyAssetsPage.jsx
│   │   │   ├── DiscoveryPage.jsx
│   │   │   ├── TopologyPage.jsx
│   │   │   ├── AgentsPage.jsx
│   │   │   └── TenantsPage.jsx  # SuperAdmin only
│   │   └── App.jsx
│   ├── .env.production          # VITE_API_URL + VITE_GOOGLE_CLIENT_ID (git-ignored)
│   └── package.json
├── backend/                     # Legacy FastAPI backend (retained for reference)
├── deploy-workers.ps1           # One-shot full deployment script
├── .env                         # All secrets (git-ignored)
└── .env.example                 # Template for required variables
```

## Role-Based Access Control (RBAC)

| Role | Description |
|------|-------------|
| `superadmin` | Full platform access + tenant management |
| `ops_lead` | Full operational access — scans, assets, reports, advisories |
| `security_engineer` | Discovery, threat intel, drift management, advisory pipeline |
| `mssp_analyst` | Read-only operational modules, advisories, posture reports |
| `business_owner` | Executive overview — posture metrics and executive reports only |

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

# Both
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
