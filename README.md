# UMEagleEye 2.0 — AI-Driven CAASM Platform

UMEagleEye is an AI-Driven Cyber Asset Attack Surface Management (CAASM) platform developed as a Final Year Project at the Faculty of Computer Science & Information Technology, University of Malaya. It provides comprehensive visibility into cyber assets, automates threat detection, delivers intelligent remediation guidance, and generates automated posture scoring and reporting.

## Live Deployment

| Service | URL |
|---------|-----|
| Frontend | https://umeagleeye.pages.dev |
| API Docs | Tunnel URL + `/docs` (see `.tunnel-url` file) |

## Core Features

- **Comprehensive Asset Discovery** — Aggregates and correlates data across sources to provide a unified asset inventory using Nmap, Masscan, Syft, and Grype.
- **Continuous Posture Management** — Automated drift detection and ongoing posture scoring to track security health over time.
- **Threat Intelligence Integration** — Ingests live threat feeds (AlienVault OTX, TAXII 2.0, ThreatFox, NVD) to identify vulnerable assets proactively.
- **AI-Driven Advisory Pipeline** — Leverages DeepSeek (via OpenRouter) with RAG (pgvector + FastEmbed) to deliver actionable remediation instructions.
- **SBOM Analysis** — Software Bill of Materials generation and vulnerability correlation via Syft + Grype.
- **Asset Relationship Graph** — Visualises asset dependencies and lateral movement paths.
- **EPSS Integration** — Dynamic threat mapping with Exploit Prediction Scoring System scores.
- **Automated Reporting** — Generates detailed PDF reports for executive stakeholders via ReportLab and Google Cloud Storage.
- **ChatOps Integration** — Telegram bot with role-based filtering and real-time security alerts.

## Technology Stack

### Backend
- **Framework:** Python 3.12, FastAPI (async), Uvicorn
- **Task Queue:** Celery + Redis (async workers + Beat scheduler)
- **Database:** PostgreSQL 15 with pgvector extension (vector embeddings for RAG)
- **ORM:** SQLAlchemy (asyncio)
- **AI / RAG:** DeepSeek via OpenRouter API, FastEmbed
- **Scanning Tools:** Nmap, Masscan, Syft, Grype
- **Threat Intel:** AlienVault OTX, TAXII 2.0, ThreatFox, NVD API
- **Auth:** JWT (PyJWT), TOTP/MFA (pyotp), Bcrypt
- **Storage:** Google Cloud Storage, AWS S3 (boto3)
- **Notifications:** Telegram Bot API

### Frontend
- **Framework:** React 18 + Vite
- **Styling:** Tailwind CSS
- **State Management:** React Context API
- **HTTP Client:** Axios
- **Charts:** Recharts

### Infrastructure
- **Containerisation:** Docker + Docker Compose
- **Message Broker:** Redis 7
- **CDN / Hosting:** Cloudflare Pages (frontend), Cloudflare Quick Tunnel (backend)

## Project Structure

```
UMEagleEye2.0/
├── backend/
│   ├── app/
│   │   ├── api/         # REST API routes
│   │   ├── core/        # Config, dependencies, security
│   │   ├── db/          # Models, enums, database session
│   │   ├── schemas/     # Pydantic validation schemas
│   │   ├── services/    # Business logic (discovery, threat intel, reports, etc.)
│   │   ├── tasks/       # Celery background tasks
│   │   └── bot/         # Telegram bot
│   ├── Dockerfile
│   └── requirements.txt
├── frontend/
│   ├── src/
│   │   ├── api/         # Axios client
│   │   ├── components/  # Reusable UI components
│   │   ├── context/     # Auth context
│   │   └── pages/       # Page views
│   ├── Dockerfile
│   └── package.json
├── docker-compose.yml       # Local development
├── docker-compose.prod.yml  # Production overrides
├── deploy.ps1               # One-shot Cloudflare deployment script
├── redeploy-frontend.ps1    # Re-deploy frontend after tunnel URL change
└── .env                     # Environment variables (git-ignored)
```

## Getting Started (Local Development)

### Prerequisites
- Docker Desktop
- Node.js 18+ and npm

### Setup

1. **Configure environment variables**
   ```powershell
   cp .env.example .env
   # Edit .env and fill in: OPENROUTER_API_KEY, TELEGRAM_BOT_TOKEN, NVD_API_KEY, etc.
   ```

2. **Start all services**
   ```powershell
   docker compose up --build -d
   ```
   This starts:
   - PostgreSQL 15 + pgvector (`localhost:5432`)
   - Redis 7 (`localhost:6379`)
   - FastAPI backend (`localhost:8000`)
   - Celery Worker + Beat
   - React Vite frontend (`localhost:5173`)

3. **Access the application**
   - **Frontend UI:** http://localhost:5173
   - **API Docs (Swagger):** http://localhost:8000/docs

4. **Create your first user** via Swagger UI at `/api/v1/auth/register` or the API directly:
   ```bash
   curl -X POST http://localhost:8000/api/v1/auth/register \
     -H "Content-Type: application/json" \
     -d '{"username":"admin","email":"admin@example.com","password":"yourpassword","role":"ops_lead"}'
   ```

## Production Deployment (Cloudflare)

The frontend is hosted on **Cloudflare Pages** and the backend is exposed via **Cloudflare Quick Tunnel** — no domain required.

### First-time deployment

```powershell
.\deploy.ps1
```

This script will:
1. Start Docker Compose backend services (db, redis, backend, celery-worker, celery-beat)
2. Start a Cloudflare Quick Tunnel → assigns a `*.trycloudflare.com` URL
3. Build the React frontend with that URL as `VITE_API_URL`
4. Deploy frontend to Cloudflare Pages (opens browser for one-time Cloudflare login)

**Result:** Frontend live at `https://umeagleeye.pages.dev`

### After restarting cloudflared (tunnel URL changes)

The Quick Tunnel URL changes on restart. Run:
```powershell
.\redeploy-frontend.ps1
```
This gets the new URL and redeploys the frontend in ~30 seconds.

### Custom project name

```powershell
.\deploy.ps1 -ProjectName myapp
# Frontend will be at https://myapp.pages.dev
```

---

## Role-Based Access Control (RBAC)

UMEagleEye enforces RBAC with four personas:

| Role | Capabilities |
|------|-------------|
| `ops_lead` | Full administrative access — scans, assets, reports, advisories |
| `security_engineer` | Discovery scans, threat intelligence, drift management, advisory pipeline |
| `mssp_analyst` | Read-only access to operational modules, view advisories and posture reports |
| `business_owner` | Executive overview — high-level posture metrics and executive reporting only |

### User Registration Flow
1. Register via `/api/v1/auth/register` (role defaults to `business_owner` if not specified)
2. Authenticate via `/api/v1/auth/login` to receive a JWT access token
3. Optionally enable MFA via `/api/v1/auth/mfa/setup` → `/api/v1/auth/mfa/enable`

---

## Environment Variables

Key variables in `.env` (see `.env.example` for full reference):

| Variable | Description |
|----------|-------------|
| `DATABASE_URL` | PostgreSQL async connection string |
| `REDIS_URL` | Redis connection string for Celery |
| `JWT_SECRET_KEY` | Secret for signing JWT tokens |
| `OPENROUTER_API_KEY` | DeepSeek AI via OpenRouter |
| `TELEGRAM_BOT_TOKEN` | Telegram ChatOps bot |
| `OTX_API_KEY` | AlienVault OTX threat intelligence |
| `NVD_API_KEY` | NIST NVD vulnerability database |
| `GCS_BUCKET_NAME` | Google Cloud Storage bucket for PDF reports |
| `BACKEND_CORS_ORIGINS` | Comma-separated allowed origins (includes Pages URL in production) |
