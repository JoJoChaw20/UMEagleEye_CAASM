# Project 1 Detail — AI-Driven Cyber Asset Attack Surface Management (CAASM)

## Project Overview
Small and Medium Enterprises (SMEs) are the backbone of Malaysia's digital economy but remain highly vulnerable due to four critical "Blind Spots": Inventory Drift, Alert Fatigue, the Context Gap, and the Expertise Gap. This project develops **UMEagleEye 2.0**, a unified Cyber Asset Attack Surface Management (CAASM) platform.

The system acts as a "Digital Iron Dome" for the Malaysian SME landscape. It provides automated asset discovery, vulnerability mapping, and AI-assisted strategic feedback. By integrating threat intelligence from AlienVault OTX and ThreatFox with MITRE ATT&CK mapping and leveraging AI as a "Virtual Senior Analyst" via DeepSeek, UMEagleEye 2.0 enables lean IT teams to defend against enterprise-grade threats without enterprise-grade budgets.

## Live Deployment
| Service | URL |
|---------|-----|
| Frontend (Cloudflare Pages) | https://umeagleeye.pages.dev |
| Frontend (University Domain) | https://umeagleeye.csnet.my |
| Backend API (Cloudflare Workers) | https://umeagleeye-api.syntaxch404.workers.dev/api/v1 |

## Key Technologies
- **CAASM Core:** Serverless edge backend (Cloudflare Workers + Hono/TypeScript), agentless-first asset discovery, SBOM generation, and real-time asset inventory.
- **Localized CTI:** AlienVault OTX and ThreatFox integration with full MITRE ATT&CK tactic derivation (planned MyCERT STIX/TAXII pipeline via environment config).
- **AI Strategic Advisory:** DeepSeek LLM via OpenRouter API for prescriptive, queue-driven security remediation.
- **Proactive Defense:** Automated "Golden Image" baseline enforcement, drift detection, and composite CVE risk scoring.

## Architecture Overview

### Backend — Cloudflare Workers (Active)
- **Runtime:** Cloudflare Workers (serverless edge, TypeScript)
- **Framework:** Hono 4
- **Database:** Neon PostgreSQL (serverless HTTP protocol) with Drizzle ORM
- **Auth:** JWT (jose), PBKDF2 Web Crypto, TOTP 2FA, Google OAuth
- **Async Jobs:** Cloudflare Queues (advisory generation, PDF reports)
- **Scheduled Tasks:** 5 Cloudflare Cron Triggers (drift audit every 15 min, SLA monitor every 30 min, CTI ingestion 6:00 AM MYT, NVD update 7:00 AM MYT, posture snapshot midnight MYT)
- **Storage:** Cloudflare R2 (PDF reports), Cloudflare KV (rate-limit locks)
- **AI:** DeepSeek V4 Pro via OpenRouter (`deepseek/deepseek-v4-pro`) — advisory generation and chatbot; direct DeepSeek API also supported via `DEEPSEEK_API_KEY`

### Agent — Python 3.10+
- **Active Scanning:** Nmap (`-sV -T4`) with NSE scripts (`smb-os-discovery`, `banner`); polls backend every 30 s
- **Passive Scanning:** Three parallel Scapy sniffers (ARP host discovery, mDNS/NetBIOS-NS hostname resolution, DHCP device classification); auto-flushes every 60 s
- **SBOM/CVE:** Syft (CycloneDX v1.5) + Grype pipeline; triggered from dashboard
- **Heartbeat:** 30 s keepalive to maintain Online status

### Frontend — React SPA
- **Stack:** React 18.3.1 + Vite 5.4.5 + Tailwind CSS 3.4.11
- **Charts:** Recharts 2.12.7 (posture trend, severity pie, dependency bar chart)
- **Routing:** React Router DOM 6.26.2 (16 pages)
- **Theme:** Dark / Light / System with CSS custom property tokens

### Legacy Backend (Reference Only)
- FastAPI 0.115 + SQLAlchemy 2.0 + asyncpg, Celery + Redis, pgvector (RAG embeddings)
- Retained for reference; all production traffic served by Cloudflare Workers

---

## Project Breakdown (2 Students)

### Student 1: Discovery, Intelligence & Risk Engine
**Objective:** Eliminate the "Inventory Drift" and "Context Gap" blind spots by building a comprehensive visibility engine and threat correlation pipeline.

**Key Responsibilities:**

**Hybrid Discovery Engine**
- Develop the EagleEye Python agent with both Active (Nmap) and Passive (Scapy) scanning modes.
- Active mode: Nmap `-sV -T4` with NSE scripts for service and OS detection across 14 key ports (SSH, HTTP/S, SMB, RDP, databases).
- Passive mode: Three parallel daemon sniffers — ARP (host discovery), mDNS/NetBIOS-NS (hostname resolution), DHCP (device classification via options 12/60/55).
- MAC vendor OUI lookup via `api.macvendors.com`.
- Fingerbank API integration for DHCP-based device fingerprinting.

**Asset Management & Drift Detection**
- Design and implement the `assets` database schema with criticality scoring, baseline snapshots, and source hierarchy (manual > scan_active > scan_passive).
- Build the "Golden Image" auditor: baseline comparison logic that generates drift events (`port_opened`, `port_closed`, `config_change`) on deviation.
- CSV bulk import with IP-level upsert per tenant.

**SBOM Generation & CVE Correlation**
- Integrate Syft (CycloneDX v1.5 JSON) for automated Software Bill of Materials generation.
- Integrate Grype for automatic post-SBOM CVE scanning; filter low-signal findings (Unknown/Negligible severity, CVSS < 4.0 unless vendor-marked High/Critical).
- EPSS enrichment via FIRST.org batch API.

**Composite Risk Scoring Engine**
- Implement the multi-factor risk formula:
  ```
  score = (CVSS × 10 × 0.40)      # 40% — exploitability
        + (EPSS × 100 × 0.35)     # 35% — exploit probability
        + (Criticality × 10 × 0.15) # 15% — asset impact
        + (CTI match ? 10 : 0)    # flat 10 pts for active threat overlap
  score = min(score, 100)
  ```
- CTI enrichment: cross-reference CVE IDs against live threat intelligence table.

**Threat Intelligence Pipeline**
- Build the CTI ingestion service for AlienVault OTX (50 latest pulses) and ThreatFox (last 7 days IoCs); scheduled daily at 6:00 AM MYT.
- Full MITRE ATT&CK tactic derivation via three-level cascade:
  1. **Authoritative** — `attack_ids[0].name` technique code mapped to tactic (~150 entries, all 14 MITRE tactics)
  2. **Tag-based** — Free-text pulse tags (e.g., `"ransomware"`, `"botnet"`) mapped to tactic (~30 entries)
  3. **Type default** — Indicator type fallback (IP → C2, domain → C2, URL → Initial Access, hash → Execution)
- Real-time IoC Lookup: cross-reference IP/domain/hash/URL/email against internal assets.
- NVD API integration for daily CVE feed (7:00 AM MYT).

**Network Topology & Relationship Graph**
- Build the relationship inference engine: automatic parent assignment (same-subnet, cross-subnet, fallback to gateway).
- BFS blast-radius analysis for impact propagation.
- Subnet-aware topology classification (gateway → router → switch → access_point → host).

**Skills:** Network Security, Python 3 (Scapy, python-nmap), Cyber Threat Intelligence, MITRE ATT&CK, CVE/NVD API, EPSS API, SBOM standards (CycloneDX), TypeScript (Hono route handlers for scan/CTI/SBOM APIs).

---

### Student 2: AI Advisory, Platform & Visualization
**Objective:** Close the "Expertise Gap" and "Alert Fatigue" blind spots by building the AI advisory brain, the serverless platform backbone, and the executive-facing dashboard.

**Key Responsibilities:**

**Serverless Platform Architecture**
- Design and deploy the Cloudflare Workers backend (Hono/TypeScript) with Neon PostgreSQL and Drizzle ORM.
- Implement the full 14-table database schema (tenants, users, assets, sboms, dependencies, events, ctiIndicators, advisories, postureMetrics, assetRelationships, auditLogs, bridges, agents, topologyNodes).
- Configure Cloudflare Queues (advisory-queue, report-queue), KV, R2 storage, and 5 Cron Triggers.
- PowerShell deployment pipeline (`deploy-workers.ps1`): secrets management → Worker deploy → Pages build.

**Authentication & Multi-Tenant RBAC**
- Implement JWT auth (jose HS256), PBKDF2 password hashing (Web Crypto API, 100k iterations), TOTP 2FA (otplib).
- TOTP setup flow: `POST /mfa/setup` generates secret + SVG QR code (module-matrix rect approach — no canvas, Workers-compatible); `POST /mfa/enable` activates MFA after first code verification; `POST /mfa/verify` issues JWT at login. Settings page includes manual secret copy fallback for users who cannot scan the QR.
- Google OAuth sign-in with email-based account linking.
- Four-role RBAC: `superadmin`, `tenant_superadmin`, `tenant_admin`, `business_owner` with centralised `permissions.ts` and route-level `requireRoles()` / `requireTenantAccess()` guards.
- Full multi-tenant data partitioning: `superadmin` manages the platform; `tenant_superadmin` self-manages their own tenant (invite/assign users, edit tenant name/status).

**AI Strategic Advisory Pipeline**
- Integrate DeepSeek (direct API or via OpenRouter) for prescriptive remediation generation.
- Async queue-driven pipeline: advisory-queue with max 10 batch size, 30 s timeout, 2 retries.
- Advisory lifecycle management: `open → in_progress → acknowledged → resolved` with analyst assignment.
- SLA monitoring: alerts for advisories open > 72 h (checked every 30 min via Cron).

**AI Security Chatbot**
- Build the `/chatbot` route and `ChatbotPage` — natural language interface for all roles.
- Structured intent detection: `status`, `posture`, `assets`, `alerts`, `advisories`, `debug`, `fix` commands; free-text falls through to DeepSeek with live context injection (posture score, top 3 critical alerts, top 5 open/in-progress advisories with recommended actions).
- SSE streaming: Worker uses `TransformStream` to pipe OpenRouter tokens back to the client; frontend reads with native fetch `ReadableStream` reader; responses appear word-by-word and the 30-second Worker wall-clock limit is never reached (`max_tokens: 2048`).
- Multi-session conversation history: `ChatbotContext` at app root holds sessions and active session ID; state persists to localStorage keyed by user ID; survives page navigation and browser refresh (up to 50 messages per session).
- Advisory debug sessions: selecting an advisory from the sidebar opens a dedicated session; streaming continues even if the user navigates away mid-response.
- `fix <advisory_id>` resolves an advisory directly from the chat interface.
- Role-filtered: `business_owner` limited to `status` and `posture`; advisory fix requires `tenant_admin` or above.
- Dual AI backend: `DEEPSEEK_API_KEY` (direct) takes priority; falls back to `OPENROUTER_API_KEY`; current model `deepseek/deepseek-v4-pro`.
- Rich markdown rendering: `MarkdownBody` React component handles bold, inline code pill badges (theme-aware colour), bullet lists, and paragraph spacing — no `dangerouslySetInnerHTML`.

**Security Posture Scoring**
- Build the posture score calculation engine: starts at 100, deducts (critical × 5 capped at −40) + (high × 2 capped at −20) + (−10 if >20% of assets have criticality ≥ 8); minimum score 0.
- Posture score is computed live on demand from the `events` and `assets` tables — no stale cached value.
- 30-day history reconstructed per-day from the same formula applied to data that existed up to the end of each day.
- Drift audit every 15 min via Cron; 24-hour deduplication prevents flooding on repeated comparisons.

**Executive Dashboard & Visualization**
- Build the React SPA (16 pages) with Tailwind CSS dark/light/system themes; theme driven entirely by CSS custom properties — no JSX conditional logic.
- Security Posture Dashboard: 4 stat cards (posture score 0–100 with colour thresholds, total assets, critical alerts count, critical assets count); 30-day posture trend area chart; threat distribution donut sourced from full event history via `GET /events/stats/summary`; 10-row recent events table.
- Alerts Dashboard: 4 stat cards (total alerts, critical count, advisory resolution rate, avg composite risk score for CVE events); severity breakdown donut; 7-day alerts trend area chart with zero-fill for missing days; alert types horizontal bar chart; paginated events table with CVSS/EPSS/Risk Score columns, per-event advisory button (green dot badge when advisory exists), and drift acknowledge action.
- SBOM Dependency Explorer: per-package-manager breakdown with bar chart.
- MITRE ATT&CK heatmap: tactic coverage visualization with technique IDs and indicator counts.
- Collapsible network topology tree with DMZ badges and criticality colour coding.
- Force-directed asset relationship graph (canvas) with BFS blast-radius highlighting.

**Reporting & ChatOps**
- Automated PDF report generation queued via Cloudflare Queue; secure blob download via R2 (no token in URL).
- In-app Notification Centre with unread badge; aggregates advisories, SLA breaches (>72 h), and agent status.

**Agent Management & Bridge Infrastructure**
- Agent registry with SHA-256 API key verification and heartbeat-based Online/Offline/Degraded status.
- Bridge relay server endpoints for agents on isolated/NAT networks.
- AI-driven asset classification: DeepSeek analyzes discovered hosts for human-readable description and Accept/Ignore/Investigate recommendations.

**Skills:** AI/LLM Integration (DeepSeek/OpenRouter, multi-turn chatbot), Serverless Architecture (Cloudflare Workers/Pages/Queues/R2/KV), TypeScript (Hono), Drizzle ORM, React 18 (Tailwind CSS, Recharts), JWT/OAuth/TOTP, PostgreSQL (Neon), RBAC design (`permissions.ts`, `requireTenantAccess()`).

---

## Project Benefits to Students
- **Sovereign Technology:** Contribute to a Malaysian cybersecurity solution aligned with the national digital economy agenda.
- **Advanced Frameworks:** Hands-on experience with MITRE ATT&CK, CycloneDX SBOM standards, EPSS exploit scoring, and AI-driven security operations (AIOps).
- **Production-Grade Deployment:** Real serverless architecture on Cloudflare (Workers, Pages, Queues, R2, KV, Cron) with a live university subdomain (`umeagleeye.csnet.my`).
- **Pilot Validation:** Tested within the JTM UM operational environment with realistic multi-tenant datasets.

## Programming Languages & Tools
| Category | Technologies |
|----------|-------------|
| **Backend** | TypeScript (Hono 4), Cloudflare Workers, Drizzle ORM, Neon PostgreSQL |
| **Agent** | Python 3.10+, Scapy, python-nmap, Syft, Grype |
| **Frontend** | React 18, Vite 5, Tailwind CSS 3, Recharts, React Router 6, React Context API (Auth / Theme / Chatbot) |
| **AI/LLM** | DeepSeek (direct API or via OpenRouter) |
| **Intelligence** | AlienVault OTX API, ThreatFox (abuse.ch) API, NVD/CVE API, FIRST.org EPSS API |
| **Auth** | JWT (jose), TOTP (otplib), Google OAuth, PBKDF2 Web Crypto |
| **Infrastructure** | Cloudflare Workers/Pages/Queues/R2/KV, Neon PostgreSQL, Docker (dev/legacy) |
| **SBOM** | Syft (CycloneDX v1.5), Grype |
| **Network** | Nmap, Scapy (ARP/mDNS/DHCP sniffing), MAC OUI API, Fingerbank API |

## Conclusion
Student 1 builds the **Eyes & Memory** (Discovery + SBOM + CVE + CTI + MITRE correlation), and Student 2 builds the **Brain & Voice** (AI Advisory + Serverless Platform + Executive Dashboard). Together, they deliver a production-deployed "Digital Iron Dome" that is technically sophisticated yet operationally accessible for Malaysian SMEs — running live at `umeagleeye.csnet.my`.
