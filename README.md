# UMEagleEye CAASM

UMEagleEye is an AI-Driven Cyber Asset Attack Surface Management (CAASM) platform. It provides comprehensive visibility into cyber assets, automates threat detection, offers intelligent remediation guidance, and generates automated posture scoring and reporting.

This project was developed as a Final Year Project (FYP) to provide advanced security posture management capabilities for SMEs and enterprise environments.

## Core Features

- **Comprehensive Asset Discovery:** Aggregates and correlates data across various sources to provide a unified asset inventory.
- **Continuous Posture Management:** Automated drift detection and ongoing posture scoring to track security health.
- **Threat Intelligence Integration:** Ingests live threat feeds (e.g., AlienVault OTX) to identify vulnerable assets proactively.
- **AI-Driven Advisory Pipeline:** Leverages Google Gemini and RAG (Retrieval-Augmented Generation) to deliver actionable remediation instructions.
- **Automated Reporting:** Generates detailed PDF reports for executive stakeholders.
- **ChatOps Integration:** Telegram bot support for real-time security alerts and operations.

## Technology Stack

### Backend
- **Framework:** Python, FastAPI
- **Task Queue:** Celery for asynchronous background tasks
- **Database Architecture:** SQLAlchemy ORM, Database models & migrations
- **Threat Intel & AI:** Integrated with AlienVault OTX and Google Gemini

### Frontend
- **Framework:** React (Vite)
- **Styling:** Tailwind CSS for a modern, responsive UI
- **State Management:** React Context API (AuthContext, etc.)

## Project Structure

```
UMEagleEye2.0/
├── backend/
│   ├── app/
│   │   ├── api/       # API Routes (CTI, Advisories, etc.)
│   │   ├── core/      # Config, dependencies, security
│   │   ├── db/        # Database models and session management
│   │   ├── schemas/   # Pydantic schemas for data validation
│   │   ├── services/  # Core business logic (Threat Intel, Posture, etc.)
│   │   └── tasks/     # Celery background tasks
│   └── requirements.txt
└── frontend/
    ├── src/
    │   ├── components/# Reusable UI components
    │   ├── context/   # Context providers
    │   ├── pages/     # Page views (Dashboard, DriftPage, AssetsPage, etc.)
    │   └── index.css  # Global styles
    ├── package.json
    └── tailwind.config.js
```

## Getting Started

### Prerequisites
- Docker and Docker Compose installed on your machine.

### Initial Setup Process
1. **Environment Configuration**
   Copy the example environment file and configure the necessary keys:
   ```bash
   cp .env.example .env
   ```
   *Note: Open `.env` and fill in your specific credentials such as `GEMINI_API_KEY`, `TELEGRAM_BOT_TOKEN`, and `NVD_API_KEY` for full functionality.*

2. **Run the System with Docker Compose**
   Build and start all the services using Docker Compose:
   ```bash
   docker-compose up --build -d
   ```
   This command provisions the following containers:
   - PostgreSQL 15 database (pgvector enabled)
   - Redis 7
   - FastAPI Backend (`localhost:8000`)
   - Celery Worker & Beat (background tasks and scheduling)
   - Telegram Bot
   - React Vite Frontend (`localhost:5173`)

3. **Access the Application**
   - **Frontend UI:** [http://localhost:5173](http://localhost:5173)
   - **API Documentation (Swagger UI):** [http://localhost:8000/docs](http://localhost:8000/docs)

---

## Role-Based Access Control (RBAC) & User Interaction

UMEagleEye enforces a strict RBAC architecture to ensure proper segregation of duties across different personas interacting with the system.

### User Registration Flow
1. **Registration:** Users create an account through the `/auth/register` API endpoint.
2. **Role Assignment:** By default, new users are assigned the `BUSINESS_OWNER` role. Alternatively, a specific role can be explicitly defined in the registration payload.
3. **Authentication:** Users authenticate via `/auth/login` to obtain a JWT access token. 
4. **MFA (Optional but Recommended):** Users can establish Multi-Factor Authentication via `/auth/mfa/setup` to receive a TOTP secret/QR code, and activate it via `/auth/mfa/enable`.

### Roles & Capabilities
The system leverages JWT claims to enforce role-based API access across endpoints:

- **Ops Lead (`ops_lead`)**
  - **Interaction:** Administrative level. Can manage the entire lifecycle.
  - **Capabilities:** Execute network scans, manage all assets, view comprehensive reports, and assign/resolve AI-driven advisories.

- **Security Engineer (`security_engineer`)**
  - **Interaction:** Operational security level. 
  - **Capabilities:** Trigger discovery scans, interact with threat intelligence data, review asset drifts, and manage advisory pipelines.

- **MSSP Analyst (`mssp_analyst`)**
  - **Interaction:** External consultant/auditor level.
  - **Capabilities:** Read-only access to specific operational modules. Capable of viewing advisories and generating/viewing posture reports without altering configurations or triggering network scans.

- **Business Owner (`business_owner`)**
  - **Interaction:** Executive overview level.
  - **Capabilities:** Restricted to high-level posture metrics, overall scoring, and executive reporting. Cannot access underlying asset discovery or vulnerability scan execution endpoints.
