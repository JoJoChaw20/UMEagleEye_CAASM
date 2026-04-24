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

*(Further instructions on how to set up the environment, database, and run both the backend and frontend servers locally will be added here.)*
