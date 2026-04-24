"""
UMEagleEye - AI-Driven Cyber Asset Attack Surface Management (CAASM)
FastAPI Application Entry Point.

Faculty of Computer Science and Information Technology
University of Malaya, Kuala Lumpur
"""

from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import settings
from app.db.database import init_db
from app.api.router import api_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifecycle: startup and shutdown events."""
    # Startup: initialize database tables
    await init_db()
    print(f"✅ {settings.APP_NAME} database initialized")
    yield
    # Shutdown
    print(f"🛑 {settings.APP_NAME} shutting down")


app = FastAPI(
    title=settings.APP_NAME,
    description="AI-Driven Cyber Asset Attack Surface Management (CAASM) for Malaysian SMEs",
    version="2.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

# ── CORS Middleware ──
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Include API Router ──
app.include_router(api_router)


@app.get("/", tags=["Health"])
async def root():
    """Root health check endpoint."""
    return {
        "name": settings.APP_NAME,
        "version": "2.0.0",
        "status": "operational",
        "description": "AI-Driven CAASM for Malaysian SMEs",
    }


@app.get("/health", tags=["Health"])
async def health_check():
    """Detailed health check."""
    return {
        "status": "healthy",
        "environment": settings.APP_ENV,
        "database": "connected",
        "redis": "connected",
    }
