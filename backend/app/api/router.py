"""
UMEagleEye - Main API router aggregating all sub-routers.
"""

from fastapi import APIRouter

from app.api.routes import auth, assets, scans, events, advisories, posture, cti, reports, relationships, telegram_webhook

api_router = APIRouter(prefix="/api/v1")

api_router.include_router(auth.router)
api_router.include_router(assets.router)
api_router.include_router(scans.router)
api_router.include_router(events.router)
api_router.include_router(advisories.router)
api_router.include_router(posture.router)
api_router.include_router(cti.router)
api_router.include_router(reports.router)
api_router.include_router(relationships.router)
api_router.include_router(telegram_webhook.router)

