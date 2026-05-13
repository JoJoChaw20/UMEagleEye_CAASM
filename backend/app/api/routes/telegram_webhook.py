"""
UMEagleEye - FastAPI Telegram Webhook Route.

Receives inbound Telegram updates via POST /api/v1/telegram/webhook.
Verifies the X-Telegram-Bot-Api-Secret-Token header, then dispatches
the Update to the bot application (webhook mode — no polling).

Flow (diagram layer: Trigger sources → Auth + routing):
  Telegram servers → POST /webhook → FastAPI → bot.process_update()
"""

import logging
import json

from fastapi import APIRouter, Request, Response, HTTPException, Header
from telegram import Update
from telegram.ext import Application

from app.core.config import settings

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/telegram", tags=["Telegram"])

import asyncio

# Module-level bot application — initialised lazily on first request
_bot_app: Application | None = None
_init_lock = asyncio.Lock()


async def _get_bot_app() -> Application:
    """Lazily build and initialise the PTB Application (webhook mode)."""
    global _bot_app
    async with _init_lock:
        if _bot_app is None:
            # Import here to avoid circular imports
            from app.bot.telegram_bot import build_application
            _bot_app = build_application()
            await _bot_app.initialize()
            # In webhook mode, we also need to call start() to prepare the app
            await _bot_app.start()
            logger.info("Telegram bot application initialised and started (webhook mode).")
    return _bot_app


@router.post("/webhook")
async def telegram_webhook(
    request: Request,
    x_telegram_bot_api_secret_token: str = Header(default=""),
):
    """
    Receive a Telegram Update payload.

    Telegram sends a secret token header when the webhook is registered with
    `secret_token` — we verify it to reject spoofed requests.
    """
    # ── Secret token verification ──────────────────────────────────
    expected = settings.TELEGRAM_WEBHOOK_SECRET
    if expected and x_telegram_bot_api_secret_token != expected:
        logger.warning("Webhook received with invalid secret token — rejected.")
        raise HTTPException(status_code=403, detail="Invalid secret token")

    # ── Parse Update ───────────────────────────────────────────────
    try:
        body = await request.body()
        data = json.loads(body)
        update = Update.de_json(data, (await _get_bot_app()).bot)
    except Exception as exc:
        logger.error(f"Failed to parse Telegram update: {exc}")
        raise HTTPException(status_code=400, detail="Bad request")

    # ── Dispatch to bot handlers ───────────────────────────────────
    try:
        app = await _get_bot_app()
        await app.process_update(update)
    except Exception as exc:
        logger.error(f"Error processing Telegram update: {exc}")
        # Always return 200 to Telegram — otherwise it will retry forever
        return Response(status_code=200)

    return Response(status_code=200)


@router.get("/webhook/info", tags=["Telegram"])
async def webhook_info():
    """Return current webhook registration status (admin diagnostic)."""
    if not settings.TELEGRAM_BOT_TOKEN:
        return {"configured": False}

    import httpx
    url = f"https://api.telegram.org/bot{settings.TELEGRAM_BOT_TOKEN}/getWebhookInfo"
    async with httpx.AsyncClient() as client:
        resp = await client.get(url, timeout=10)
    return resp.json()
