"""
UMEagleEye - Telegram Bot with full ChatOps (FR-05-03, FR-05-04).
Natural language command parser for asset status, alerts, and advisories.
"""

import asyncio
import logging
from datetime import datetime, timezone
from telegram import Update
from telegram.ext import Application, CommandHandler, MessageHandler, filters, ContextTypes

from app.core.config import settings

logger = logging.getLogger(__name__)


def get_db_session():
    """Create sync session for bot queries."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session
    engine = create_engine(settings.DATABASE_URL_SYNC, pool_pre_ping=True)
    return Session(engine)


async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "🦅 *UMEagleEye CAASM Bot*\n\n"
        "AI-Driven Cyber Asset Attack Surface Management\n\n"
        "*Commands:*\n"
        "/status — System health overview\n"
        "/assets — Asset inventory summary\n"
        "/alerts — Recent critical alerts\n"
        "/advisories — Open advisories\n"
        "/posture — Current security posture score\n"
        "/scan — Trigger a network scan\n"
        "/cti — Threat intelligence summary\n"
        "/help — Show this message",
        parse_mode="Markdown",
    )


async def status_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """FR-05-04: System status query."""
    from sqlalchemy import select, func
    from app.db.models import Asset, Event, Advisory, CTIIndicator
    from app.db.enums import AdvisoryStatus

    session = get_db_session()
    try:
        total_assets = session.execute(select(func.count(Asset.asset_id))).scalar()
        total_events = session.execute(select(func.count(Event.event_id))).scalar()
        open_advisories = session.execute(
            select(func.count(Advisory.advisory_id)).where(
                Advisory.status.in_([AdvisoryStatus.OPEN, AdvisoryStatus.IN_PROGRESS])
            )
        ).scalar()
        total_indicators = session.execute(select(func.count(CTIIndicator.indicator_id))).scalar()

        await update.message.reply_text(
            f"🟢 *UMEagleEye Status*\n\n"
            f"📊 *Assets Discovered:* {total_assets}\n"
            f"⚠️ *Security Events:* {total_events}\n"
            f"📋 *Open Advisories:* {open_advisories}\n"
            f"🛡️ *CTI Indicators:* {total_indicators}\n"
            f"🕐 *Updated:* {datetime.now(timezone.utc).strftime('%H:%M UTC')}",
            parse_mode="Markdown",
        )
    finally:
        session.close()


async def assets_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Quick asset summary."""
    from sqlalchemy import select, func
    from app.db.models import Asset

    session = get_db_session()
    try:
        assets = session.execute(
            select(Asset).order_by(Asset.criticality_score.desc()).limit(10)
        ).scalars().all()

        if not assets:
            await update.message.reply_text("No assets discovered yet. Run /scan first.")
            return

        lines = ["🖥️ *Top Assets by Criticality*\n"]
        for a in assets:
            crit = "🔴" if a.criticality_score >= 8 else "🟡" if a.criticality_score >= 5 else "🟢"
            baseline = "✅" if a.baseline_state else "⚠️"
            lines.append(f"{crit} `{a.ip_address}` — {a.hostname or 'Unknown'} [{a.criticality_score}/10] {baseline}")

        await update.message.reply_text("\n".join(lines), parse_mode="Markdown")
    finally:
        session.close()


async def alerts_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Recent critical/high alerts."""
    from sqlalchemy import select
    from app.db.models import Event
    from app.db.enums import Severity

    session = get_db_session()
    try:
        events = session.execute(
            select(Event).where(
                Event.severity.in_([Severity.CRITICAL, Severity.HIGH])
            ).order_by(Event.timestamp.desc()).limit(10)
        ).scalars().all()

        if not events:
            await update.message.reply_text("✅ No critical or high alerts. All clear!")
            return

        lines = ["🚨 *Recent Critical/High Alerts*\n"]
        for e in events:
            icon = "🔴" if e.severity == Severity.CRITICAL else "🟠"
            time_str = e.timestamp.strftime("%m/%d %H:%M")
            detail = e.details.get("cve_id") or e.details.get("action", e.event_type.value)
            lines.append(f"{icon} [{time_str}] {e.event_type.value}: {detail}")

        await update.message.reply_text("\n".join(lines), parse_mode="Markdown")
    finally:
        session.close()


async def advisories_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Open advisories summary."""
    from sqlalchemy import select
    from app.db.models import Advisory
    from app.db.enums import AdvisoryStatus

    session = get_db_session()
    try:
        advisories = session.execute(
            select(Advisory).where(
                Advisory.status.in_([AdvisoryStatus.OPEN, AdvisoryStatus.ACKNOWLEDGED])
            ).order_by(Advisory.created_at.desc()).limit(5)
        ).scalars().all()

        if not advisories:
            await update.message.reply_text("✅ No open advisories!")
            return

        lines = ["📋 *Open Advisories*\n"]
        for a in advisories:
            status_icon = {"open": "🔵", "acknowledged": "🟡", "in_progress": "🟠"}.get(a.status.value, "⚪")
            lines.append(f"{status_icon} *{a.status.value.upper()}*\n   {a.summary[:120]}...")

        await update.message.reply_text("\n".join(lines), parse_mode="Markdown")
    finally:
        session.close()


async def posture_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Current posture score."""
    from sqlalchemy import select
    from app.db.models import PostureMetrics

    session = get_db_session()
    try:
        snapshot = session.execute(
            select(PostureMetrics).order_by(PostureMetrics.timestamp.desc()).limit(1)
        ).scalar_one_or_none()

        if not snapshot:
            await update.message.reply_text("📊 Posture score not yet calculated. Run the posture engine first.")
            return

        score = snapshot.overall_score
        bar_filled = int(score / 10)
        bar_empty = 10 - bar_filled
        bar = "█" * bar_filled + "░" * bar_empty

        color = "🟢" if score >= 80 else "🟡" if score >= 50 else "🔴"

        await update.message.reply_text(
            f"📊 *Security Posture Score*\n\n"
            f"{color} *{score}/100*\n"
            f"`[{bar}]`\n\n"
            f"Assets: {snapshot.total_assets}\n"
            f"Critical Assets: {snapshot.total_critical_assets}\n"
            f"Open Critical Events: {snapshot.open_critical_events}",
            parse_mode="Markdown",
        )
    finally:
        session.close()


async def scan_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Trigger a network scan."""
    from app.tasks.discovery_tasks import run_active_scan
    task = run_active_scan.delay(
        target_subnet=settings.SCAN_DEFAULT_SUBNET,
        scan_type="nmap",
        rate_limit=settings.SCAN_RATE_LIMIT,
        initiated_by="telegram_bot",
    )
    await update.message.reply_text(
        f"🔍 *Scan Initiated*\n\n"
        f"Target: `{settings.SCAN_DEFAULT_SUBNET}`\n"
        f"Task ID: `{task.id}`\n"
        f"Status: QUEUED",
        parse_mode="Markdown",
    )


async def cti_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """CTI summary."""
    from sqlalchemy import select, func
    from app.db.models import CTIIndicator

    session = get_db_session()
    try:
        total = session.execute(select(func.count(CTIIndicator.indicator_id))).scalar()
        sources = session.execute(
            select(CTIIndicator.source, func.count(CTIIndicator.indicator_id))
            .group_by(CTIIndicator.source)
        ).all()

        lines = [f"🛡️ *Threat Intelligence*\n\nTotal Indicators: *{total}*\n"]
        for source, count in sources:
            lines.append(f"  • {source}: {count}")

        await update.message.reply_text("\n".join(lines), parse_mode="Markdown")
    finally:
        session.close()


async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """FR-05-04: Natural language parser for unrecognized messages."""
    text = update.message.text.lower().strip()

    if any(w in text for w in ["status", "health", "how"]):
        await status_command(update, context)
    elif any(w in text for w in ["asset", "device", "server", "host"]):
        await assets_command(update, context)
    elif any(w in text for w in ["alert", "threat", "critical", "attack"]):
        await alerts_command(update, context)
    elif any(w in text for w in ["advisory", "fix", "remediat", "action"]):
        await advisories_command(update, context)
    elif any(w in text for w in ["score", "posture", "risk"]):
        await posture_command(update, context)
    elif any(w in text for w in ["scan", "discover"]):
        await scan_command(update, context)
    else:
        await update.message.reply_text(
            "I didn't understand that. Try /help for available commands.",
        )


def main():
    """Start the Telegram bot."""
    if not settings.TELEGRAM_BOT_TOKEN:
        logger.error("TELEGRAM_BOT_TOKEN not set. Bot will not start.")
        return

    app = Application.builder().token(settings.TELEGRAM_BOT_TOKEN).build()

    app.add_handler(CommandHandler("start", start_command))
    app.add_handler(CommandHandler("help", start_command))
    app.add_handler(CommandHandler("status", status_command))
    app.add_handler(CommandHandler("assets", assets_command))
    app.add_handler(CommandHandler("alerts", alerts_command))
    app.add_handler(CommandHandler("advisories", advisories_command))
    app.add_handler(CommandHandler("posture", posture_command))
    app.add_handler(CommandHandler("scan", scan_command))
    app.add_handler(CommandHandler("cti", cti_command))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))

    logger.info("Starting UMEagleEye Telegram bot with full ChatOps...")
    app.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == "__main__":
    main()
