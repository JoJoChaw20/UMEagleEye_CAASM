"""
UMEagleEye - Telegram Bot (webhook mode).
Full ChatOps flow: intent classifier → role-aware handlers → inline buttons → audit log.
"""
import logging
from datetime import datetime, timezone
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup, ReplyKeyboardMarkup
from telegram.ext import (
    Application, CommandHandler, MessageHandler,
    CallbackQueryHandler, filters, ContextTypes,
)
from telegram.request import HTTPXRequest
from app.core.config import settings
import re

logger = logging.getLogger(__name__)

def _esc(t):
    """Escape all MarkdownV2 reserved characters."""
    return re.sub(r"([_*\[\]()~`>#+\-=|{}.!\\])", r"\\\1", str(t))


# ── DB helpers ────────────────────────────────────────────────────
def _session():
    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session
    return Session(create_engine(settings.DATABASE_URL_SYNC, pool_pre_ping=True))


def _get_user_by_chat(chat_id: str):
    from sqlalchemy import select
    from app.db.models import User
    with _session() as s:
        return s.execute(select(User).where(User.telegram_chat_id == chat_id)).scalar_one_or_none()


def _write_audit(user_id, action: str, target: str, prev=None, nxt=None):
    from app.db.models import AuditLog
    with _session() as s:
        s.add(AuditLog(
            user_id=user_id, action_type=action,
            target_entity=target, previous_state=prev, new_state=nxt,
        ))
        s.commit()


# ── Auth helpers ──────────────────────────────────────────────────
async def _get_linked_user(update: Update):
    """Return (User | None). None means not linked."""
    chat_id = str(update.effective_chat.id)
    user = _get_user_by_chat(chat_id)
    return user


async def _require_auth(update: Update):
    chat_id = str(update.effective_chat.id)
    # 1. Check admin fallback first (fast, no DB)
    if settings.TELEGRAM_CHAT_ID and chat_id == str(settings.TELEGRAM_CHAT_ID):
        return True

    # 2. Check linked user in DB
    user = await _get_linked_user(update)
    if user is None:
        await update.message.reply_text(
            "⛔ *Not linked*\\.\nYour Telegram account is not associated with any UMEagleEye user\\.\n\n"
            "Use `/link <username>` to begin\\.",
            parse_mode="MarkdownV2",
            reply_markup=get_main_keyboard()
        )
        return False
    return user


async def _require_role(update: Update, allowed=("admin", "security_analyst")):
    user = await _get_linked_user(update)
    if user is None:
        await update.message.reply_text("⛔ Not linked. Use /link <username> first.")
        return None
    if user.role.value not in allowed:
        await update.message.reply_text(f"⛔ Role *{_esc(user.role.value)}* cannot use this command\\.", parse_mode="MarkdownV2")
        return None
    return user


def get_main_keyboard(role: str = None):
    if role == "business_owner":
        keyboard = [
            ["📊 Status", "🛡️ Posture Score"]
        ]
    else:
        keyboard = [
            ["📊 Status", "🖥️ Assets"],
            ["🚨 Alerts", "📋 Advisories"],
            ["🛡️ Posture Score", "🔍 Network Scan"]
        ]
    return ReplyKeyboardMarkup(keyboard, resize_keyboard=True)


# ── /start /help ──────────────────────────────────────────────────
async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = await _get_linked_user(update)
    role = user.role.value if (user and hasattr(user, "role")) else None
    reply_markup = get_main_keyboard(role=role)

    await update.message.reply_text(
        "🦅 *UMEagleEye CAASM Bot*\n\n"
        "Commands:\n"
        "/status — System health\n"
        "/assets — Asset inventory\n"
        "/alerts — Critical alerts\n"
        "/advisories — Open advisories\n"
        "/posture — Posture score \\+ PDF\n"
        "/ask \\<question\\> — AI remediation\n"
        "/fix \\<advisory\\_id\\> — Mark resolved\n"
        "/scan — Trigger network scan _\\(analyst\\+\\)_\n"
        "/report — Generate posture PDF _\\(analyst\\+\\)_\n"
        "/link \\<username\\> — Link account\n"
        "/unlink — Stop alerts",
        parse_mode="MarkdownV2",
        reply_markup=reply_markup,
    )


# ── /link /unlink ─────────────────────────────────────────────────
async def link_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    chat_id = str(update.effective_chat.id)
    username = " ".join(context.args).strip() if context.args else ""
    if not username:
        await update.message.reply_text("Usage: `/link \\<username\\>`", parse_mode="MarkdownV2")
        return
    from sqlalchemy import select
    from app.db.models import User
    with _session() as s:
        user = s.execute(select(User).where(User.username == username)).scalar_one_or_none()
        if not user:
            await update.message.reply_text(f"❌ Username `{username}` not found.", parse_mode="MarkdownV2")
            return
        user.telegram_chat_id = chat_id
        s.commit()
        await update.message.reply_text(
            f"✅ *Linked* to *{_esc(user.username)}* \\({_esc(user.role.value)}\\)\\.\nAlerts will arrive here\\.",
            parse_mode="MarkdownV2",
            reply_markup=get_main_keyboard(role=user.role.value)
        )

async def unlink_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    chat_id = str(update.effective_chat.id)
    from sqlalchemy import select
    from app.db.models import User
    with _session() as s:
        users = s.execute(select(User).where(User.telegram_chat_id == chat_id)).scalars().all()
        for u in users:
            u.telegram_chat_id = None
        s.commit()
    await update.message.reply_text("✅ Unlinked from all accounts.")


# ── /status ───────────────────────────────────────────────────────
async def status_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = await _require_auth(update)
    if not user:
        return
    from sqlalchemy import select, func
    from app.db.models import Asset, Event, Advisory, CTIIndicator
    from app.db.enums import AdvisoryStatus
    from app.services.telegram_formatter import format_status_reply
    role = user.role.value if hasattr(user, "role") else None
    with _session() as s:
        ta = s.execute(select(func.count(Asset.asset_id))).scalar()
        te = s.execute(select(func.count(Event.event_id))).scalar()
        oa = s.execute(select(func.count(Advisory.advisory_id)).where(
            Advisory.status.in_([AdvisoryStatus.OPEN, AdvisoryStatus.IN_PROGRESS])
        )).scalar()
        ti = s.execute(select(func.count(CTIIndicator.indicator_id))).scalar()
    text = format_status_reply(ta, te, oa, ti, role=role)
    await update.message.reply_text(text, parse_mode="MarkdownV2")


# ── /assets ───────────────────────────────────────────────────────
async def assets_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = await _require_auth(update)
    if not user:
        return
    if hasattr(user, "role") and user.role.value == "business_owner":
        await update.message.reply_text("⛔ *Access Denied*: Business Owners cannot view detailed asset inventory.", parse_mode="MarkdownV2")
        return
    from sqlalchemy import select
    from app.db.models import Asset
    with _session() as s:
        assets = s.execute(
            select(Asset).order_by(Asset.criticality_score.desc()).limit(10)
        ).scalars().all()
        if not assets:
            await update.message.reply_text("No assets discovered yet\\. Run /scan first\\.", parse_mode="MarkdownV2")
            return
        lines = ["🖥️ *Top Assets by Criticality*\n"]
        for a in assets:
            crit = "🔴" if a.criticality_score >= 8 else "🟡" if a.criticality_score >= 5 else "🟢"
            lines.append(f"{crit} `{_esc(a.ip_address)}` — {_esc(a.hostname or 'Unknown')} \\[{a.criticality_score}/10\\]")
    await update.message.reply_text("\n".join(lines), parse_mode="MarkdownV2")


# ── /alerts ───────────────────────────────────────────────────────
async def alerts_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = await _require_auth(update)
    if not user:
        return
    if hasattr(user, "role") and user.role.value == "business_owner":
        await update.message.reply_text("⛔ *Access Denied*: Business Owners cannot view technical alerts.", parse_mode="MarkdownV2")
        return
    from sqlalchemy import select
    from app.db.models import Event
    from app.db.enums import Severity
    with _session() as s:
        events = s.execute(
            select(Event).where(Event.severity.in_([Severity.CRITICAL, Severity.HIGH]))
            .order_by(Event.timestamp.desc()).limit(10)
        ).scalars().all()
        if not events:
            await update.message.reply_text("✅ No critical/high alerts\\. All clear\\!", parse_mode="MarkdownV2")
            return
        lines = ["🚨 *Recent Critical/High Alerts*\n"]
        for e in events:
            icon = "🔴" if e.severity == Severity.CRITICAL else "🟠"
            ts = e.timestamp.strftime("%m/%d %H:%M")
            detail = e.details.get("cve_id") or e.details.get("action", e.event_type.value)
            lines.append(f"{icon} \\[{_esc(ts)}\\] {_esc(e.event_type.value)}: {_esc(detail)}")
    await update.message.reply_text("\n".join(lines), parse_mode="MarkdownV2")


# ── /advisories ───────────────────────────────────────────────────
async def advisories_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = await _require_auth(update)
    if not user:
        return
    if hasattr(user, "role") and user.role.value == "business_owner":
        await update.message.reply_text("⛔ *Access Denied*: Business Owners cannot view technical advisories.", parse_mode="MarkdownV2")
        return
    from sqlalchemy import select
    from app.db.models import Advisory
    from app.db.enums import AdvisoryStatus
    with _session() as s:
        advs = s.execute(
            select(Advisory).where(Advisory.status.in_([AdvisoryStatus.OPEN, AdvisoryStatus.ACKNOWLEDGED]))
            .order_by(Advisory.created_at.desc()).limit(10)
        ).scalars().all()
        if not advs:
            await update.message.reply_text("✅ No open advisories\\!", parse_mode="MarkdownV2")
            return
        lines = ["📋 *Open Advisories*\n"]
        for a in advs:
            icon = {"open": "🔵", "acknowledged": "🟡", "in_progress": "🟠"}.get(a.status.value, "⚪")
            short_id = str(a.advisory_id)[:8]
            lines.append(
                f"{icon} `{_esc(short_id)}` \\| {_esc(a.status.value.upper())}\n"
                f"   _{_esc(a.summary[:100])}\\.\\.\\._ \n"
                f"   /fix\\_{_esc(short_id)}"
            )
    await update.message.reply_text("\n".join(lines), parse_mode="MarkdownV2")


# ── /posture ──────────────────────────────────────────────────────
async def posture_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = await _require_auth(update)
    if not user:
        return
    from sqlalchemy import select
    from app.db.models import PostureMetrics
    from app.services.telegram_formatter import format_posture_report
    role = user.role.value if hasattr(user, "role") else None
    with _session() as s:
        snap = s.execute(
            select(PostureMetrics).order_by(PostureMetrics.timestamp.desc()).limit(1)
        ).scalar_one_or_none()
        if not snap:
            await update.message.reply_text("📊 Posture score not yet calculated\\.", parse_mode="MarkdownV2")
            return
        text, markup = format_posture_report(
            snapshot_id=str(snap.snapshot_id),
            overall_score=snap.overall_score,
            total_assets=snap.total_assets,
            total_critical_assets=snap.total_critical_assets,
            open_critical_events=snap.open_critical_events,
            top_risks=snap.top_risks or [],
            role=role,
        )
    await update.message.reply_text(text, parse_mode="MarkdownV2", reply_markup=markup)


# ── /scan (analyst+ only) ─────────────────────────────────────────
async def scan_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = await _require_role(update, allowed=("admin", "security_analyst", "ops_lead"))
    if not user:
        return
    from app.tasks.discovery_tasks import run_active_scan
    task = run_active_scan.delay(
        target_subnet=settings.SCAN_DEFAULT_SUBNET,
        scan_type="nmap",
        rate_limit=settings.SCAN_RATE_LIMIT,
        initiated_by="telegram_bot",
    )
    await update.message.reply_text(
        f"🔍 *Scan Initiated*\nTarget: `{_esc(settings.SCAN_DEFAULT_SUBNET)}`\nTask: `{_esc(task.id)}`",
        parse_mode="MarkdownV2",
    )


# ── /ask ──────────────────────────────────────────────────────────
async def ask_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = await _require_auth(update)
    if not user:
        return
    if hasattr(user, "role") and user.role.value == "business_owner":
        await update.message.reply_text("⛔ *Access Denied*: Business Owners cannot use the AI remediation assistant.", parse_mode="MarkdownV2")
        return
    query = " ".join(context.args) if context.args else ""
    if not query:
        await update.message.reply_text("Usage: `/ask <security question>`", parse_mode="MarkdownV2")
        return
    await update.message.reply_text("🤔 Querying AI with RAG context…")
    try:
        from app.services.advisory import AdvisoryService
        event_data = {"event_type": "chatops_query", "severity": "medium", "details": {"query": query}}
        asset_data = {"device_type": "server", "criticality_score": 7, "is_internet_facing": True}
        with _session() as s:
            result = await AdvisoryService.generate_advisory(event_data, asset_data, db=s)
        summary = result.get("summary", "")
        action = result.get("recommended_action", "")
        import re
        def esc(t): return _esc(t)
        await update.message.reply_text(
            f"🤖 *AI Remediation Response*\n"
            f"━━━━━━━━━━━━━━━━━━━━━━\n"
            f"❓ *Query:* {esc(query)}\n\n"
            f"📋 *Summary:*\n{esc(summary[:300])}\n\n"
            f"🛠️ *Actions:*\n`{esc(action[:500])}`",
            parse_mode="MarkdownV2",
        )
    except Exception as e:
        logger.error(f"ChatOps /ask error: {e}")
        await update.message.reply_text(f"⚠️ Error: {str(e)[:200]}")


# ── /report (analyst+ only) ───────────────────────────────────────
async def report_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = await _require_role(update, allowed=("admin", "security_analyst"))
    if not user:
        return
    await update.message.reply_text("📄 Generating posture PDF…")
    await _send_posture_pdf(update, str(user.user_id))


# ── /fix_<id> dynamic command ─────────────────────────────────────
async def fix_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /fix_<advisory_short_id> sent from /advisories listing."""
    user = await _require_auth(update)
    if not user:
        return
    if hasattr(user, "role") and user.role.value == "business_owner":
        await update.message.reply_text("⛔ *Access Denied*: Business Owners cannot perform remediation actions.", parse_mode="MarkdownV2")
        return
    text = update.message.text or ""
    short_id = text.split("_", 1)[1].strip() if "_" in text else ""
    if not short_id:
        await update.message.reply_text("Usage: /fix\\_<advisory\\_id>", parse_mode="MarkdownV2")
        return
    await _show_fix_menu_by_short(update, short_id, user)


# ── Callback query handler (inline buttons) ───────────────────────
async def callback_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    data = query.data or ""
    chat_id = str(query.from_user.id)
    user = _get_user_by_chat(chat_id)

    if data.startswith("ack_"):
        event_id = data[4:]
        await _acknowledge_event(query, event_id, user)

    elif data.startswith("resolve_"):
        advisory_id = data[8:]
        await _resolve_advisory(query, advisory_id, user)

    elif data.startswith("detail_"):
        advisory_id = data[7:]
        await _show_advisory_detail(query, advisory_id)

    elif data.startswith("debug_"):
        advisory_id = data[6:]
        from telegram import ForceReply
        lines = [
            f"🤖 You are debugging Advisory `{_esc(advisory_id[:8])}`\\.",
            "",
            "Reply directly to this message with your specific question or terminal output:"
        ]
        await query.message.reply_text(
            "\n".join(lines),
            reply_markup=ForceReply(selective=True),
            parse_mode="MarkdownV2"
        )

    elif data.startswith("pdf_"):
        snap_id = data[4:]
        await _send_posture_pdf_callback(query, snap_id, user)

    else:
        await query.edit_message_text("⚠️ Unknown action.")


async def _acknowledge_event(query, event_id: str, user):
    """Acknowledge an advisory linked to an event; write audit log."""
    from sqlalchemy import select
    from app.db.models import Advisory, Event
    from app.db.enums import AdvisoryStatus
    with _session() as s:
        try:
            event = s.execute(select(Event).where(Event.event_id == event_id)).scalar_one_or_none()
            if not event:
                await query.edit_message_text("❌ Event not found.")
                return
            advisories = s.execute(
                select(Advisory).where(
                    Advisory.event_id == event_id,
                    Advisory.status == AdvisoryStatus.OPEN,
                )
            ).scalars().all()
            for adv in advisories:
                prev = {"status": adv.status.value}
                adv.status = AdvisoryStatus.ACKNOWLEDGED
                if user:
                    _write_audit(
                        user.user_id, "telegram_acknowledge",
                        f"advisory:{adv.advisory_id}",
                        prev, {"status": "acknowledged"},
                    )
            s.commit()
            count = len(advisories)
            await query.edit_message_text(
                f"✅ Acknowledged {count} advisory(ies) for event `{event_id[:8]}`.",
                parse_mode="MarkdownV2",
            )
        except Exception as e:
            logger.error(f"Acknowledge error: {e}")
            await query.edit_message_text(f"⚠️ Error: {e}")


async def _resolve_advisory(query, advisory_id: str, user):
    """Mark advisory resolved; write audit log."""
    from sqlalchemy import select
    from app.db.models import Advisory
    from app.db.enums import AdvisoryStatus
    import uuid
    with _session() as s:
        try:
            # Support both full UUID and short prefix
            try:
                uuid.UUID(advisory_id)
                adv = s.execute(select(Advisory).where(Advisory.advisory_id == advisory_id)).scalar_one_or_none()
            except ValueError:
                advs = s.execute(select(Advisory)).scalars().all()
                adv = next((a for a in advs if str(a.advisory_id).startswith(advisory_id)), None)

            if not adv:
                await query.edit_message_text("❌ Advisory not found.")
                return
            prev = {"status": adv.status.value}
            adv.status = AdvisoryStatus.RESOLVED
            adv.resolved_at = datetime.now(timezone.utc)
            if user:
                _write_audit(
                    user.user_id, "telegram_resolve",
                    f"advisory:{adv.advisory_id}",
                    prev, {"status": "resolved"},
                )
            s.commit()
            await query.edit_message_text(
                f"✅ Advisory `{str(adv.advisory_id)[:8]}` marked *RESOLVED*\\.",
                parse_mode="MarkdownV2",
            )
        except Exception as e:
            logger.error(f"Resolve error: {e}")
            await query.edit_message_text(f"⚠️ Error: {e}")


async def _show_fix_menu_by_short(update, short_id: str, user):
    """Show advisory details and AI debug menu for /fix_ command."""
    from sqlalchemy import select
    from app.db.models import Advisory
    def esc(t): return _esc(t)
    with _session() as s:
        advs = s.execute(select(Advisory)).scalars().all()
        adv = next((a for a in advs if str(a.advisory_id).startswith(short_id)), None)
        if not adv:
            await update.message.reply_text("❌ Advisory not found.")
            return

        await update.message.reply_text(
            f"📋 *Advisory Detail*\n"
            f"🆔 `{esc(str(adv.advisory_id)[:8])}`\n"
            f"Status: *{esc(adv.status.value.upper())}*\n\n"
            f"📝 *Summary:*\n{esc(adv.summary[:400])}\n\n"
            f"🛠️ *Actions:*\n```\n{esc(adv.recommended_action[:500])}\n```",
            parse_mode="MarkdownV2",
            reply_markup=InlineKeyboardMarkup([
                [InlineKeyboardButton("✅ Mark Resolved", callback_data=f"resolve_{adv.advisory_id}")],
                [InlineKeyboardButton("🤖 Debug with AI", callback_data=f"debug_{adv.advisory_id}")]
            ]),
        )


async def _show_advisory_detail(query, advisory_id: str):
    from sqlalchemy import select
    from app.db.models import Advisory
    import re
    def esc(t): return _esc(t)
    with _session() as s:
        try:
            adv = s.execute(select(Advisory).where(Advisory.advisory_id == advisory_id)).scalar_one_or_none()
            if not adv:
                await query.edit_message_text("❌ Advisory not found.")
                return
            await query.edit_message_text(
                f"📋 *Advisory Detail*\n"
                f"🆔 `{esc(str(adv.advisory_id)[:8])}`\n"
                f"Status: *{esc(adv.status.value.upper())}*\n\n"
                f"📝 *Summary:*\n{esc(adv.summary[:400])}\n\n"
                f"🛠️ *Actions:*\n```\n{esc(adv.recommended_action[:500])}\n```",
                parse_mode="MarkdownV2",
                reply_markup=InlineKeyboardMarkup([
                    [InlineKeyboardButton("✅ Mark Resolved", callback_data=f"resolve_{advisory_id}")],
                    [InlineKeyboardButton("🤖 Debug with AI", callback_data=f"debug_{advisory_id}")]
                ]),
            )
        except Exception as e:
            await query.edit_message_text(f"⚠️ Error: {e}")


async def _send_posture_pdf(update, user_id: str):
    """Generate and send local PDF posture report."""
    from sqlalchemy import select
    from app.db.models import PostureMetrics
    from app.services.report import ReportService
    with _session() as s:
        snap = s.execute(select(PostureMetrics).order_by(PostureMetrics.timestamp.desc()).limit(1)).scalar_one_or_none()
        if not snap:
            await update.message.reply_text("📊 No posture snapshot available yet.")
            return
        try:
            pdf_bytes = ReportService.generate_posture_pdf(snap)
            filename = f"posture_report_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M')}.pdf"
            await update.message.reply_document(document=pdf_bytes, filename=filename, caption="📊 Security Posture Report")
            _write_audit(user_id, "telegram_download_pdf", f"posture:{snap.snapshot_id}", None, {"filename": filename})
        except Exception as e:
            logger.error(f"PDF generation error: {e}")
            await update.message.reply_text(f"⚠️ PDF error: {str(e)[:200]}")


async def _send_posture_pdf_callback(query, snap_id: str, user):
    """Generate and send PDF from button callback."""
    from sqlalchemy import select
    from app.db.models import PostureMetrics
    from app.services.report import ReportService
    await query.edit_message_text("📄 Generating PDF…")
    with _session() as s:
        if snap_id == "latest":
            snap = s.execute(select(PostureMetrics).order_by(PostureMetrics.timestamp.desc()).limit(1)).scalar_one_or_none()
        else:
            snap = s.execute(select(PostureMetrics).where(PostureMetrics.snapshot_id == snap_id)).scalar_one_or_none()
        if not snap:
            await query.message.reply_text("📊 No posture snapshot available.")
            return
        try:
            pdf_bytes = ReportService.generate_posture_pdf(snap)
            filename = f"posture_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M')}.pdf"
            await query.message.reply_document(document=pdf_bytes, filename=filename, caption="📊 Security Posture Report")
            if user:
                _write_audit(user.user_id, "telegram_download_pdf", f"posture:{snap.snapshot_id}", None, {"filename": filename})
        except Exception as e:
            logger.error(f"PDF callback error: {e}")
            await query.message.reply_text(f"⚠️ PDF error: {str(e)[:200]}")


# ── Natural language intent classifier ───────────────────────────
async def _handle_ai_debug(update, short_id: str, user_question: str):
    from sqlalchemy import select
    from app.db.models import Advisory
    from app.services.advisory import AdvisoryService
    
    msg = await update.message.reply_text(
        "🤖 Thinking\\.\\.\\.", 
        parse_mode="MarkdownV2", 
        reply_markup=get_main_keyboard()
    )
    
    with _session() as s:
        advs = s.execute(select(Advisory)).scalars().all()
        adv = next((a for a in advs if str(a.advisory_id).startswith(short_id)), None)
        if not adv:
            await msg.edit_text("❌ Advisory not found.")
            return
            
        import asyncio
        loop = asyncio.get_event_loop()
        try:
            answer = await loop.run_in_executor(None, AdvisoryService.debug_advisory, adv, user_question)
        except Exception as ai_err:
            logger.error(f"AI Executor error: {ai_err}")
            answer = f"⚠️ AI Error: {str(ai_err)}"

        if not answer or not answer.strip():
            answer = "🤖 The AI returned an empty response. Please try rephrasing your question."

        # Delete thinking message and send new response to avoid 'Message can't be edited' errors
        try:
            await msg.delete()
        except:
            pass
            
        await update.message.reply_text(answer, parse_mode="Markdown", reply_markup=get_main_keyboard())


async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = await _require_auth(update)
    if not user:
        return
    text = (update.message.text or "").lower().strip()
    raw_text = update.message.text or ""

    # Check if this is a reply to an AI Debug prompt
    if update.message.reply_to_message and update.message.reply_to_message.from_user.is_bot:
        reply_text = update.message.reply_to_message.text or ""
        if "debugging Advisory" in reply_text:
            import re
            match = re.search(r"Advisory ([a-zA-Z0-9]+)", reply_text)
            if match:
                short_id = match.group(1)
                await _handle_ai_debug(update, short_id, raw_text)
                return

    if any(w in text for w in ("status", "health", "how are")):
        await status_command(update, context)
    elif any(w in text for w in ("asset", "device", "server", "host")):
        await assets_command(update, context)
    elif any(w in text for w in ("alert", "threat", "critical", "attack")):
        await alerts_command(update, context)
    elif any(w in text for w in ("advisor", "fix", "remediat", "action", "resolve")):
        await advisories_command(update, context)
    elif any(w in text for w in ("score", "posture", "risk", "report")):
        await posture_command(update, context)
    elif any(w in text for w in ("scan", "discover")):
        await scan_command(update, context)
    elif any(w in text for w in ("ask", "block", "stop", "prevent", "mitigat", "harden", "how to")):
        context.args = text.split()
        await ask_command(update, context)
    else:
        await update.message.reply_text(
            "I didn't understand that\\. Try /help or `/ask <question>`\\.",
            parse_mode="MarkdownV2",
        )


# ── Application builder (used by webhook route) ───────────────────
def build_application() -> Application:
    """Build and return the PTB Application with all handlers registered."""
    if not settings.TELEGRAM_BOT_TOKEN:
        raise RuntimeError("TELEGRAM_BOT_TOKEN not set.")
    
    # Increase timeouts for unstable networks (FR-05 requirements)
    request = HTTPXRequest(connect_timeout=30.0, read_timeout=30.0, write_timeout=30.0)
    app = Application.builder().token(settings.TELEGRAM_BOT_TOKEN).request(request).build()
    app.add_handler(CommandHandler("start",       start_command))
    app.add_handler(CommandHandler("help",        start_command))
    app.add_handler(CommandHandler("link",        link_command))
    app.add_handler(CommandHandler("unlink",      unlink_command))
    app.add_handler(CommandHandler("status",      status_command))
    app.add_handler(CommandHandler("assets",      assets_command))
    app.add_handler(CommandHandler("alerts",      alerts_command))
    app.add_handler(CommandHandler("advisories",  advisories_command))
    app.add_handler(CommandHandler("posture",     posture_command))
    app.add_handler(CommandHandler("scan",        scan_command))
    app.add_handler(CommandHandler("ask",         ask_command))
    app.add_handler(CommandHandler("report",      report_command))
    app.add_handler(MessageHandler(filters.Regex(r"^/fix_"), fix_command))
    app.add_handler(CallbackQueryHandler(callback_handler))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))
    return app


def main():
    """Polling entrypoint (dev fallback only)."""
    app = build_application()
    logger.info("Starting UMEagleEye Telegram bot (polling mode)…")
    app.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == "__main__":
    main()
