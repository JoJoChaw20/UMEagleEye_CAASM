"""
UMEagleEye - Telegram Formatter Service.

Role-aware MarkdownV2 message builder with inline keyboard buttons.
Centralises all Telegram message formatting per the ChatOps flow diagram:
  - Drift Alert    → Severity + asset + diff + Acknowledge button
  - AI Advisory    → Step-by-step commands + Mark Resolved button
  - Posture Report → Score + top CVEs + Download PDF button
"""

import logging
import re
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any

from telegram import InlineKeyboardButton, InlineKeyboardMarkup

logger = logging.getLogger(__name__)


# ── MarkdownV2 escape helper ─────────────────────────────────────
_MDV2_SPECIAL = r"_*[]()~`>#+=|{}.!\-"


def _esc(text: str) -> str:
    """Escape all MarkdownV2 special characters."""
    if not text:
        return ""
    return re.sub(r"([_*\[\]()~`>#+=|{}.!\-\\])", r"\\\1", str(text))


# ── Role constants ────────────────────────────────────────────────
ROLE_ADMIN = "admin"
ROLE_ANALYST = "security_analyst"
ROLE_VIEWER = "business_owner"       # matches UserRole enum values
ROLE_AUDITOR = "auditor"


def _is_privileged(role: Optional[str]) -> bool:
    """Admin and analyst can see full technical detail."""
    return role in (ROLE_ADMIN, ROLE_ANALYST)


# ══════════════════════════════════════════════════════════════════
# 1. DRIFT ALERT  (Automated push — from Celery worker)
# ══════════════════════════════════════════════════════════════════

SEVERITY_ICONS = {
    "critical": "🔴",
    "high":     "🟠",
    "medium":   "🟡",
    "low":      "🟢",
}


def format_drift_alert(
    asset_ip: str,
    asset_hostname: str,
    event_type: str,
    severity: str,
    changed_attribute: str,
    previous_value: str,
    new_value: str,
    event_id: str,
    evidence: Optional[Dict] = None,
    role: Optional[str] = None,
) -> tuple[str, InlineKeyboardMarkup]:
    """
    Build a MarkdownV2 drift alert message with an Acknowledge inline button.

    Returns (text, reply_markup) ready for bot.send_message().
    """
    icon = SEVERITY_ICONS.get(severity.lower(), "⚪")
    ts = datetime.now(timezone.utc).strftime("%Y\\-%m\\-%d %H:%M UTC")
    event_label = _esc(event_type.replace("_", " ").title())

    lines = [
        f"{icon} *DRIFT ALERT — {_esc(severity.upper())}*",
        "━━━━━━━━━━━━━━━━━━━━━━",
        f"🖥️ *Asset:* `{_esc(asset_ip)}` \\({_esc(asset_hostname or 'Unknown')}\\)",
        f"🔍 *Event:* {event_label}",
    ]

    if _is_privileged(role):
        # Full technical diff for analysts / admins
        lines += [
            f"📋 *Changed:* `{_esc(changed_attribute)}`",
            f"⬅️ *Previous:* `{_esc(previous_value)}`",
            f"➡️ *New Value:* `{_esc(new_value)}`",
        ]
        if evidence:
            first_key = next(iter(evidence), None)
            if first_key:
                lines.append(
                    f"📎 *Evidence:* `{_esc(first_key)}: {_esc(str(evidence[first_key])[:80])}`"
                )
    else:
        # Summary-only for business owner / auditor
        lines.append(f"⚠️ *Impact:* Configuration change detected on `{_esc(asset_ip)}`")

    lines += [
        f"🕐 *Detected:* {ts}",
        "",
        "_Reply /advisories for AI remediation steps_",
    ]

    text = "\n".join(lines)

    keyboard = InlineKeyboardMarkup([
        [InlineKeyboardButton("✅ Acknowledge", callback_data=f"ack_{event_id}")]
    ])

    return text, keyboard


# ══════════════════════════════════════════════════════════════════
# 2. AI ADVISORY  (Step-by-step + Mark Resolved button)
# ══════════════════════════════════════════════════════════════════

def format_advisory_message(
    advisory_id: str,
    event_type: str,
    severity: str,
    summary: str,
    recommended_action: str,
    asset_ip: str = "Unknown",
    role: Optional[str] = None,
) -> tuple[str, InlineKeyboardMarkup]:
    """
    Build a MarkdownV2 AI advisory message with a Mark Resolved inline button.
    """
    icon = SEVERITY_ICONS.get(severity.lower(), "⚪")
    ts = datetime.now(timezone.utc).strftime("%Y\\-%m\\-%d %H:%M UTC")
    event_label = _esc(event_type.replace("_", " ").title())

    lines = [
        f"🤖 *AI ADVISORY GENERATED*",
        "━━━━━━━━━━━━━━━━━━━━━━",
        f"{icon} *Severity:* {_esc(severity.upper())}",
        f"🔍 *Event:* {event_label}",
        f"🖥️ *Asset:* `{_esc(asset_ip)}`",
        f"🕐 *Time:* {ts}",
        "",
        f"📋 *Summary:*",
        _esc(summary[:300]) + ("\\.\\.\\." if len(summary) > 300 else ""),
    ]

    if _is_privileged(role):
        # Show full recommended action with commands for analysts
        lines += [
            "",
            f"🛠️ *Recommended Actions:*",
            f"`{_esc(recommended_action[:500])}`",
        ]

    lines += [
        "",
        f"🆔 `{_esc(advisory_id[:8])}`\\.\\.\\.",
    ]

    text = "\n".join(lines)

    keyboard = InlineKeyboardMarkup([
        [
            InlineKeyboardButton("✅ Mark Resolved", callback_data=f"resolve_{advisory_id}"),
            InlineKeyboardButton("📋 View Details", callback_data=f"detail_{advisory_id}"),
        ]
    ])

    return text, keyboard


# ══════════════════════════════════════════════════════════════════
# 3. POSTURE REPORT  (Score + top CVEs + Download PDF button)
# ══════════════════════════════════════════════════════════════════

def format_posture_report(
    snapshot_id: str,
    overall_score: int,
    total_assets: int,
    total_critical_assets: int,
    open_critical_events: int,
    top_risks: List[Dict[str, Any]],
    role: Optional[str] = None,
) -> tuple[str, InlineKeyboardMarkup]:
    """
    Build a MarkdownV2 posture report message with a Download PDF inline button.
    """
    bar_filled = int(overall_score / 10)
    bar = "█" * bar_filled + "░" * (10 - bar_filled)
    color = "🟢" if overall_score >= 80 else "🟡" if overall_score >= 50 else "🔴"
    ts = datetime.now(timezone.utc).strftime("%Y\\-%m\\-%d %H:%M UTC")

    lines = [
        f"📊 *SECURITY POSTURE REPORT*",
        "━━━━━━━━━━━━━━━━━━━━━━",
        f"{color} *Score: {_esc(str(overall_score))}/100*",
        f"`\\[{bar}\\]`",
        "",
        f"🖥️ Assets: *{_esc(str(total_assets))}* \\({_esc(str(total_critical_assets))} critical\\)",
        f"🚨 Open Critical Events: *{_esc(str(open_critical_events))}*",
        f"🕐 *Generated:* {ts}",
    ]

    if top_risks and _is_privileged(role):
        lines += ["", "🔝 *Top Risks:*"]
        for risk in top_risks[:3]:
            sev_icon = SEVERITY_ICONS.get(risk.get("severity", "medium").lower(), "⚪")
            cve = risk.get("details", {}).get("cve_id", risk.get("event_type", "N/A"))
            score = risk.get("risk_score", 0)
            lines.append(f"  {sev_icon} `{_esc(str(cve))}` — Risk: {_esc(str(score))}")

    text = "\n".join(lines)

    keyboard = InlineKeyboardMarkup([
        [InlineKeyboardButton("📄 Download PDF Report", callback_data=f"pdf_{snapshot_id}")]
    ])

    return text, keyboard


# ══════════════════════════════════════════════════════════════════
# 4. SLA ESCALATION  (Critical advisory open >4h)
# ══════════════════════════════════════════════════════════════════

def format_escalation_alert(
    advisory_id: str,
    event_type: str,
    asset_ip: str,
    hours_open: float,
    role: Optional[str] = None,
) -> tuple[str, InlineKeyboardMarkup]:
    """Build a MarkdownV2 SLA escalation message with an Acknowledge button."""
    ts = datetime.now(timezone.utc).strftime("%Y\\-%m\\-%d %H:%M UTC")
    event_label = _esc(event_type.replace("_", " ").title())

    lines = [
        "🚨 *ESCALATION — CRITICAL ADVISORY UNRESOLVED*",
        "━━━━━━━━━━━━━━━━━━━━━━",
        f"⏰ *Open for:* {_esc(f'{hours_open:.1f}')} hours \\(threshold: 4h\\)",
        f"🔍 *Event:* {event_label}",
        f"🖥️ *Asset:* `{_esc(asset_ip)}`",
        f"🆔 *Advisory:* `{_esc(advisory_id[:8])}\\.\\.\\.`",
        f"🕐 *Escalated:* {ts}",
        "",
        "⚠️ *This critical advisory requires immediate attention\\!*",
        "_Reply /advisories to review and assign_",
    ]

    text = "\n".join(lines)

    keyboard = InlineKeyboardMarkup([
        [
            InlineKeyboardButton("✅ Acknowledge", callback_data=f"resolve_{advisory_id}"),
            InlineKeyboardButton("📄 Get PDF", callback_data=f"pdf_latest"),
        ]
    ])

    return text, keyboard


# ══════════════════════════════════════════════════════════════════
# 5. STATUS / ASSETS  (User-initiated query responses)
# ══════════════════════════════════════════════════════════════════

def format_status_reply(
    total_assets: int,
    total_events: int,
    open_advisories: int,
    total_indicators: int,
    role: Optional[str] = None,
) -> str:
    """Plain MarkdownV2 status reply (no buttons needed)."""
    ts = datetime.now(timezone.utc).strftime("%Y\\-%m\\-%d %H:%M UTC")

    lines = [
        "🟢 *UMEagleEye Status*",
        "━━━━━━━━━━━━━━━━━━━━━━",
        f"📊 *Assets Discovered:* {_esc(str(total_assets))}",
        f"⚠️ *Security Events:* {_esc(str(total_events))}",
        f"📋 *Open Advisories:* {_esc(str(open_advisories))}",
        f"🛡️ *CTI Indicators:* {_esc(str(total_indicators))}",
        f"🕐 *Updated:* {ts}",
    ]

    return "\n".join(lines)
