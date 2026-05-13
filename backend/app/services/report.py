"""
UMEagleEye - Report Service.
Generates local PDF posture reports using reportlab (no GCS required).
"""
import io
import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


class ReportService:
    """Generate PDF reports as bytes buffers."""

    @staticmethod
    def generate_posture_pdf(snapshot) -> bytes:
        """
        Build a posture report PDF from a PostureMetrics snapshot.
        Returns raw PDF bytes suitable for sending as a Telegram document.
        """
        try:
            from reportlab.lib.pagesizes import A4
            from reportlab.lib import colors
            from reportlab.lib.units import cm
            from reportlab.platypus import (
                SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
            )
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.enums import TA_CENTER, TA_LEFT

            buf = io.BytesIO()
            doc = SimpleDocTemplate(buf, pagesize=A4,
                                    rightMargin=2*cm, leftMargin=2*cm,
                                    topMargin=2*cm, bottomMargin=2*cm)

            styles = getSampleStyleSheet()
            title_style = ParagraphStyle("Title", parent=styles["Title"],
                                         fontSize=20, textColor=colors.HexColor("#1a1a2e"),
                                         spaceAfter=6)
            heading_style = ParagraphStyle("Heading", parent=styles["Heading2"],
                                           fontSize=13, textColor=colors.HexColor("#16213e"),
                                           spaceBefore=12, spaceAfter=4)
            body_style = styles["Normal"]

            # ── Score colour ──────────────────────────────────────
            score = snapshot.overall_score
            if score >= 80:
                score_color = colors.HexColor("#27ae60")
            elif score >= 50:
                score_color = colors.HexColor("#f39c12")
            else:
                score_color = colors.HexColor("#e74c3c")

            score_style = ParagraphStyle("Score", parent=styles["Normal"],
                                         fontSize=48, textColor=score_color,
                                         alignment=TA_CENTER, spaceAfter=4)

            now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

            story = [
                Paragraph("UMEagleEye — Security Posture Report", title_style),
                Paragraph(f"Generated: {now_str}", body_style),
                HRFlowable(width="100%", thickness=1, color=colors.HexColor("#cccccc")),
                Spacer(1, 0.4*cm),

                Paragraph("Overall Score", heading_style),
                Paragraph(f"{score}/100", score_style),
                Spacer(1, 0.3*cm),

                Paragraph("Summary", heading_style),
            ]

            # Summary table
            summary_data = [
                ["Metric", "Value"],
                ["Total Assets",          str(snapshot.total_assets)],
                ["Critical Assets",       str(snapshot.total_critical_assets)],
                ["Open Critical Events",  str(snapshot.open_critical_events)],
            ]
            summary_table = Table(summary_data, colWidths=[9*cm, 7*cm])
            summary_table.setStyle(TableStyle([
                ("BACKGROUND",   (0, 0), (-1, 0), colors.HexColor("#1a1a2e")),
                ("TEXTCOLOR",    (0, 0), (-1, 0), colors.white),
                ("FONTNAME",     (0, 0), (-1, 0), "Helvetica-Bold"),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1),
                 [colors.HexColor("#f9f9f9"), colors.white]),
                ("GRID",         (0, 0), (-1, -1), 0.5, colors.HexColor("#cccccc")),
                ("PADDING",      (0, 0), (-1, -1), 8),
            ]))
            story.append(summary_table)
            story.append(Spacer(1, 0.4*cm))

            # Top risks
            top_risks = snapshot.top_risks or []
            if top_risks:
                story.append(Paragraph("Top Risks", heading_style))
                risk_data = [["Event Type", "Severity", "Risk Score"]]
                for r in top_risks[:5]:
                    risk_data.append([
                        r.get("event_type", "N/A"),
                        r.get("severity", "N/A").upper(),
                        str(r.get("risk_score", 0)),
                    ])
                risk_table = Table(risk_data, colWidths=[8*cm, 5*cm, 3*cm])
                risk_table.setStyle(TableStyle([
                    ("BACKGROUND",   (0, 0), (-1, 0), colors.HexColor("#e74c3c")),
                    ("TEXTCOLOR",    (0, 0), (-1, 0), colors.white),
                    ("FONTNAME",     (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1),
                     [colors.HexColor("#fdf2f2"), colors.white]),
                    ("GRID",         (0, 0), (-1, -1), 0.5, colors.HexColor("#cccccc")),
                    ("PADDING",      (0, 0), (-1, -1), 8),
                ]))
                story.append(risk_table)

            story.append(Spacer(1, 0.8*cm))
            story.append(Paragraph(
                "This report was auto-generated by UMEagleEye CAASM. "
                "University of Malaya — Faculty of Computer Science &amp; Information Technology.",
                ParagraphStyle("Footer", parent=body_style,
                               fontSize=8, textColor=colors.grey, alignment=TA_CENTER)
            ))

            doc.build(story)
            return buf.getvalue()

        except Exception as e:
            logger.error(f"PDF generation error: {e}")
            raise
