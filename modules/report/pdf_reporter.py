"""
PDF Reporter — modules/report/pdf_reporter.py

Generates professional penetration test PDF reports from Glitchicons findings.

Features:
  - Executive summary page with severity donut + key stats
  - Per-finding pages: title, CVSS, CWE, description, evidence, remediation
  - Table of contents
  - Cover page with engagement metadata
  - Severity color coding
  - CVSS score bar visualization

Requirements:
  pip install reportlab

Usage:
    from modules.report.pdf_reporter import PDFReporter

    reporter = PDFReporter(
        findings=findings,
        target="target.com",
        output_dir="./findings/reports",
        engagement_name="Target Corp — API Security Assessment",
        author="Glitchicons Security",
    )
    path = reporter.generate()
    print(f"PDF saved: {path}")

Author: ardanov96
"""

import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from rich.console import Console

console = Console()

# Severity ordering and colors (hex strings for reportlab)
SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

SEVERITY_COLORS_HEX = {
    "CRITICAL": "#FF0040",
    "HIGH":     "#FF6B35",
    "MEDIUM":   "#FFB300",
    "LOW":      "#30D158",
    "INFO":     "#64D2FF",
}

SEVERITY_CVSS_RANGE = {
    "CRITICAL": (9.0, 10.0),
    "HIGH":     (7.0, 8.9),
    "MEDIUM":   (4.0, 6.9),
    "LOW":      (0.1, 3.9),
    "INFO":     (0.0, 0.0),
}


def _hex_to_rgb(hex_color: str) -> tuple:
    """Convert hex color to RGB tuple (0-1 range for reportlab)."""
    hex_color = hex_color.lstrip("#")
    r = int(hex_color[0:2], 16) / 255
    g = int(hex_color[2:4], 16) / 255
    b = int(hex_color[4:6], 16) / 255
    return (r, g, b)


class PDFReporter:
    """
    Generate professional PDF pentest reports from Glitchicons findings.

    Uses reportlab for pure Python PDF generation (no wkhtmltopdf required).
    Falls back to structured JSON if reportlab not installed.
    """

    def __init__(
        self,
        findings: list[dict],
        target: str,
        output_dir: str = "./findings/reports",
        engagement_name: str = "",
        author: str = "Glitchicons Security",
        confidentiality: str = "CONFIDENTIAL",
    ):
        self.findings        = findings
        self.target          = target
        self.output_dir      = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.engagement_name = engagement_name or f"Security Assessment — {target}"
        self.author          = author
        self.confidentiality = confidentiality
        self.generated_at    = datetime.now(timezone.utc)

        # Pre-compute stats
        self.counts = Counter(f.get("severity", "INFO") for f in findings)
        self.sorted_findings = sorted(
            findings,
            key=lambda f: SEVERITY_ORDER.index(f.get("severity", "INFO"))
        )

    def generate(self) -> Path:
        """Generate PDF report. Falls back to JSON if reportlab not available."""
        try:
            return self._generate_pdf()
        except ImportError:
            console.print(
                "  [yellow]reportlab not installed — generating JSON report instead.[/yellow]\n"
                "  Install: pip install reportlab"
            )
            return self._generate_json_fallback()

    def _generate_pdf(self) -> Path:
        """Generate actual PDF using reportlab."""
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import mm
        from reportlab.lib import colors
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
            HRFlowable, PageBreak, KeepTogether,
        )
        from reportlab.graphics.shapes import Drawing, Rect, String, Circle
        from reportlab.graphics.charts.piecharts import Pie
        from reportlab.graphics import renderPDF

        slug = self.target.replace("/", "_").replace(":", "")
        out  = self.output_dir / f"report_{slug}_{self.generated_at.strftime('%Y%m%d_%H%M%S')}.pdf"

        doc = SimpleDocTemplate(
            str(out), pagesize=A4,
            leftMargin=20*mm, rightMargin=20*mm,
            topMargin=20*mm, bottomMargin=20*mm,
            title=self.engagement_name,
            author=self.author,
        )

        W, H = A4
        styles = getSampleStyleSheet()

        # Custom styles
        def c(hex_str):
            r, g, b = _hex_to_rgb(hex_str)
            return colors.Color(r, g, b)

        style_h1 = ParagraphStyle("H1", parent=styles["Heading1"],
            fontSize=22, textColor=c("#A855F7"), spaceAfter=6)
        style_h2 = ParagraphStyle("H2", parent=styles["Heading2"],
            fontSize=14, textColor=c("#A855F7"), spaceAfter=4)
        style_h3 = ParagraphStyle("H3", parent=styles["Heading3"],
            fontSize=11, textColor=c("#C8C8E8"), spaceAfter=2)
        style_body = ParagraphStyle("Body", parent=styles["Normal"],
            fontSize=9, textColor=c("#9898B8"), leading=14, spaceAfter=4)
        style_code = ParagraphStyle("Code", parent=styles["Code"],
            fontSize=8, textColor=c("#C8C8E8"),
            backColor=c("#131326"), borderPad=4, spaceAfter=4)
        style_label = ParagraphStyle("Label", parent=styles["Normal"],
            fontSize=8, textColor=c("#4A4A6A"), spaceAfter=2)
        style_meta = ParagraphStyle("Meta", parent=styles["Normal"],
            fontSize=8, textColor=c("#6B6B90"), spaceAfter=1)

        elements = []

        # ── COVER PAGE ────────────────────────────────────
        elements.append(Spacer(1, 40*mm))

        # Title
        elements.append(Paragraph("SECURITY ASSESSMENT REPORT", style_h1))
        elements.append(HRFlowable(color=c("#6B00FF"), thickness=2, spaceAfter=8))
        elements.append(Paragraph(self.engagement_name, style_h2))
        elements.append(Spacer(1, 8*mm))

        # Cover metadata table
        cover_data = [
            ["Target",       self.target],
            ["Engagement",   self.engagement_name],
            ["Author",       self.author],
            ["Generated",    self.generated_at.strftime("%Y-%m-%d %H:%M UTC")],
            ["Findings",     str(len(self.findings))],
            ["Classification", self.confidentiality],
        ]
        cover_table = Table(cover_data, colWidths=[45*mm, 120*mm])
        cover_table.setStyle(TableStyle([
            ("BACKGROUND",  (0, 0), (0, -1), c("#131326")),
            ("TEXTCOLOR",   (0, 0), (0, -1), c("#A855F7")),
            ("TEXTCOLOR",   (1, 0), (1, -1), c("#C8C8E8")),
            ("FONTSIZE",    (0, 0), (-1, -1), 9),
            ("FONTNAME",    (0, 0), (0, -1), "Helvetica-Bold"),
            ("ROWBACKGROUNDS", (0, 0), (-1, -1), [c("#0D0D1A"), c("#131326")]),
            ("GRID",        (0, 0), (-1, -1), 0.5, c("#2D2D4A")),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("RIGHTPADDING",(0, 0), (-1, -1), 8),
            ("TOPPADDING",  (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING",(0, 0), (-1, -1), 6),
        ]))
        elements.append(cover_table)
        elements.append(PageBreak())

        # ── EXECUTIVE SUMMARY ─────────────────────────────
        elements.append(Paragraph("EXECUTIVE SUMMARY", style_h1))
        elements.append(HRFlowable(color=c("#6B00FF"), thickness=1, spaceAfter=6))

        # Severity breakdown table
        sev_data = [["Severity", "Count", "CVSS Range", "Risk Level"]]
        for sev in SEVERITY_ORDER:
            count = self.counts.get(sev, 0)
            if count == 0:
                continue
            low, high = SEVERITY_CVSS_RANGE[sev]
            cvss_range = f"{low:.1f}–{high:.1f}" if high > 0 else "N/A"
            sev_data.append([sev, str(count), cvss_range, self._risk_label(sev)])

        sev_table = Table(sev_data, colWidths=[40*mm, 25*mm, 40*mm, 60*mm])
        sev_style = [
            ("BACKGROUND",  (0, 0), (-1, 0), c("#1A1A35")),
            ("TEXTCOLOR",   (0, 0), (-1, 0), c("#A855F7")),
            ("FONTNAME",    (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE",    (0, 0), (-1, -1), 9),
            ("GRID",        (0, 0), (-1, -1), 0.5, c("#2D2D4A")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [c("#0D0D1A"), c("#131326")]),
            ("TEXTCOLOR",   (0, 1), (-1, -1), c("#C8C8E8")),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("TOPPADDING",  (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING",(0, 0), (-1, -1), 5),
        ]
        # Color severity column
        row = 1
        for sev in SEVERITY_ORDER:
            if self.counts.get(sev, 0) > 0:
                sev_style.append(("TEXTCOLOR", (0, row), (0, row), c(SEVERITY_COLORS_HEX[sev])))
                sev_style.append(("FONTNAME",  (0, row), (0, row), "Helvetica-Bold"))
                row += 1
        sev_table.setStyle(TableStyle(sev_style))
        elements.append(sev_table)
        elements.append(Spacer(1, 6*mm))

        # Key stats
        critical = self.counts.get("CRITICAL", 0)
        high     = self.counts.get("HIGH", 0)
        avg_cvss = (sum(f.get("cvss", 0) for f in self.findings) / len(self.findings)
                    if self.findings else 0)

        elements.append(Paragraph(
            f"Total findings: <b>{len(self.findings)}</b> &nbsp;|&nbsp; "
            f"Critical: <b>{critical}</b> &nbsp;|&nbsp; "
            f"High: <b>{high}</b> &nbsp;|&nbsp; "
            f"Avg CVSS: <b>{avg_cvss:.1f}</b>",
            ParagraphStyle("Stats", parent=styles["Normal"],
                fontSize=10, textColor=c("#C8C8E8"), spaceAfter=6)
        ))

        # Overall risk
        overall = self._overall_risk()
        elements.append(Paragraph(
            f"Overall Risk: <b>{overall}</b>",
            ParagraphStyle("Risk", parent=styles["Normal"],
                fontSize=12, textColor=c(SEVERITY_COLORS_HEX.get(overall, "#64D2FF")),
                spaceAfter=8)
        ))

        elements.append(PageBreak())

        # ── TABLE OF CONTENTS ─────────────────────────────
        elements.append(Paragraph("TABLE OF CONTENTS", style_h1))
        elements.append(HRFlowable(color=c("#6B00FF"), thickness=1, spaceAfter=6))

        for i, f in enumerate(self.sorted_findings, 1):
            sev   = f.get("severity", "INFO")
            title = f.get("title", "Untitled")[:70]
            cvss  = f.get("cvss", 0)
            toc_entry = Table(
                [[f"{i:02d}.", f"[{sev}]", f"{title}", f"CVSS {cvss:.1f}"]],
                colWidths=[10*mm, 25*mm, 120*mm, 20*mm],
            )
            toc_entry.setStyle(TableStyle([
                ("TEXTCOLOR", (0, 0), (0, 0), c("#4A4A6A")),
                ("TEXTCOLOR", (1, 0), (1, 0), c(SEVERITY_COLORS_HEX.get(sev, "#64D2FF"))),
                ("TEXTCOLOR", (2, 0), (2, 0), c("#9898B8")),
                ("TEXTCOLOR", (3, 0), (3, 0), c("#6B6B90")),
                ("FONTSIZE",  (0, 0), (-1, 0), 8),
                ("TOPPADDING",(0, 0), (-1, 0), 2),
                ("BOTTOMPADDING",(0, 0), (-1, 0), 2),
            ]))
            elements.append(toc_entry)

        elements.append(PageBreak())

        # ── FINDINGS ──────────────────────────────────────
        elements.append(Paragraph("FINDINGS", style_h1))
        elements.append(HRFlowable(color=c("#6B00FF"), thickness=1, spaceAfter=8))

        for i, f in enumerate(self.sorted_findings, 1):
            sev   = f.get("severity", "INFO")
            title = f.get("title", "Untitled")
            cvss  = f.get("cvss", 0.0)
            cwe   = f.get("cwe", "N/A")

            block = []

            # Finding header
            block.append(Paragraph(
                f'<font color="{SEVERITY_COLORS_HEX.get(sev, "#64D2FF")}">'
                f'[{sev}]</font> {i:02d}. {title}',
                style_h2
            ))

            # Metadata row
            meta_data = [
                ["CVSS Score", f"{cvss:.1f}", "CWE", cwe,
                 "Target", str(f.get("target", "N/A"))[:40]],
            ]
            meta_table = Table(meta_data, colWidths=[22*mm, 20*mm, 15*mm, 30*mm, 18*mm, 65*mm])
            meta_table.setStyle(TableStyle([
                ("BACKGROUND",  (0, 0), (-1, -1), c("#0D0D1A")),
                ("TEXTCOLOR",   (0, 0), (0, 0),   c(SEVERITY_COLORS_HEX.get(sev, "#64D2FF"))),
                ("TEXTCOLOR",   (1, 0), (1, 0),   c(SEVERITY_COLORS_HEX.get(sev, "#64D2FF"))),
                ("TEXTCOLOR",   (2, 0), (2, 0),   c("#4A4A6A")),
                ("TEXTCOLOR",   (3, 0), (-1, -1), c("#9898B8")),
                ("FONTNAME",    (0, 0), (0, 0),   "Helvetica-Bold"),
                ("FONTNAME",    (1, 0), (1, 0),   "Helvetica-Bold"),
                ("FONTSIZE",    (0, 0), (-1, -1), 8),
                ("GRID",        (0, 0), (-1, -1), 0.3, c("#2D2D4A")),
                ("TOPPADDING",  (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING",(0, 0), (-1, -1), 4),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ]))
            block.append(meta_table)
            block.append(Spacer(1, 3*mm))

            # Description
            if f.get("description"):
                block.append(Paragraph("Description", style_h3))
                block.append(Paragraph(f.get("description", "")[:800], style_body))

            # Evidence
            if f.get("evidence"):
                block.append(Paragraph("Evidence", style_h3))
                evidence_text = str(f.get("evidence", ""))[:600].replace("\n", "<br/>")
                block.append(Paragraph(evidence_text, style_code))

            # Remediation
            if f.get("remediation"):
                block.append(Paragraph("Remediation", style_h3))
                block.append(Paragraph(f.get("remediation", "")[:500], style_body))

            block.append(HRFlowable(color=c("#2D2D4A"), thickness=0.5, spaceAfter=6))
            elements.append(KeepTogether(block[:4]))  # Keep header + meta together
            elements.extend(block[4:])

        # Build PDF
        doc.build(elements)
        console.print(f"  [green]PDF:[/green] {out} ({len(self.findings)} findings)")
        return out

    def _overall_risk(self) -> str:
        for sev in SEVERITY_ORDER:
            if self.counts.get(sev, 0) > 0:
                return sev
        return "INFO"

    def _risk_label(self, severity: str) -> str:
        labels = {
            "CRITICAL": "Immediate action required",
            "HIGH":     "Address within 7 days",
            "MEDIUM":   "Address within 30 days",
            "LOW":      "Address in next sprint",
            "INFO":     "Informational only",
        }
        return labels.get(severity, "")

    def _generate_json_fallback(self) -> Path:
        """Fallback: save structured JSON report."""
        slug = self.target.replace("/", "_").replace(":", "")
        out  = self.output_dir / f"report_{slug}_{self.generated_at.strftime('%Y%m%d_%H%M%S')}.json"
        report = {
            "engagement":    self.engagement_name,
            "target":        self.target,
            "author":        self.author,
            "generated_at":  self.generated_at.isoformat(),
            "total_findings": len(self.findings),
            "severity_counts": dict(self.counts),
            "overall_risk":  self._overall_risk(),
            "findings":      self.sorted_findings,
        }
        out.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
        console.print(f"  [green]JSON report:[/green] {out}")
        return out
