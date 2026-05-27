"""
HTML Reporter — modules/report/html_reporter.py

Generates a self-contained interactive HTML pentest report.

Features:
  - Single-file HTML, zero external dependencies
  - Sortable findings table (click column headers)
  - Severity filter buttons
  - Expandable finding detail cards
  - CVSS color coding + severity badges
  - Doughnut chart — severity distribution
  - Evidence code blocks with copy button
  - Print-friendly CSS
  - Dark theme matching Glitchicons aesthetic

Usage:
    from modules.report.html_reporter import HTMLReporter

    reporter = HTMLReporter(
        findings=[...],
        target="target.com",
        org="Client Corp",
        report_type="internal",
        output_dir="./findings",
    )
    path = reporter.generate()
    print(f"Report: {path}")

Author: ardanov96
"""

import json
import html as html_lib
from datetime import datetime
from pathlib import Path
from collections import Counter


SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
SEVERITY_COLORS = {
    "CRITICAL": "#ff2d55",
    "HIGH":     "#ff6b35",
    "MEDIUM":   "#ffd60a",
    "LOW":      "#30d158",
    "INFO":     "#64d2ff",
}


class HTMLReporter:
    """Generate self-contained interactive HTML pentest report."""

    def __init__(
        self,
        findings: list[dict],
        target: str,
        org: str = "Unknown",
        report_type: str = "internal",
        output_dir: str = "./findings",
        tool_version: str = "0.7.0",
        engagement_duration: str = "N/A",
    ):
        self.findings = sorted(
            findings,
            key=lambda f: (SEVERITY_ORDER.get(f.get("severity", "INFO"), 99), -f.get("cvss", 0)),
        )
        self.target = target
        self.org = org
        self.report_type = report_type
        self.output_dir = Path(output_dir)
        self.tool_version = tool_version
        self.engagement_duration = engagement_duration
        self.generated_at = datetime.now()
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate(self) -> Path:
        """Generate HTML report. Return path to created file."""
        filename = f"report_{self.target.replace('.', '_')}_{self.generated_at.strftime('%Y%m%d_%H%M%S')}.html"
        out_path = self.output_dir / filename
        out_path.write_text(self._build_html(), encoding="utf-8")
        return out_path

    # ── Summary helpers ───────────────────────────────────

    def _severity_counts(self) -> dict:
        return dict(Counter(f.get("severity", "INFO") for f in self.findings))

    def _cvss_avg(self) -> float:
        if not self.findings:
            return 0.0
        scores = [f.get("cvss", 0) for f in self.findings if isinstance(f.get("cvss"), (int, float))]
        return round(sum(scores) / len(scores), 1) if scores else 0.0

    def _risk_rating(self) -> str:
        sev = self._severity_counts()
        if sev.get("CRITICAL", 0) > 0:
            return "CRITICAL"
        if sev.get("HIGH", 0) > 0:
            return "HIGH"
        if sev.get("MEDIUM", 0) > 0:
            return "MEDIUM"
        if sev.get("LOW", 0) > 0:
            return "LOW"
        return "INFO"

    # ── HTML builder ──────────────────────────────────────

    def _build_html(self) -> str:
        sev = self._severity_counts()
        risk = self._risk_rating()
        risk_color = SEVERITY_COLORS.get(risk, "#64d2ff")

        chart_data = json.dumps([
            sev.get("CRITICAL", 0),
            sev.get("HIGH", 0),
            sev.get("MEDIUM", 0),
            sev.get("LOW", 0),
            sev.get("INFO", 0),
        ])

        findings_json = json.dumps([
            {
                "id":          f.get("id", f"FIND-{i+1:03d}"),
                "title":       html_lib.escape(str(f.get("title", "Untitled"))),
                "severity":    f.get("severity", "INFO"),
                "cvss":        f.get("cvss", 0),
                "cwe":         html_lib.escape(str(f.get("cwe", "N/A"))),
                "description": html_lib.escape(str(f.get("description", ""))),
                "evidence":    html_lib.escape(str(f.get("evidence", ""))),
                "remediation": html_lib.escape(str(f.get("remediation", ""))),
                "target":      html_lib.escape(str(f.get("target", self.target))),
            }
            for i, f in enumerate(self.findings)
        ], indent=2)

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Pentest Report — {html_lib.escape(self.target)}</title>
<style>
  :root {{
    --bg:        #0d0f14;
    --surface:   #161a22;
    --surface2:  #1e2430;
    --border:    #2a3040;
    --text:      #e2e8f0;
    --muted:     #8892a4;
    --accent:    #7c5cbf;
    --accent2:   #9d7de8;
    --critical:  #ff2d55;
    --high:      #ff6b35;
    --medium:    #ffd60a;
    --low:       #30d158;
    --info:      #64d2ff;
    --radius:    10px;
    --font:      'Segoe UI', system-ui, sans-serif;
    --mono:      'Cascadia Code', 'Fira Code', monospace;
  }}

  * {{ box-sizing: border-box; margin: 0; padding: 0; }}

  body {{
    background: var(--bg);
    color: var(--text);
    font-family: var(--font);
    font-size: 14px;
    line-height: 1.6;
    padding: 0 0 60px;
  }}

  /* ── Header ── */
  .header {{
    background: linear-gradient(135deg, #0d0f14 0%, #1a1040 50%, #0d0f14 100%);
    border-bottom: 1px solid var(--accent);
    padding: 40px 48px 32px;
    position: relative;
    overflow: hidden;
  }}
  .header::before {{
    content: '⬡';
    position: absolute;
    right: 48px; top: 20px;
    font-size: 120px;
    opacity: 0.04;
    color: var(--accent2);
  }}
  .header-logo {{ font-size: 11px; letter-spacing: 4px; color: var(--accent2); margin-bottom: 8px; text-transform: uppercase; }}
  .header-title {{ font-size: 28px; font-weight: 700; color: var(--text); margin-bottom: 4px; }}
  .header-subtitle {{ color: var(--muted); font-size: 13px; }}
  .header-meta {{
    display: flex; gap: 32px; margin-top: 24px; flex-wrap: wrap;
  }}
  .header-meta-item {{ display: flex; flex-direction: column; gap: 2px; }}
  .header-meta-label {{ font-size: 10px; letter-spacing: 2px; color: var(--muted); text-transform: uppercase; }}
  .header-meta-value {{ font-size: 14px; font-weight: 600; color: var(--text); }}

  /* ── Risk badge ── */
  .risk-badge {{
    display: inline-flex; align-items: center; gap: 8px;
    padding: 6px 16px; border-radius: 20px;
    font-size: 12px; font-weight: 700; letter-spacing: 1px;
    background: {risk_color}22; border: 1px solid {risk_color};
    color: {risk_color};
    margin-top: 20px;
  }}
  .risk-badge::before {{ content: '●'; font-size: 8px; }}

  /* ── Layout ── */
  .container {{ max-width: 1200px; margin: 0 auto; padding: 0 32px; }}
  .section {{ margin-top: 40px; }}
  .section-title {{
    font-size: 11px; letter-spacing: 3px; color: var(--accent2);
    text-transform: uppercase; margin-bottom: 20px;
    padding-bottom: 8px; border-bottom: 1px solid var(--border);
  }}

  /* ── Summary cards ── */
  .summary-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
    gap: 12px; margin-bottom: 32px;
  }}
  .summary-card {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 20px 16px;
    text-align: center;
    transition: border-color 0.2s;
  }}
  .summary-card:hover {{ border-color: var(--accent); }}
  .summary-card.critical {{ border-top: 3px solid var(--critical); }}
  .summary-card.high     {{ border-top: 3px solid var(--high); }}
  .summary-card.medium   {{ border-top: 3px solid var(--medium); }}
  .summary-card.low      {{ border-top: 3px solid var(--low); }}
  .summary-card.info     {{ border-top: 3px solid var(--info); }}
  .summary-card.total    {{ border-top: 3px solid var(--accent); }}
  .summary-count {{
    font-size: 36px; font-weight: 800; line-height: 1;
    margin-bottom: 6px;
  }}
  .summary-label {{ font-size: 10px; letter-spacing: 2px; color: var(--muted); text-transform: uppercase; }}
  .c-critical {{ color: var(--critical); }}
  .c-high     {{ color: var(--high); }}
  .c-medium   {{ color: var(--medium); }}
  .c-low      {{ color: var(--low); }}
  .c-info     {{ color: var(--info); }}
  .c-accent   {{ color: var(--accent2); }}

  /* ── Chart ── */
  .chart-section {{
    display: flex; gap: 32px; align-items: center;
    background: var(--surface); border: 1px solid var(--border);
    border-radius: var(--radius); padding: 24px; margin-bottom: 32px;
  }}
  canvas#donut {{ width: 160px !important; height: 160px !important; flex-shrink: 0; }}
  .chart-legend {{ display: flex; flex-direction: column; gap: 10px; }}
  .legend-item {{ display: flex; align-items: center; gap: 10px; font-size: 13px; }}
  .legend-dot {{ width: 10px; height: 10px; border-radius: 50%; flex-shrink: 0; }}
  .legend-label {{ color: var(--muted); min-width: 70px; }}
  .legend-count {{ font-weight: 700; margin-left: auto; padding-left: 16px; }}

  /* ── Filter buttons ── */
  .filter-bar {{ display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 16px; align-items: center; }}
  .filter-label {{ color: var(--muted); font-size: 11px; letter-spacing: 1px; margin-right: 4px; }}
  .filter-btn {{
    padding: 5px 14px; border-radius: 20px; border: 1px solid var(--border);
    background: transparent; color: var(--muted); font-size: 12px;
    cursor: pointer; transition: all 0.15s; font-family: var(--font);
  }}
  .filter-btn:hover, .filter-btn.active {{
    background: var(--accent); border-color: var(--accent); color: #fff;
  }}
  .filter-btn.f-critical.active {{ background: var(--critical); border-color: var(--critical); }}
  .filter-btn.f-high.active    {{ background: var(--high);     border-color: var(--high); }}
  .filter-btn.f-medium.active  {{ background: #b89500;         border-color: var(--medium); color: #000; }}
  .filter-btn.f-low.active     {{ background: var(--low);      border-color: var(--low); color: #000; }}

  /* ── Search ── */
  .search-bar {{
    width: 100%; padding: 10px 16px;
    background: var(--surface); border: 1px solid var(--border);
    border-radius: var(--radius); color: var(--text);
    font-family: var(--font); font-size: 13px;
    margin-bottom: 16px; outline: none;
    transition: border-color 0.2s;
  }}
  .search-bar:focus {{ border-color: var(--accent); }}
  .search-bar::placeholder {{ color: var(--muted); }}

  /* ── Table ── */
  .findings-table {{
    width: 100%; border-collapse: collapse;
    background: var(--surface); border-radius: var(--radius);
    overflow: hidden; border: 1px solid var(--border);
  }}
  .findings-table th {{
    background: var(--surface2);
    padding: 12px 16px; text-align: left;
    font-size: 10px; letter-spacing: 2px; color: var(--muted);
    text-transform: uppercase; cursor: pointer;
    user-select: none; white-space: nowrap;
    border-bottom: 1px solid var(--border);
  }}
  .findings-table th:hover {{ color: var(--accent2); }}
  .findings-table th .sort-icon {{ margin-left: 4px; opacity: 0.4; }}
  .findings-table th.sorted .sort-icon {{ opacity: 1; color: var(--accent2); }}
  .findings-table td {{
    padding: 12px 16px; border-bottom: 1px solid var(--border);
    vertical-align: middle;
  }}
  .findings-table tr:last-child td {{ border-bottom: none; }}
  .findings-table tr {{ cursor: pointer; transition: background 0.1s; }}
  .findings-table tr:hover td {{ background: var(--surface2); }}
  .findings-table tr.hidden {{ display: none; }}

  /* ── Severity badge ── */
  .badge {{
    display: inline-block; padding: 2px 10px;
    border-radius: 12px; font-size: 10px; font-weight: 700;
    letter-spacing: 0.5px; text-transform: uppercase;
  }}
  .badge-CRITICAL {{ background: #ff2d5522; color: var(--critical); border: 1px solid #ff2d5544; }}
  .badge-HIGH     {{ background: #ff6b3522; color: var(--high);     border: 1px solid #ff6b3544; }}
  .badge-MEDIUM   {{ background: #ffd60a22; color: var(--medium);   border: 1px solid #ffd60a44; }}
  .badge-LOW      {{ background: #30d15822; color: var(--low);       border: 1px solid #30d15844; }}
  .badge-INFO     {{ background: #64d2ff22; color: var(--info);      border: 1px solid #64d2ff44; }}

  /* ── CVSS bar ── */
  .cvss-cell {{ white-space: nowrap; }}
  .cvss-score {{ font-weight: 700; font-size: 13px; margin-right: 8px; }}
  .cvss-bar-bg {{ display: inline-block; width: 60px; height: 5px; background: var(--border); border-radius: 3px; vertical-align: middle; }}
  .cvss-bar-fill {{ height: 100%; border-radius: 3px; }}

  /* ── Finding detail modal ── */
  .modal-overlay {{
    display: none; position: fixed; inset: 0;
    background: #00000088; z-index: 100;
    align-items: center; justify-content: center;
    padding: 24px;
  }}
  .modal-overlay.open {{ display: flex; }}
  .modal {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 14px;
    max-width: 760px; width: 100%;
    max-height: 85vh; overflow-y: auto;
    padding: 32px;
    position: relative;
    animation: slideUp 0.2s ease;
  }}
  @keyframes slideUp {{ from {{ transform: translateY(20px); opacity: 0; }} to {{ transform: none; opacity: 1; }} }}
  .modal-close {{
    position: absolute; right: 20px; top: 20px;
    background: var(--surface2); border: 1px solid var(--border);
    color: var(--muted); width: 30px; height: 30px;
    border-radius: 50%; cursor: pointer;
    font-size: 16px; display: flex; align-items: center; justify-content: center;
    transition: all 0.15s;
  }}
  .modal-close:hover {{ background: var(--critical); color: #fff; border-color: var(--critical); }}
  .modal-id {{ font-size: 10px; letter-spacing: 2px; color: var(--accent2); margin-bottom: 8px; }}
  .modal-title {{ font-size: 20px; font-weight: 700; margin-bottom: 16px; line-height: 1.3; }}
  .modal-meta {{ display: flex; gap: 16px; flex-wrap: wrap; margin-bottom: 24px; align-items: center; }}
  .modal-section {{ margin-bottom: 20px; }}
  .modal-section-label {{
    font-size: 10px; letter-spacing: 2px; color: var(--muted);
    text-transform: uppercase; margin-bottom: 8px;
  }}
  .modal-section-text {{ color: var(--text); line-height: 1.7; }}
  .evidence-block {{
    background: var(--bg); border: 1px solid var(--border);
    border-radius: 8px; padding: 16px;
    font-family: var(--mono); font-size: 12px; color: #a8b4c4;
    white-space: pre-wrap; word-break: break-all;
    position: relative; margin-top: 8px;
  }}
  .copy-btn {{
    position: absolute; right: 10px; top: 10px;
    background: var(--surface2); border: 1px solid var(--border);
    color: var(--muted); padding: 3px 10px;
    border-radius: 6px; cursor: pointer; font-size: 11px;
    transition: all 0.15s;
  }}
  .copy-btn:hover {{ background: var(--accent); color: #fff; border-color: var(--accent); }}

  /* ── Empty state ── */
  .empty-state {{
    text-align: center; padding: 48px; color: var(--muted);
  }}
  .empty-state-icon {{ font-size: 40px; margin-bottom: 12px; opacity: 0.3; }}

  /* ── Footer ── */
  .footer {{
    margin-top: 60px; padding: 24px 48px;
    border-top: 1px solid var(--border);
    display: flex; justify-content: space-between;
    align-items: center; color: var(--muted); font-size: 12px;
  }}
  .footer-logo {{ color: var(--accent2); font-weight: 700; letter-spacing: 2px; }}

  /* ── Print ── */
  @media print {{
    .filter-bar, .search-bar, .modal-overlay, .copy-btn {{ display: none !important; }}
    body {{ background: white; color: black; }}
    .header {{ background: white; border-bottom: 2px solid #333; }}
    .findings-table {{ border: 1px solid #ccc; }}
    .findings-table th {{ background: #f5f5f5; color: #333; }}
  }}

  /* ── Scrollbar ── */
  ::-webkit-scrollbar {{ width: 6px; }}
  ::-webkit-scrollbar-track {{ background: var(--bg); }}
  ::-webkit-scrollbar-thumb {{ background: var(--border); border-radius: 3px; }}
  ::-webkit-scrollbar-thumb:hover {{ background: var(--accent); }}
</style>
</head>
<body>

<!-- Header -->
<div class="header">
  <div class="header-logo">⬡ Glitchicons Security Platform</div>
  <div class="header-title">Penetration Test Report</div>
  <div class="header-subtitle">{html_lib.escape(self.target)}</div>
  <div class="header-meta">
    <div class="header-meta-item">
      <span class="header-meta-label">Organization</span>
      <span class="header-meta-value">{html_lib.escape(self.org)}</span>
    </div>
    <div class="header-meta-item">
      <span class="header-meta-label">Date</span>
      <span class="header-meta-value">{self.generated_at.strftime('%Y-%m-%d')}</span>
    </div>
    <div class="header-meta-item">
      <span class="header-meta-label">Report Type</span>
      <span class="header-meta-value">{html_lib.escape(self.report_type.title())}</span>
    </div>
    <div class="header-meta-item">
      <span class="header-meta-label">Duration</span>
      <span class="header-meta-value">{html_lib.escape(self.engagement_duration)}</span>
    </div>
    <div class="header-meta-item">
      <span class="header-meta-label">Tool</span>
      <span class="header-meta-value">Glitchicons v{html_lib.escape(self.tool_version)}</span>
    </div>
    <div class="header-meta-item">
      <span class="header-meta-label">Avg CVSS</span>
      <span class="header-meta-value">{self._cvss_avg()}</span>
    </div>
  </div>
  <div class="risk-badge">Overall Risk: {html_lib.escape(risk)}</div>
</div>

<div class="container">

  <!-- Executive Summary -->
  <div class="section">
    <div class="section-title">Executive Summary</div>
    <div class="summary-grid">
      <div class="summary-card total">
        <div class="summary-count c-accent">{len(self.findings)}</div>
        <div class="summary-label">Total Findings</div>
      </div>
      <div class="summary-card critical">
        <div class="summary-count c-critical">{sev.get('CRITICAL', 0)}</div>
        <div class="summary-label">Critical</div>
      </div>
      <div class="summary-card high">
        <div class="summary-count c-high">{sev.get('HIGH', 0)}</div>
        <div class="summary-label">High</div>
      </div>
      <div class="summary-card medium">
        <div class="summary-count c-medium">{sev.get('MEDIUM', 0)}</div>
        <div class="summary-label">Medium</div>
      </div>
      <div class="summary-card low">
        <div class="summary-count c-low">{sev.get('LOW', 0)}</div>
        <div class="summary-label">Low</div>
      </div>
      <div class="summary-card info">
        <div class="summary-count c-info">{sev.get('INFO', 0)}</div>
        <div class="summary-label">Info</div>
      </div>
    </div>

    <!-- Chart -->
    <div class="chart-section">
      <canvas id="donut"></canvas>
      <div class="chart-legend">
        <div class="legend-item">
          <div class="legend-dot" style="background:var(--critical)"></div>
          <span class="legend-label">Critical</span>
          <span class="legend-count c-critical">{sev.get('CRITICAL', 0)}</span>
        </div>
        <div class="legend-item">
          <div class="legend-dot" style="background:var(--high)"></div>
          <span class="legend-label">High</span>
          <span class="legend-count c-high">{sev.get('HIGH', 0)}</span>
        </div>
        <div class="legend-item">
          <div class="legend-dot" style="background:var(--medium)"></div>
          <span class="legend-label">Medium</span>
          <span class="legend-count c-medium">{sev.get('MEDIUM', 0)}</span>
        </div>
        <div class="legend-item">
          <div class="legend-dot" style="background:var(--low)"></div>
          <span class="legend-label">Low</span>
          <span class="legend-count c-low">{sev.get('LOW', 0)}</span>
        </div>
        <div class="legend-item">
          <div class="legend-dot" style="background:var(--info)"></div>
          <span class="legend-label">Info</span>
          <span class="legend-count c-info">{sev.get('INFO', 0)}</span>
        </div>
      </div>
    </div>
  </div>

  <!-- Findings Table -->
  <div class="section">
    <div class="section-title">Findings</div>

    <div class="filter-bar">
      <span class="filter-label">Filter:</span>
      <button class="filter-btn active" data-filter="ALL">All ({len(self.findings)})</button>
      <button class="filter-btn f-critical" data-filter="CRITICAL">Critical ({sev.get('CRITICAL', 0)})</button>
      <button class="filter-btn f-high"     data-filter="HIGH">High ({sev.get('HIGH', 0)})</button>
      <button class="filter-btn f-medium"   data-filter="MEDIUM">Medium ({sev.get('MEDIUM', 0)})</button>
      <button class="filter-btn f-low"      data-filter="LOW">Low ({sev.get('LOW', 0)})</button>
    </div>

    <input class="search-bar" type="text" id="searchBar" placeholder="Search findings by title, CWE, description...">

    <div id="tableWrap">
      <table class="findings-table" id="findingsTable">
        <thead>
          <tr>
            <th data-col="id">ID <span class="sort-icon">↕</span></th>
            <th data-col="severity">Severity <span class="sort-icon">↕</span></th>
            <th data-col="cvss">CVSS <span class="sort-icon">↕</span></th>
            <th data-col="title">Title <span class="sort-icon">↕</span></th>
            <th data-col="cwe">CWE <span class="sort-icon">↕</span></th>
          </tr>
        </thead>
        <tbody id="findingsTbody">
        </tbody>
      </table>
      <div class="empty-state" id="emptyState" style="display:none">
        <div class="empty-state-icon">⬡</div>
        <div>No findings match your filter</div>
      </div>
    </div>
  </div>

</div>

<!-- Finding Detail Modal -->
<div class="modal-overlay" id="modalOverlay">
  <div class="modal" id="modal">
    <button class="modal-close" id="modalClose">✕</button>
    <div class="modal-id" id="modalId"></div>
    <div class="modal-title" id="modalTitle"></div>
    <div class="modal-meta" id="modalMeta"></div>

    <div class="modal-section">
      <div class="modal-section-label">Description</div>
      <div class="modal-section-text" id="modalDesc"></div>
    </div>

    <div class="modal-section">
      <div class="modal-section-label">Evidence</div>
      <div class="evidence-block" id="modalEvidence">
        <button class="copy-btn" id="copyBtn">Copy</button>
        <span id="modalEvidenceText"></span>
      </div>
    </div>

    <div class="modal-section">
      <div class="modal-section-label">Remediation</div>
      <div class="modal-section-text" id="modalRemediation"></div>
    </div>
  </div>
</div>

<!-- Footer -->
<div class="footer">
  <div>
    Generated {self.generated_at.strftime('%Y-%m-%d %H:%M:%S')} ·
    Confidential — {html_lib.escape(self.org)}
  </div>
  <div class="footer-logo">⬡ GLITCHICONS</div>
</div>

<script>
const FINDINGS = {findings_json};

const SEV_ORDER = {{CRITICAL:0, HIGH:1, MEDIUM:2, LOW:3, INFO:4}};
const SEV_COLORS = {{
  CRITICAL: '#ff2d55', HIGH: '#ff6b35',
  MEDIUM: '#ffd60a', LOW: '#30d158', INFO: '#64d2ff'
}};

let currentFilter = 'ALL';
let sortCol = 'severity';
let sortDir = 1;
let currentFindings = [...FINDINGS];

// ── Donut chart (pure canvas, no libs) ──
function drawDonut() {{
  const canvas = document.getElementById('donut');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const dpr = window.devicePixelRatio || 1;
  const size = 160;
  canvas.width = size * dpr;
  canvas.height = size * dpr;
  canvas.style.width = size + 'px';
  canvas.style.height = size + 'px';
  ctx.scale(dpr, dpr);

  const data = {chart_data};
  const colors = ['#ff2d55','#ff6b35','#ffd60a','#30d158','#64d2ff'];
  const total = data.reduce((a,b) => a+b, 0);

  const cx = size/2, cy = size/2, r = 68, inner = 42;
  let angle = -Math.PI/2;

  if (total === 0) {{
    ctx.beginPath();
    ctx.arc(cx, cy, r, 0, Math.PI*2);
    ctx.arc(cx, cy, inner, Math.PI*2, 0, true);
    ctx.fillStyle = '#2a3040';
    ctx.fill();
  }} else {{
    data.forEach((val, i) => {{
      if (val === 0) return;
      const slice = (val / total) * Math.PI * 2;
      ctx.beginPath();
      ctx.moveTo(cx, cy);
      ctx.arc(cx, cy, r, angle, angle + slice);
      ctx.closePath();
      ctx.fillStyle = colors[i];
      ctx.fill();
      angle += slice;
    }});
    ctx.beginPath();
    ctx.arc(cx, cy, inner, 0, Math.PI*2);
    ctx.fillStyle = '#161a22';
    ctx.fill();
  }}

  ctx.fillStyle = '#e2e8f0';
  ctx.font = 'bold 22px Segoe UI, system-ui, sans-serif';
  ctx.textAlign = 'center';
  ctx.textBaseline = 'middle';
  ctx.fillText(total, cx, cy - 6);
  ctx.fillStyle = '#8892a4';
  ctx.font = '10px Segoe UI, system-ui, sans-serif';
  ctx.fillText('findings', cx, cy + 12);
}}

// ── CVSS bar ──
function cvssBar(score) {{
  const pct = (score / 10) * 100;
  const color = score >= 9 ? 'var(--critical)'
    : score >= 7 ? 'var(--high)'
    : score >= 4 ? 'var(--medium)'
    : score >  0 ? 'var(--low)'
    : 'var(--info)';
  return `<span class="cvss-score" style="color:${{color}}">${{score}}</span>
    <span class="cvss-bar-bg">
      <span class="cvss-bar-fill" style="width:${{pct}}%;background:${{color}}"></span>
    </span>`;
}}

// ── Render table ──
function renderTable() {{
  const tbody = document.getElementById('findingsTbody');
  const emptyState = document.getElementById('emptyState');
  const search = document.getElementById('searchBar').value.toLowerCase();

  let filtered = currentFindings.filter(f => {{
    if (currentFilter !== 'ALL' && f.severity !== currentFilter) return false;
    if (search) {{
      const haystack = (f.title + f.cwe + f.description + f.severity).toLowerCase();
      if (!haystack.includes(search)) return false;
    }}
    return true;
  }});

  if (filtered.length === 0) {{
    tbody.innerHTML = '';
    emptyState.style.display = 'block';
    return;
  }}
  emptyState.style.display = 'none';

  tbody.innerHTML = filtered.map(f => `
    <tr data-id="${{f.id}}" onclick="openModal('${{f.id}}')">
      <td style="font-family:monospace;font-size:12px;color:var(--muted)">${{f.id}}</td>
      <td><span class="badge badge-${{f.severity}}">${{f.severity}}</span></td>
      <td class="cvss-cell">${{cvssBar(f.cvss)}}</td>
      <td>${{f.title}}</td>
      <td style="color:var(--muted);font-size:12px">${{f.cwe}}</td>
    </tr>
  `).join('');
}}

// ── Sorting ──
document.querySelectorAll('th[data-col]').forEach(th => {{
  th.addEventListener('click', () => {{
    const col = th.dataset.col;
    if (sortCol === col) {{ sortDir *= -1; }}
    else {{ sortCol = col; sortDir = 1; }}

    document.querySelectorAll('th').forEach(t => t.classList.remove('sorted'));
    th.classList.add('sorted');
    const icon = th.querySelector('.sort-icon');
    icon.textContent = sortDir === 1 ? '↑' : '↓';

    currentFindings.sort((a, b) => {{
      if (col === 'severity') return sortDir * (SEV_ORDER[a.severity] - SEV_ORDER[b.severity]);
      if (col === 'cvss')     return sortDir * (b.cvss - a.cvss) * -1;
      return sortDir * String(a[col]).localeCompare(String(b[col]));
    }});
    renderTable();
  }});
}});

// ── Filter ──
document.querySelectorAll('.filter-btn').forEach(btn => {{
  btn.addEventListener('click', () => {{
    document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    currentFilter = btn.dataset.filter;
    renderTable();
  }});
}});

// ── Search ──
document.getElementById('searchBar').addEventListener('input', renderTable);

// ── Modal ──
function openModal(id) {{
  const f = FINDINGS.find(x => x.id === id);
  if (!f) return;

  document.getElementById('modalId').textContent = f.id;
  document.getElementById('modalTitle').textContent = f.title;
  document.getElementById('modalDesc').textContent = f.description;
  document.getElementById('modalEvidenceText').textContent = f.evidence;
  document.getElementById('modalRemediation').textContent = f.remediation;

  const color = SEV_COLORS[f.severity] || '#64d2ff';
  document.getElementById('modalMeta').innerHTML = `
    <span class="badge badge-${{f.severity}}">${{f.severity}}</span>
    <span style="color:${{color}};font-weight:700">CVSS ${{f.cvss}}</span>
    <span style="color:var(--muted);font-size:12px">${{f.cwe}}</span>
    <span style="color:var(--muted);font-size:12px">${{f.target}}</span>
  `;

  document.getElementById('modalOverlay').classList.add('open');
  document.body.style.overflow = 'hidden';
}}

function closeModal() {{
  document.getElementById('modalOverlay').classList.remove('open');
  document.body.style.overflow = '';
}}

document.getElementById('modalClose').addEventListener('click', closeModal);
document.getElementById('modalOverlay').addEventListener('click', e => {{
  if (e.target === document.getElementById('modalOverlay')) closeModal();
}});
document.addEventListener('keydown', e => {{ if (e.key === 'Escape') closeModal(); }});

// ── Copy evidence ──
document.getElementById('copyBtn').addEventListener('click', () => {{
  const text = document.getElementById('modalEvidenceText').textContent;
  navigator.clipboard.writeText(text).then(() => {{
    const btn = document.getElementById('copyBtn');
    btn.textContent = 'Copied!';
    setTimeout(() => {{ btn.textContent = 'Copy'; }}, 1500);
  }});
}});

// ── Init ──
drawDonut();
currentFindings = [...FINDINGS];
renderTable();
</script>
</body>
</html>"""
