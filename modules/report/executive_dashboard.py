"""
Executive Dashboard — modules/report/executive_dashboard.py

Generates a self-contained HTML executive dashboard from Glitchicons findings.

Features:
  - Dark themed (matches Glitchicons brand)
  - Severity donut chart (Chart.js CDN)
  - CVSS distribution bar chart
  - Finding cards with expandable evidence
  - Remediation priority heatmap
  - Top 5 critical findings at a glance
  - Fully self-contained (no server needed)
  - Print-to-PDF ready

Usage:
    from modules.report.executive_dashboard import ExecutiveDashboard

    dashboard = ExecutiveDashboard(
        findings=findings,
        target="target.com",
        output_dir="./findings/reports",
        engagement_name="Target Corp — Security Assessment",
    )
    path = dashboard.generate()

Author: ardanov96
"""

import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from rich.console import Console

console = Console()

SEVERITY_COLORS = {
    "CRITICAL": "#FF0040",
    "HIGH":     "#FF6B35",
    "MEDIUM":   "#FFB300",
    "LOW":      "#30D158",
    "INFO":     "#64D2FF",
}

SEVERITY_BG = {
    "CRITICAL": "rgba(255,0,64,.15)",
    "HIGH":     "rgba(255,107,53,.12)",
    "MEDIUM":   "rgba(255,179,0,.12)",
    "LOW":      "rgba(48,209,88,.1)",
    "INFO":     "rgba(100,210,255,.1)",
}

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


class ExecutiveDashboard:
    """
    Generate a self-contained HTML executive dashboard.

    Single HTML file with embedded CSS + JS + Chart.js from CDN.
    No server required — open directly in browser.
    """

    def __init__(
        self,
        findings: list[dict],
        target: str,
        output_dir: str = "./findings/reports",
        engagement_name: str = "",
        author: str = "Glitchicons Security",
    ):
        self.findings        = findings
        self.target          = target
        self.output_dir      = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.engagement_name = engagement_name or f"Security Assessment — {target}"
        self.author          = author
        self.generated_at    = datetime.now(timezone.utc)
        self.counts          = Counter(f.get("severity", "INFO") for f in findings)

        self.sorted_findings = sorted(
            findings,
            key=lambda f: SEVERITY_ORDER.index(f.get("severity", "INFO"))
            if f.get("severity", "INFO") in SEVERITY_ORDER else 99
        )

    def generate(self) -> Path:
        """Generate the HTML dashboard file."""
        slug = self.target.replace("/", "_").replace(":", "")
        out  = self.output_dir / f"dashboard_{slug}_{self.generated_at.strftime('%Y%m%d_%H%M%S')}.html"
        html = self._build_html()
        out.write_text(html, encoding="utf-8")
        console.print(f"  [green]Dashboard:[/green] {out}")
        return out

    def _build_html(self) -> str:
        avg_cvss = (
            sum(f.get("cvss", 0) for f in self.findings) / len(self.findings)
            if self.findings else 0.0
        )
        overall = self._overall_risk()
        overall_color = SEVERITY_COLORS.get(overall, "#64D2FF")

        # Chart.js data
        chart_labels = json.dumps(
            [s for s in SEVERITY_ORDER if self.counts.get(s, 0) > 0]
        )
        chart_data = json.dumps(
            [self.counts.get(s, 0) for s in SEVERITY_ORDER if self.counts.get(s, 0) > 0]
        )
        chart_colors = json.dumps(
            [SEVERITY_COLORS[s] for s in SEVERITY_ORDER if self.counts.get(s, 0) > 0]
        )

        # CVSS distribution (buckets)
        cvss_buckets = [0] * 10  # 0-1, 1-2, ... 9-10
        for f in self.findings:
            cvss = float(f.get("cvss", 0))
            bucket = min(int(cvss), 9)
            cvss_buckets[bucket] += 1

        # Finding cards HTML
        cards_html = "\n".join(self._finding_card(i + 1, f)
                               for i, f in enumerate(self.sorted_findings))

        # Top 5 critical table
        top5 = [f for f in self.sorted_findings if f.get("severity") in ("CRITICAL", "HIGH")][:5]
        top5_rows = "\n".join(self._top5_row(f) for f in top5)

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{self.engagement_name} — Security Report</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.min.js"></script>
<style>
:root {{
  --bg: #06060D; --bg2: #0D0D1A; --bg3: #131326;
  --purple: #6B00FF; --purple-bright: #A855F7; --purple-glow: #BF00FF;
  --text: #E8E8F8; --text2: #9898B8; --text3: #4A4A6A;
  --border: rgba(107,0,255,.2);
}}
* {{ margin:0; padding:0; box-sizing:border-box; }}
body {{ background:var(--bg); color:var(--text); font-family:'Segoe UI',system-ui,sans-serif; }}
.container {{ max-width:1200px; margin:0 auto; padding:2rem; }}

/* Header */
.header {{ border-bottom:1px solid var(--border); padding-bottom:1.5rem; margin-bottom:2rem; }}
.header-top {{ display:flex; justify-content:space-between; align-items:flex-start; flex-wrap:wrap; gap:1rem; }}
.badge {{ font-size:.65rem; letter-spacing:.25em; color:#FF00AA; border:1px solid rgba(255,0,170,.4); padding:.25rem .75rem; display:inline-block; }}
.title {{ font-size:1.6rem; font-weight:700; color:var(--text); margin:.5rem 0 .25rem; }}
.subtitle {{ font-size:.9rem; color:var(--text2); }}
.meta-grid {{ display:flex; gap:2rem; flex-wrap:wrap; margin-top:1rem; }}
.meta-item {{ font-size:.75rem; color:var(--text3); }}
.meta-item strong {{ color:var(--text2); display:block; }}

/* Stat cards */
.stats {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(140px,1fr)); gap:1rem; margin-bottom:2rem; }}
.stat {{ background:var(--bg3); border:1px solid var(--border); padding:1.25rem; text-align:center; }}
.stat-num {{ font-size:2rem; font-weight:700; line-height:1; }}
.stat-label {{ font-size:.7rem; letter-spacing:.12em; color:var(--text3); text-transform:uppercase; margin-top:.25rem; }}

/* Charts row */
.charts {{ display:grid; grid-template-columns:320px 1fr; gap:1.5rem; margin-bottom:2rem; }}
@media(max-width:700px){{ .charts {{ grid-template-columns:1fr; }} }}
.chart-box {{ background:var(--bg3); border:1px solid var(--border); padding:1.5rem; }}
.chart-title {{ font-size:.75rem; letter-spacing:.15em; color:var(--purple-bright); text-transform:uppercase; margin-bottom:1rem; }}
.donut-wrap {{ position:relative; width:220px; margin:0 auto; }}
.donut-center {{ position:absolute; top:50%; left:50%; transform:translate(-50%,-50%); text-align:center; pointer-events:none; }}
.donut-center-num {{ font-size:2rem; font-weight:700; color:{overall_color}; }}
.donut-center-label {{ font-size:.65rem; color:var(--text3); }}

/* Top 5 table */
.section-title {{ font-size:.75rem; letter-spacing:.2em; color:var(--purple-bright); text-transform:uppercase; margin-bottom:1rem; padding-bottom:.5rem; border-bottom:1px solid var(--border); }}
.top5-table {{ width:100%; border-collapse:collapse; font-size:.85rem; margin-bottom:2rem; }}
.top5-table th {{ text-align:left; padding:.6rem .75rem; background:var(--bg3); color:var(--text3); font-size:.7rem; letter-spacing:.1em; font-weight:500; border-bottom:1px solid var(--border); }}
.top5-table td {{ padding:.65rem .75rem; border-bottom:1px solid rgba(255,255,255,.04); color:var(--text2); vertical-align:top; }}
.top5-table tr:hover td {{ background:var(--bg2); }}
.sev-badge {{ display:inline-block; font-size:.65rem; font-weight:700; padding:.15rem .5rem; border-radius:2px; }}

/* Finding cards */
.findings-grid {{ display:flex; flex-direction:column; gap:1rem; }}
.finding-card {{ background:var(--bg3); border:1px solid var(--border); border-left:3px solid var(--border); overflow:hidden; transition:border-color .2s; }}
.finding-card:hover {{ border-color:rgba(107,0,255,.4); }}
.finding-header {{ display:flex; align-items:center; gap:.75rem; padding:1rem 1.25rem; cursor:pointer; user-select:none; }}
.finding-num {{ font-size:.7rem; color:var(--text3); min-width:2rem; }}
.finding-title {{ flex:1; font-size:.95rem; font-weight:600; color:var(--text); }}
.finding-cvss {{ font-size:.75rem; color:var(--text2); white-space:nowrap; }}
.finding-body {{ display:none; padding:0 1.25rem 1rem; border-top:1px solid rgba(255,255,255,.05); }}
.finding-body.open {{ display:block; }}
.finding-meta {{ display:flex; flex-wrap:wrap; gap:1rem; margin:.75rem 0; }}
.meta-chip {{ font-size:.7rem; background:rgba(107,0,255,.1); border:1px solid rgba(107,0,255,.2); padding:.2rem .6rem; color:var(--text2); }}
.field-label {{ font-size:.7rem; letter-spacing:.12em; color:var(--text3); text-transform:uppercase; margin:.75rem 0 .25rem; }}
.field-value {{ font-size:.85rem; color:var(--text2); line-height:1.6; }}
.evidence-block {{ font-family:monospace; font-size:.78rem; background:var(--bg2); border:1px solid var(--border); padding:.75rem; color:#C8C8E8; white-space:pre-wrap; word-break:break-all; max-height:200px; overflow-y:auto; }}
.toggle-btn {{ font-size:.65rem; color:var(--purple-bright); border:1px solid rgba(107,0,255,.3); padding:.2rem .5rem; background:transparent; cursor:pointer; white-space:nowrap; }}

/* Footer */
.footer {{ margin-top:3rem; padding-top:1.5rem; border-top:1px solid var(--border); font-size:.7rem; color:var(--text3); display:flex; justify-content:space-between; flex-wrap:wrap; gap:.5rem; }}
</style>
</head>
<body>
<div class="container">

<!-- Header -->
<div class="header">
  <div class="header-top">
    <div>
      <div class="badge">⬡ GLITCHICONS · SECURITY REPORT</div>
      <div class="title">{self.engagement_name}</div>
      <div class="subtitle">Penetration Test — Executive Dashboard</div>
    </div>
    <div style="text-align:right">
      <div style="font-size:1.5rem;font-weight:700;color:{overall_color}">{overall}</div>
      <div style="font-size:.7rem;color:var(--text3)">OVERALL RISK</div>
    </div>
  </div>
  <div class="meta-grid">
    <div class="meta-item"><strong>Target</strong>{self.target}</div>
    <div class="meta-item"><strong>Author</strong>{self.author}</div>
    <div class="meta-item"><strong>Generated</strong>{self.generated_at.strftime('%Y-%m-%d %H:%M UTC')}</div>
    <div class="meta-item"><strong>Total Findings</strong>{len(self.findings)}</div>
  </div>
</div>

<!-- Stats -->
<div class="stats">
{self._stat_cards()}
</div>

<!-- Charts -->
<div class="charts">
  <div class="chart-box">
    <div class="chart-title">Severity Distribution</div>
    <div class="donut-wrap">
      <canvas id="donutChart" width="220" height="220"></canvas>
      <div class="donut-center">
        <div class="donut-center-num">{len(self.findings)}</div>
        <div class="donut-center-label">FINDINGS</div>
      </div>
    </div>
  </div>
  <div class="chart-box">
    <div class="chart-title">CVSS Score Distribution</div>
    <canvas id="cvssChart" height="180"></canvas>
  </div>
</div>

<!-- Top 5 Critical -->
<div class="section-title">⚠ Top Critical & High Findings</div>
<table class="top5-table">
  <thead><tr>
    <th>#</th><th>Title</th><th>Severity</th><th>CVSS</th><th>CWE</th><th>Target</th>
  </tr></thead>
  <tbody>{top5_rows}</tbody>
</table>

<!-- All Findings -->
<div class="section-title">All Findings ({len(self.findings)})</div>
<div class="findings-grid">
{cards_html}
</div>

<!-- Footer -->
<div class="footer">
  <span>GLITCHICONS Security Platform v1.6.0 · MIT License</span>
  <span>Generated {self.generated_at.strftime('%Y-%m-%d %H:%M UTC')}</span>
</div>

</div><!-- /container -->

<script>
// Donut chart
new Chart(document.getElementById('donutChart'), {{
  type: 'doughnut',
  data: {{
    labels: {chart_labels},
    datasets: [{{ data: {chart_data}, backgroundColor: {chart_colors}, borderWidth: 1, borderColor: '#06060D', hoverOffset: 4 }}]
  }},
  options: {{
    cutout: '72%', plugins: {{ legend: {{ display: false }} }},
    animation: {{ animateRotate: true, duration: 800 }}
  }}
}});

// CVSS bar chart
new Chart(document.getElementById('cvssChart'), {{
  type: 'bar',
  data: {{
    labels: ['0','1','2','3','4','5','6','7','8','9'],
    datasets: [{{
      label: 'Findings',
      data: {json.dumps(cvss_buckets)},
      backgroundColor: ['#64D2FF','#64D2FF','#64D2FF','#30D158','#FFB300','#FFB300','#FFB300','#FF6B35','#FF0040','#FF0040'],
      borderRadius: 2, borderSkipped: false
    }}]
  }},
  options: {{
    responsive: true,
    plugins: {{ legend: {{ display: false }} }},
    scales: {{
      x: {{ grid: {{ color: 'rgba(107,0,255,.1)' }}, ticks: {{ color: '#6B6B90' }} }},
      y: {{ grid: {{ color: 'rgba(107,0,255,.1)' }}, ticks: {{ color: '#6B6B90', stepSize: 1 }} }}
    }}
  }}
}});

// Toggle finding details
document.querySelectorAll('.finding-header').forEach(function(h) {{
  h.addEventListener('click', function() {{
    var body = this.nextElementSibling;
    body.classList.toggle('open');
    var btn = this.querySelector('.toggle-btn');
    if(btn) btn.textContent = body.classList.contains('open') ? '▲ COLLAPSE' : '▼ EXPAND';
  }});
}});
</script>
</body>
</html>"""

    def _stat_cards(self) -> str:
        cards = []
        for sev in SEVERITY_ORDER:
            count = self.counts.get(sev, 0)
            if count == 0:
                continue
            color = SEVERITY_COLORS[sev]
            cards.append(
                f'<div class="stat" style="border-top:2px solid {color}">'
                f'<div class="stat-num" style="color:{color}">{count}</div>'
                f'<div class="stat-label">{sev}</div>'
                f'</div>'
            )

        avg_cvss = (sum(f.get("cvss", 0) for f in self.findings) / len(self.findings)
                    if self.findings else 0)
        cards.append(
            f'<div class="stat" style="border-top:2px solid #A855F7">'
            f'<div class="stat-num" style="color:#A855F7">{avg_cvss:.1f}</div>'
            f'<div class="stat-label">Avg CVSS</div>'
            f'</div>'
        )
        return "\n".join(cards)

    def _finding_card(self, num: int, f: dict) -> str:
        sev   = f.get("severity", "INFO")
        color = SEVERITY_COLORS.get(sev, "#64D2FF")
        bg    = SEVERITY_BG.get(sev, "rgba(100,210,255,.1)")
        title = f.get("title", "Untitled")
        cvss  = f.get("cvss", 0.0)
        cwe   = f.get("cwe", "N/A")
        desc  = f.get("description", "")[:400]
        evid  = f.get("evidence", "N/A")[:500]
        rem   = f.get("remediation", "")[:400]
        tgt   = str(f.get("target", "N/A"))[:80]

        return f"""<div class="finding-card" style="border-left-color:{color}">
  <div class="finding-header">
    <span class="finding-num">{num:02d}</span>
    <span class="sev-badge" style="background:{bg};color:{color}">{sev}</span>
    <span class="finding-title">{title}</span>
    <span class="finding-cvss">CVSS {cvss:.1f}</span>
    <button class="toggle-btn">▼ EXPAND</button>
  </div>
  <div class="finding-body">
    <div class="finding-meta">
      <span class="meta-chip">CWE: {cwe}</span>
      <span class="meta-chip">CVSS: {cvss:.1f}</span>
      <span class="meta-chip">Target: {tgt}</span>
    </div>
    <div class="field-label">Description</div>
    <div class="field-value">{desc}</div>
    <div class="field-label">Evidence</div>
    <div class="evidence-block">{evid}</div>
    <div class="field-label">Remediation</div>
    <div class="field-value">{rem}</div>
  </div>
</div>"""

    def _top5_row(self, f: dict) -> str:
        sev   = f.get("severity", "INFO")
        color = SEVERITY_COLORS.get(sev, "#64D2FF")
        bg    = SEVERITY_BG.get(sev, "transparent")
        return (
            f'<tr>'
            f'<td><span class="sev-badge" style="background:{bg};color:{color}">{sev}</span></td>'
            f'<td style="color:var(--text)">{f.get("title","")[:60]}</td>'
            f'<td style="color:{color};font-weight:700">{f.get("cvss",0):.1f}</td>'
            f'<td style="color:var(--text2)">{f.get("cwe","N/A")}</td>'
            f'<td style="color:var(--text3);font-size:.8rem">{str(f.get("target",""))[:40]}</td>'
            f'</tr>'
        )

    def _overall_risk(self) -> str:
        for sev in SEVERITY_ORDER:
            if self.counts.get(sev, 0) > 0:
                return sev
        return "INFO"
