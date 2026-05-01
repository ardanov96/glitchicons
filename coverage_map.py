"""
GLITCHICONS ⬡ — Coverage Map Module
Decepticons Siege Division

Tracks and visualizes code coverage from AFL++ fuzzing sessions.
Shows which code paths have been hit and which remain unexplored.

Features:
- Parse AFL++ coverage data (bitmap + lcov)
- Parse gcov/LLVM coverage output
- Generate interactive HTML coverage map
- Identify uncovered paths → feed back to LLM for targeted seeds
- Coverage diff between sessions (progress tracking)
"""

import re
import json
import subprocess
import shutil
from pathlib import Path
from datetime import datetime
from typing import Optional
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn

console = Console()


# ══════════════════════════════════════════════════════════════════════════════
# COVERAGE DATA STRUCTURES
# ══════════════════════════════════════════════════════════════════════════════

class FunctionCoverage:
    """Coverage data for a single function."""
    def __init__(self, name: str, file: str, line: int):
        self.name = name
        self.file = file
        self.line = line
        self.hit_count = 0
        self.lines_total = 0
        self.lines_covered = 0
        self.branches_total = 0
        self.branches_covered = 0

    @property
    def line_coverage_pct(self) -> float:
        if self.lines_total == 0:
            return 0.0
        return round(self.lines_covered / self.lines_total * 100, 1)

    @property
    def branch_coverage_pct(self) -> float:
        if self.branches_total == 0:
            return 0.0
        return round(self.branches_covered / self.branches_total * 100, 1)

    @property
    def severity(self) -> str:
        """How critical is this uncovered function?"""
        dangerous = ["parse", "process", "handle", "decode", "validate",
                     "auth", "exec", "run", "load", "read"]
        name_lower = self.name.lower()
        if any(d in name_lower for d in dangerous):
            return "HIGH"
        if self.hit_count == 0:
            return "MEDIUM"
        return "LOW"

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "file": self.file,
            "line": self.line,
            "hit_count": self.hit_count,
            "lines_total": self.lines_total,
            "lines_covered": self.lines_covered,
            "line_coverage_pct": self.line_coverage_pct,
            "branches_total": self.branches_total,
            "branches_covered": self.branches_covered,
            "branch_coverage_pct": self.branch_coverage_pct,
            "severity": self.severity,
        }


class FileCoverage:
    """Coverage data for a single source file."""
    def __init__(self, path: str):
        self.path = path
        self.name = Path(path).name
        self.functions: list[FunctionCoverage] = []
        self.lines: dict[int, int] = {}  # line_no → hit_count
        self.branches: dict[int, dict] = {}

    @property
    def lines_total(self) -> int:
        return len(self.lines)

    @property
    def lines_covered(self) -> int:
        return sum(1 for h in self.lines.values() if h > 0)

    @property
    def line_coverage_pct(self) -> float:
        if not self.lines:
            return 0.0
        return round(self.lines_covered / self.lines_total * 100, 1)

    @property
    def functions_total(self) -> int:
        return len(self.functions)

    @property
    def functions_covered(self) -> int:
        return sum(1 for f in self.functions if f.hit_count > 0)

    @property
    def uncovered_functions(self) -> list[FunctionCoverage]:
        return [f for f in self.functions if f.hit_count == 0]


# ══════════════════════════════════════════════════════════════════════════════
# COVERAGE COLLECTORS
# ══════════════════════════════════════════════════════════════════════════════

class GcovCollector:
    """
    Collect coverage data using gcov (GCC coverage tool).
    Works with binaries compiled with: gcc -fprofile-arcs -ftest-coverage
    """

    def __init__(self, binary_path: str, source_dir: str = "."):
        self.binary = Path(binary_path)
        self.source_dir = Path(source_dir)

    def _run_gcov(self, gcda_file: Path) -> Optional[str]:
        """Run gcov on a .gcda file, return output."""
        if not shutil.which("gcov"):
            console.print("[yellow]⚠ gcov not found. Install: sudo apt install gcov[/yellow]")
            return None
        try:
            result = subprocess.run(
                ["gcov", "-b", "-c", str(gcda_file)],
                capture_output=True, text=True,
                cwd=str(self.source_dir)
            )
            return result.stdout + result.stderr
        except Exception as e:
            console.print(f"[red]gcov error: {e}[/red]")
            return None

    def parse_gcov_file(self, gcov_path: Path) -> Optional[FileCoverage]:
        """Parse a .gcov output file."""
        if not gcov_path.exists():
            return None

        source_file = gcov_path.stem.replace(".gcov", "")
        fc = FileCoverage(source_file)
        current_func = None

        with open(gcov_path) as f:
            for line in f:
                # Function start
                func_match = re.match(r'function (\w+) called (\d+)', line)
                if func_match:
                    name = func_match.group(1)
                    hits = int(func_match.group(2))
                    func = FunctionCoverage(name, source_file, 0)
                    func.hit_count = hits
                    fc.functions.append(func)
                    current_func = func
                    continue

                # Line coverage: "count:line_no: source"
                line_match = re.match(r'\s*([\d#]+):\s*(\d+):', line)
                if line_match:
                    count_str = line_match.group(1)
                    line_no = int(line_match.group(2))
                    if line_no > 0:
                        if count_str == "#####":
                            fc.lines[line_no] = 0
                        elif count_str.isdigit():
                            fc.lines[line_no] = int(count_str)

        return fc

    def collect(self) -> list[FileCoverage]:
        """Find and parse all .gcov files in source dir."""
        files = []
        for gcov_file in self.source_dir.glob("*.gcov"):
            fc = self.parse_gcov_file(gcov_file)
            if fc:
                files.append(fc)
        return files


class AFLCoverageCollector:
    """
    Collect coverage approximation from AFL++ output directory.
    Uses AFL++ stats and bitmap to estimate coverage.
    """

    def __init__(self, afl_output_dir: str):
        self.afl_dir = Path(afl_output_dir)

    def read_fuzzer_stats(self) -> dict:
        """Parse AFL++ fuzzer_stats file."""
        stats_file = self.afl_dir / "default" / "fuzzer_stats"
        if not stats_file.exists():
            stats_file = self.afl_dir / "fuzzer_stats"
        if not stats_file.exists():
            return {}

        stats = {}
        with open(stats_file) as f:
            for line in f:
                if ":" in line:
                    key, _, val = line.partition(":")
                    stats[key.strip()] = val.strip()
        return stats

    def read_plot_data(self) -> list[dict]:
        """Parse AFL++ plot_data for timeline."""
        plot_file = self.afl_dir / "default" / "plot_data"
        if not plot_file.exists():
            return []

        data = []
        with open(plot_file) as f:
            lines = f.readlines()
            if len(lines) < 2:
                return []
            headers = [h.strip().lstrip('#').strip()
                       for h in lines[0].split(",")]
            for line in lines[1:]:
                vals = [v.strip() for v in line.split(",")]
                if len(vals) == len(headers):
                    data.append(dict(zip(headers, vals)))
        return data

    def collect(self) -> dict:
        """Collect all AFL++ coverage data."""
        stats = self.read_fuzzer_stats()
        plot = self.read_plot_data()

        return {
            "source": "afl++",
            "stats": stats,
            "timeline": plot[-20:] if plot else [],  # last 20 data points
            "paths_found": int(stats.get("paths_found", 0)),
            "paths_total": int(stats.get("corpus_count", 0)),
            "crashes_found": int(stats.get("saved_crashes", 0)),
            "exec_speed": stats.get("execs_per_sec", "unknown"),
            "total_execs": stats.get("execs_done", "unknown"),
            "run_time": stats.get("run_time", "unknown"),
            "map_density": stats.get("bitmap_cvg", "unknown"),
        }


# ══════════════════════════════════════════════════════════════════════════════
# HTML REPORT GENERATOR
# ══════════════════════════════════════════════════════════════════════════════

class CoverageReporter:
    """
    Generate interactive HTML coverage visualization.
    Shows covered/uncovered code paths with visual indicators.
    """

    def generate_html(
        self,
        file_coverages: list[FileCoverage],
        afl_data: dict,
        output_path: str,
        session_info: dict = None,
    ) -> Path:
        """Generate full interactive HTML report."""
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        total_lines = sum(f.lines_total for f in file_coverages)
        covered_lines = sum(f.lines_covered for f in file_coverages)
        total_funcs = sum(f.functions_total for f in file_coverages)
        covered_funcs = sum(f.functions_covered for f in file_coverages)
        overall_pct = round(covered_lines / total_lines * 100, 1) if total_lines > 0 else 0

        # Build uncovered functions list
        uncovered = []
        for fc in file_coverages:
            for fn in fc.uncovered_functions:
                uncovered.append({
                    "file": fc.name,
                    "function": fn.name,
                    "line": fn.line,
                    "severity": fn.severity,
                })

        uncovered_json = json.dumps(uncovered, indent=2)
        files_json = json.dumps([{
            "name": f.name,
            "path": f.path,
            "lines_total": f.lines_total,
            "lines_covered": f.lines_covered,
            "line_pct": f.line_coverage_pct,
            "funcs_total": f.functions_total,
            "funcs_covered": f.functions_covered,
        } for f in file_coverages], indent=2)

        afl_json = json.dumps(afl_data, indent=2)

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>GLITCHICONS ⬡ Coverage Map</title>
<style>
  :root {{
    --bg: #06060D; --bg2: #0D0D1A; --bg3: #131326;
    --purple: #6B00FF; --purple-bright: #A855F7;
    --magenta: #FF00AA; --green: #00FF88; --red: #FF0040;
    --yellow: #FFB300; --cyan: #00E5FF;
    --text: #E8E8F8; --dim: #6B6B90;
  }}
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{ background: var(--bg); color: var(--text);
          font-family: 'Share Tech Mono', 'Courier New', monospace;
          padding: 2rem; }}
  h1 {{ font-size: 1.5rem; color: var(--purple-bright); letter-spacing: .15em;
        border-bottom: 1px solid var(--purple); padding-bottom: .75rem; margin-bottom: 1.5rem; }}
  h2 {{ font-size: 1rem; color: var(--purple-bright); letter-spacing: .1em;
        margin: 1.5rem 0 .75rem; }}
  .meta {{ color: var(--dim); font-size: .75rem; margin-bottom: 1.5rem; }}

  /* Summary cards */
  .cards {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 1rem; margin-bottom: 2rem; }}
  .card {{ background: var(--bg3); border: 1px solid var(--purple);
           padding: 1.25rem; text-align: center; }}
  .card-num {{ font-size: 2rem; font-weight: bold; color: var(--purple-bright); display: block; }}
  .card-label {{ font-size: .65rem; color: var(--dim); letter-spacing: .15em; margin-top: .25rem; }}

  /* Progress bar */
  .progress-wrap {{ background: var(--bg3); border: 1px solid #2D2D4A;
                    height: 24px; margin: .5rem 0; position: relative; overflow: hidden; }}
  .progress-fill {{ height: 100%; transition: width .5s ease; }}
  .progress-fill.high {{ background: var(--green); }}
  .progress-fill.mid {{ background: var(--yellow); }}
  .progress-fill.low {{ background: var(--red); }}
  .progress-label {{ position: absolute; right: .5rem; top: 50%;
                     transform: translateY(-50%); font-size: .7rem; }}

  /* File table */
  table {{ width: 100%; border-collapse: collapse; margin-bottom: 2rem; }}
  th {{ background: var(--bg3); color: var(--purple-bright);
        padding: .6rem .75rem; text-align: left; font-size: .7rem;
        letter-spacing: .1em; border-bottom: 1px solid var(--purple); }}
  td {{ padding: .5rem .75rem; border-bottom: 1px solid #1E1E30;
        font-size: .75rem; }}
  tr:hover td {{ background: var(--bg3); }}

  /* Severity badges */
  .badge {{ padding: .15rem .5rem; font-size: .6rem; letter-spacing: .1em; }}
  .badge-high {{ background: rgba(255,0,64,.15); color: var(--red); border: 1px solid var(--red); }}
  .badge-medium {{ background: rgba(255,179,0,.15); color: var(--yellow); border: 1px solid var(--yellow); }}
  .badge-low {{ background: rgba(107,0,255,.15); color: var(--purple-bright); border: 1px solid var(--purple); }}

  /* AFL stats */
  .stat-grid {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: .75rem; margin-bottom: 2rem; }}
  .stat-item {{ background: var(--bg3); border: 1px solid #2D2D4A; padding: 1rem; }}
  .stat-key {{ font-size: .6rem; color: var(--dim); letter-spacing: .15em; margin-bottom: .25rem; }}
  .stat-val {{ font-size: 1.1rem; color: var(--cyan); }}

  /* Uncovered functions */
  .uncov-item {{ background: var(--bg3); border-left: 3px solid var(--red);
                 padding: .75rem 1rem; margin-bottom: .5rem; }}
  .uncov-item.medium {{ border-color: var(--yellow); }}
  .uncov-item.low {{ border-color: var(--purple); }}
  .uncov-name {{ color: var(--text); font-size: .85rem; }}
  .uncov-meta {{ color: var(--dim); font-size: .65rem; margin-top: .2rem; }}

  .footer {{ margin-top: 3rem; padding-top: 1rem; border-top: 1px solid #2D2D4A;
             color: var(--dim); font-size: .65rem; text-align: center; }}
  @media(max-width: 700px) {{
    .cards {{ grid-template-columns: 1fr 1fr; }}
    .stat-grid {{ grid-template-columns: 1fr; }}
  }}
</style>
</head>
<body>

<h1>⬡ GLITCHICONS COVERAGE MAP</h1>
<div class="meta">
  Generated: {timestamp} &nbsp;·&nbsp;
  Decepticons Siege Division &nbsp;·&nbsp;
  v0.3.0-dev
</div>

<!-- Summary cards -->
<div class="cards">
  <div class="card">
    <span class="card-num" id="overallPct">{overall_pct}%</span>
    <div class="card-label">LINE COVERAGE</div>
  </div>
  <div class="card">
    <span class="card-num">{covered_lines}/{total_lines}</span>
    <div class="card-label">LINES COVERED</div>
  </div>
  <div class="card">
    <span class="card-num">{covered_funcs}/{total_funcs}</span>
    <div class="card-label">FUNCTIONS HIT</div>
  </div>
  <div class="card">
    <span class="card-num" id="crashCount">{afl_data.get('crashes_found', 0)}</span>
    <div class="card-label">CRASHES FOUND</div>
  </div>
</div>

<!-- Overall progress bar -->
<div class="progress-wrap">
  <div class="progress-fill {'high' if overall_pct >= 70 else 'mid' if overall_pct >= 40 else 'low'}"
       style="width:{overall_pct}%"></div>
  <span class="progress-label">{overall_pct}%</span>
</div>

<!-- AFL++ Stats -->
<h2>AFL++ SESSION STATS</h2>
<div class="stat-grid" id="aflStats"></div>

<!-- File coverage table -->
<h2>FILE COVERAGE</h2>
<table>
  <thead>
    <tr>
      <th>FILE</th>
      <th>LINE COVERAGE</th>
      <th>PROGRESS</th>
      <th>FUNCTIONS</th>
    </tr>
  </thead>
  <tbody id="fileTable"></tbody>
</table>

<!-- Uncovered functions -->
<h2>UNCOVERED CODE PATHS <span style="color:var(--dim);font-size:.7rem">(priority targets for next siege)</span></h2>
<div id="uncoveredList"></div>

<div class="footer">
  GLITCHICONS ⬡ — Where others probe, we siege. Where others test, we break.
</div>

<script>
const aflData = {afl_json};
const filesData = {files_json};
const uncoveredData = {uncovered_json};

// Render AFL stats
const aflKeys = [
  ['paths_found', 'PATHS FOUND'],
  ['crashes_found', 'CRASHES SAVED'],
  ['exec_speed', 'EXEC/SEC'],
  ['total_execs', 'TOTAL EXECS'],
  ['map_density', 'MAP DENSITY'],
  ['run_time', 'RUN TIME'],
];
const aflGrid = document.getElementById('aflStats');
aflKeys.forEach(([key, label]) => {{
  const val = aflData[key] || aflData.stats?.[key] || 'N/A';
  aflGrid.innerHTML += `
    <div class="stat-item">
      <div class="stat-key">${{label}}</div>
      <div class="stat-val">${{val}}</div>
    </div>`;
}});

// Render file table
const tbody = document.getElementById('fileTable');
filesData.forEach(f => {{
  const pct = f.line_pct;
  const cls = pct >= 70 ? 'high' : pct >= 40 ? 'mid' : 'low';
  tbody.innerHTML += `
    <tr>
      <td>${{f.name}}</td>
      <td>${{f.lines_covered}}/${{f.lines_total}}</td>
      <td>
        <div class="progress-wrap" style="height:12px">
          <div class="progress-fill ${{cls}}" style="width:${{pct}}%"></div>
        </div>
        <span style="font-size:.65rem;color:var(--dim)">${{pct}}%</span>
      </td>
      <td>${{f.funcs_covered}}/${{f.funcs_total}}</td>
    </tr>`;
}});
if (filesData.length === 0) {{
  tbody.innerHTML = '<tr><td colspan="4" style="color:var(--dim);text-align:center">No gcov data. Compile with: gcc -fprofile-arcs -ftest-coverage</td></tr>';
}}

// Render uncovered functions
const uncovDiv = document.getElementById('uncoveredList');
if (uncoveredData.length === 0) {{
  uncovDiv.innerHTML = '<div style="color:var(--green);padding:1rem">✓ All instrumented functions have been hit!</div>';
}} else {{
  uncoveredData.slice(0, 20).forEach(fn => {{
    const cls = fn.severity === 'HIGH' ? '' : fn.severity === 'MEDIUM' ? 'medium' : 'low';
    const badgeCls = fn.severity === 'HIGH' ? 'badge-high' : fn.severity === 'MEDIUM' ? 'badge-medium' : 'badge-low';
    uncovDiv.innerHTML += `
      <div class="uncov-item ${{cls}}">
        <div class="uncov-name">
          <span class="badge ${{badgeCls}}">${{fn.severity}}</span>
          &nbsp; ${{fn.function}}()
        </div>
        <div class="uncov-meta">${{fn.file}} · Line ${{fn.line}}</div>
      </div>`;
  }});
}}
</script>
</body>
</html>"""

        out.write_text(html)
        return out


# ══════════════════════════════════════════════════════════════════════════════
# MAIN COVERAGE MAP CLASS
# ══════════════════════════════════════════════════════════════════════════════

class CoverageMap:
    """
    Main interface for coverage collection and visualization.

    Integrates:
    - gcov for source-level coverage (requires instrumented binary)
    - AFL++ stats for fuzzing session overview
    - HTML report generation
    - LLM seed recommendations for uncovered paths
    """

    def __init__(
        self,
        afl_output_dir: str,
        source_dir: str = ".",
        output_dir: str = "./coverage_reports",
        model: str = "qwen2.5-coder:3b",
    ):
        self.afl_dir = Path(afl_output_dir)
        self.source_dir = Path(source_dir)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.model = model

        self.afl_collector = AFLCoverageCollector(afl_output_dir)
        self.gcov_collector = GcovCollector("", source_dir)
        self.reporter = CoverageReporter()

    def collect_and_report(self, title: str = "Coverage Report") -> Path:
        """
        Collect all coverage data and generate HTML report.
        """
        console.print(Panel(
            f"[bold purple]⬡ COVERAGE MAP[/bold purple]\n\n"
            f"[dim]AFL++ dir :[/dim] {self.afl_dir}\n"
            f"[dim]Source dir:[/dim] {self.source_dir}\n"
            f"[dim]Output    :[/dim] {self.output_dir}",
            border_style="purple"
        ))

        # Collect AFL++ data
        console.print("[dim]→ Reading AFL++ stats...[/dim]")
        afl_data = self.afl_collector.collect()

        if afl_data.get("stats"):
            console.print(f"  [green]✓[/green] Paths found: {afl_data['paths_found']}")
            console.print(f"  [green]✓[/green] Crashes: {afl_data['crashes_found']}")
            console.print(f"  [green]✓[/green] Exec speed: {afl_data['exec_speed']}")
        else:
            console.print(f"  [yellow]⚠ No AFL++ stats found in {self.afl_dir}[/yellow]")

        # Collect gcov data
        console.print("[dim]→ Reading gcov coverage data...[/dim]")
        file_coverages = self.gcov_collector.collect()

        if file_coverages:
            console.print(f"  [green]✓[/green] {len(file_coverages)} source files analyzed")
            for fc in file_coverages:
                console.print(
                    f"    {fc.name}: "
                    f"[{'green' if fc.line_coverage_pct >= 70 else 'yellow'}]"
                    f"{fc.line_coverage_pct}% lines[/] · "
                    f"{fc.functions_covered}/{fc.functions_total} functions"
                )
        else:
            console.print(f"  [yellow]⚠ No gcov files found.[/yellow]")
            console.print(f"  [dim]  Recompile with: afl-gcc -fprofile-arcs -ftest-coverage[/dim]")

        # Generate report
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_path = self.output_dir / f"coverage_{timestamp}.html"

        console.print("[dim]→ Generating HTML coverage map...[/dim]")
        self.reporter.generate_html(
            file_coverages=file_coverages,
            afl_data=afl_data,
            output_path=str(report_path),
        )

        console.print(f"\n[bold green]⬡ Coverage map ready:[/bold green] {report_path}")

        # Print uncovered paths for LLM targeting
        uncovered_high = []
        for fc in file_coverages:
            for fn in fc.uncovered_functions:
                if fn.severity == "HIGH":
                    uncovered_high.append(f"{fc.name}:{fn.name}()")

        if uncovered_high:
            console.print(f"\n[red]⬡ HIGH priority uncovered paths ({len(uncovered_high)}):[/red]")
            for path in uncovered_high[:5]:
                console.print(f"  → {path}")
            console.print(f"\n[dim]Run: glitchicons seed --type targeted "
                          f"to generate seeds for these paths[/dim]")

        return report_path

    def get_coverage_summary(self) -> dict:
        """Return coverage summary as dict (for CLI display)."""
        afl_data = self.afl_collector.collect()
        file_coverages = self.gcov_collector.collect()

        total_lines = sum(f.lines_total for f in file_coverages)
        covered_lines = sum(f.lines_covered for f in file_coverages)
        total_funcs = sum(f.functions_total for f in file_coverages)
        covered_funcs = sum(f.functions_covered for f in file_coverages)

        return {
            "line_coverage_pct": round(covered_lines / total_lines * 100, 1) if total_lines else 0,
            "lines_covered": covered_lines,
            "lines_total": total_lines,
            "functions_covered": covered_funcs,
            "functions_total": total_funcs,
            "afl_paths": afl_data.get("paths_found", 0),
            "afl_crashes": afl_data.get("crashes_found", 0),
            "afl_execs": afl_data.get("total_execs", "unknown"),
        }


# ══════════════════════════════════════════════════════════════════════════════
# STANDALONE TEST
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import sys

    afl_dir = sys.argv[1] if len(sys.argv) > 1 else \
              str(Path.home() / "glitchicons/findings")
    source_dir = sys.argv[2] if len(sys.argv) > 2 else "."

    console.print("[bold magenta]Testing Coverage Map module...[/bold magenta]\n")

    cmap = CoverageMap(
        afl_output_dir=afl_dir,
        source_dir=source_dir,
        output_dir="./coverage_reports",
    )

    report = cmap.collect_and_report()
    console.print(f"\n[green]Report: {report}[/green]")
    console.print("[dim]Open in browser to view interactive map[/dim]")
