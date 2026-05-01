"""
GLITCHICONS ⬡ — GNN Code Mapper Module
Decepticons Siege Division

Builds a Control Flow Graph (CFG) from source code,
analyzes it with graph algorithms to identify high-value
attack paths, and feeds insights to LLM for targeted fuzzing.

Note: Uses networkx (lightweight) instead of PyTorch Geometric
to avoid heavy GPU dependencies. The graph analysis is equally
powerful for path prediction at this stage.

Features:
- CFG construction from C/C++ and Python source
- Graph centrality analysis (which functions are most critical)
- Attack surface scoring per node
- Shortest path to dangerous functions
- Visual HTML graph export
- Integration with seed generator (targeted seeds per path)
"""

import re
import ast
import json
import hashlib
from pathlib import Path
from datetime import datetime
from typing import Optional
from collections import defaultdict
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

try:
    import networkx as nx
    NETWORKX_AVAILABLE = True
except ImportError:
    NETWORKX_AVAILABLE = False

console = Console()


# ══════════════════════════════════════════════════════════════════════════════
# GRAPH NODE TYPES
# ══════════════════════════════════════════════════════════════════════════════

NODE_TYPES = {
    "entry":     {"color": "#00FF88", "shape": "diamond"},
    "dangerous": {"color": "#FF0040", "shape": "hexagon"},
    "normal":    {"color": "#6B00FF", "shape": "circle"},
    "exit":      {"color": "#FFB300", "shape": "square"},
    "external":  {"color": "#00E5FF", "shape": "triangle"},
}

# Dangerous function signatures by language
DANGEROUS_FUNCS = {
    "c": {
        "buffer_overflow": ["strcpy", "strcat", "sprintf", "gets",
                            "scanf", "memcpy", "strncpy", "strncat"],
        "format_string":   ["printf", "fprintf", "sprintf", "syslog"],
        "integer":         ["atoi", "atol", "strtol", "strtoul"],
        "heap":            ["malloc", "calloc", "realloc", "free"],
        "command":         ["system", "popen", "exec", "execve"],
        "file":            ["fopen", "open", "fread", "fwrite", "read"],
    },
    "python": {
        "injection":       ["eval", "exec", "compile", "__import__"],
        "deserialization": ["pickle", "yaml.load", "marshal"],
        "command":         ["os.system", "subprocess", "popen"],
        "file":            ["open", "read", "write"],
    }
}


# ══════════════════════════════════════════════════════════════════════════════
# CFG NODE
# ══════════════════════════════════════════════════════════════════════════════

class CFGNode:
    """A node in the Control Flow Graph."""

    def __init__(
        self,
        node_id: str,
        name: str,
        node_type: str = "normal",
        file: str = "",
        line: int = 0,
        calls: list = None,
        dangerous_calls: list = None,
        parameters: list = None,
    ):
        self.id = node_id
        self.name = name
        self.type = node_type
        self.file = file
        self.line = line
        self.calls = calls or []
        self.dangerous_calls = dangerous_calls or []
        self.parameters = parameters or []
        self.attack_score = 0.0  # Computed by graph analyzer

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "type": self.type,
            "file": self.file,
            "line": self.line,
            "calls": self.calls,
            "dangerous_calls": self.dangerous_calls,
            "parameters": self.parameters,
            "attack_score": round(self.attack_score, 3),
        }


# ══════════════════════════════════════════════════════════════════════════════
# CFG BUILDER
# ══════════════════════════════════════════════════════════════════════════════

class CFGBuilder:
    """
    Builds a Control Flow Graph from source code.

    For each function:
    - Creates a node
    - Detects calls to other functions (edges)
    - Tags dangerous function calls
    - Identifies entry points
    """

    def __init__(self, language: str = "auto"):
        self.language = language

    def _detect_language(self, source_path: str) -> str:
        suffix = Path(source_path).suffix.lower()
        if suffix in [".c", ".cpp", ".cc", ".h", ".hpp"]:
            return "c"
        elif suffix == ".py":
            return "python"
        return "unknown"

    def _get_dangerous_calls(self, func_body: str, lang: str) -> list[dict]:
        """Find dangerous function calls in a function body."""
        found = []
        dangerous = DANGEROUS_FUNCS.get(lang, {})
        for category, funcs in dangerous.items():
            for func in funcs:
                pattern = rf'\b{re.escape(func)}\s*\('
                matches = re.findall(pattern, func_body)
                if matches:
                    found.append({
                        "function": func,
                        "category": category,
                        "occurrences": len(matches),
                    })
        return found

    def _extract_calls(self, func_body: str, known_funcs: list[str]) -> list[str]:
        """Find calls to other known functions within a function body."""
        calls = []
        for func_name in known_funcs:
            pattern = rf'\b{re.escape(func_name)}\s*\('
            if re.search(pattern, func_body):
                calls.append(func_name)
        return calls

    def build_from_c(self, source: str, filename: str = "") -> list[CFGNode]:
        """Extract CFG nodes from C/C++ source."""
        nodes = []

        # Find all function definitions
        func_pattern = re.compile(
            r'(?:^|\n)'
            r'(?:static\s+|inline\s+|extern\s+)?'
            r'[\w\*\s]+\s+'
            r'(\w+)\s*'
            r'\(([^)]*)\)\s*\{',
            re.MULTILINE
        )

        # First pass: collect all function names
        func_names = [m.group(1) for m in func_pattern.finditer(source)]

        # Second pass: build nodes with call analysis
        lines = source.split('\n')

        for match in func_pattern.finditer(source):
            func_name = match.group(1)
            params_str = match.group(2)
            line_no = source[:match.start()].count('\n') + 1

            # Extract function body (simple brace matching)
            start = match.end() - 1
            depth = 0
            body_end = start
            for i, ch in enumerate(source[start:], start):
                if ch == '{':
                    depth += 1
                elif ch == '}':
                    depth -= 1
                    if depth == 0:
                        body_end = i
                        break

            func_body = source[start:body_end]

            # Parse parameters
            params = [p.strip().split()[-1].strip('*')
                      for p in params_str.split(',')
                      if p.strip() and p.strip() != 'void']

            # Find dangerous calls
            dangerous = self._get_dangerous_calls(func_body, "c")

            # Find calls to other functions
            other_funcs = [f for f in func_names if f != func_name]
            calls = self._extract_calls(func_body, other_funcs)

            # Determine node type
            if func_name == "main":
                node_type = "entry"
            elif dangerous:
                node_type = "dangerous"
            else:
                node_type = "normal"

            node = CFGNode(
                node_id=f"{filename}:{func_name}",
                name=func_name,
                node_type=node_type,
                file=filename,
                line=line_no,
                calls=calls,
                dangerous_calls=dangerous,
                parameters=params,
            )
            nodes.append(node)

        return nodes

    def build_from_python(self, source: str, filename: str = "") -> list[CFGNode]:
        """Extract CFG nodes from Python source using AST."""
        nodes = []

        try:
            tree = ast.parse(source)
        except SyntaxError as e:
            console.print(f"[yellow]⚠ Python parse error: {e}[/yellow]")
            return []

        # Collect all function names first
        func_names = [
            node.name for node in ast.walk(tree)
            if isinstance(node, ast.FunctionDef)
        ]

        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef):
                continue

            func_name = node.name
            params = [a.arg for a in node.args.args]

            # Get function source for call analysis
            func_source = ast.unparse(node)

            # Find dangerous calls
            dangerous = self._get_dangerous_calls(func_source, "python")

            # Find calls to other known functions
            calls = []
            for child in ast.walk(node):
                if isinstance(child, ast.Call):
                    call_name = ""
                    if isinstance(child.func, ast.Name):
                        call_name = child.func.id
                    elif isinstance(child.func, ast.Attribute):
                        call_name = child.func.attr
                    if call_name in func_names and call_name != func_name:
                        calls.append(call_name)

            # Check for decorators (route handlers = entry points)
            is_entry = any(
                isinstance(d, (ast.Call, ast.Attribute))
                for d in node.decorator_list
            )

            if func_name == "main" or is_entry:
                node_type = "entry"
            elif dangerous:
                node_type = "dangerous"
            else:
                node_type = "normal"

            cfg_node = CFGNode(
                node_id=f"{filename}:{func_name}",
                name=func_name,
                node_type=node_type,
                file=filename,
                line=node.lineno,
                calls=list(set(calls)),
                dangerous_calls=dangerous,
                parameters=params,
            )
            nodes.append(cfg_node)

        return nodes

    def build(self, source_path: str) -> list[CFGNode]:
        """Auto-detect language and build CFG nodes."""
        path = Path(source_path)
        if not path.exists():
            console.print(f"[red]✗ File not found: {source_path}[/red]")
            return []

        source = path.read_text(errors='replace')
        lang = self._detect_language(source_path)

        if lang == "c":
            return self.build_from_c(source, path.name)
        elif lang == "python":
            return self.build_from_python(source, path.name)
        else:
            console.print(f"[yellow]⚠ Unsupported language: {path.suffix}[/yellow]")
            return []


# ══════════════════════════════════════════════════════════════════════════════
# GRAPH ANALYZER
# ══════════════════════════════════════════════════════════════════════════════

class GraphAnalyzer:
    """
    Analyzes the CFG using graph algorithms to identify
    high-value attack paths and critical nodes.

    Metrics computed per node:
    - Betweenness centrality: how often this node is on
      shortest paths (high = critical bottleneck)
    - In-degree centrality: how many functions call this
      (high = widely reachable)
    - Danger score: based on dangerous calls found
    - Attack score: combined metric for fuzzing priority
    """

    def __init__(self):
        self.graph = None
        self.nodes: dict[str, CFGNode] = {}

    def build_graph(self, cfg_nodes: list[CFGNode]) -> bool:
        """Build networkx DiGraph from CFG nodes."""
        if not NETWORKX_AVAILABLE:
            console.print("[red]✗ networkx not installed. Run: pip install networkx[/red]")
            return False

        self.graph = nx.DiGraph()
        self.nodes = {node.id: node for node in cfg_nodes}

        # Add nodes
        for node in cfg_nodes:
            self.graph.add_node(
                node.id,
                name=node.name,
                type=node.type,
                file=node.file,
                line=node.line,
            )

        # Add edges (function calls)
        for node in cfg_nodes:
            for called_func in node.calls:
                # Find target node by function name
                target_id = None
                for nid, n in self.nodes.items():
                    if n.name == called_func:
                        target_id = nid
                        break
                if target_id:
                    self.graph.add_edge(node.id, target_id)

        return True

    def compute_attack_scores(self) -> dict[str, float]:
        """
        Compute attack scores for all nodes.

        Attack Score = (betweenness × 2) + (in_degree) + (danger_score × 3)

        Higher score = higher priority for fuzzing
        """
        if not self.graph:
            return {}

        scores = {}

        # Graph centrality metrics
        try:
            betweenness = nx.betweenness_centrality(self.graph)
            in_degree = nx.in_degree_centrality(self.graph)
        except Exception:
            betweenness = {n: 0 for n in self.graph.nodes}
            in_degree = {n: 0 for n in self.graph.nodes}

        for node_id, node in self.nodes.items():
            # Danger score from dangerous calls
            danger_score = 0.0
            for call in node.dangerous_calls:
                category = call.get("category", "")
                # Weight by severity
                if category in ["buffer_overflow", "injection", "command"]:
                    danger_score += 3.0
                elif category in ["format_string", "heap", "deserialization"]:
                    danger_score += 2.0
                else:
                    danger_score += 1.0
                danger_score += call.get("occurrences", 1) * 0.5

            # Entry point bonus
            entry_bonus = 1.5 if node.type == "entry" else 0.0

            # Parameter count (more params = more attack surface)
            param_bonus = len(node.parameters) * 0.2

            # Combined attack score
            score = (
                betweenness.get(node_id, 0) * 2.0 +
                in_degree.get(node_id, 0) * 1.0 +
                danger_score * 3.0 +
                entry_bonus +
                param_bonus
            )

            scores[node_id] = round(score, 3)
            node.attack_score = scores[node_id]

        return scores

    def get_attack_paths(
        self,
        top_n: int = 5
    ) -> list[dict]:
        """
        Find shortest paths from entry points to dangerous functions.
        These are the most likely exploitation chains.
        """
        if not self.graph:
            return []

        entry_nodes = [nid for nid, n in self.nodes.items()
                       if n.type == "entry"]
        dangerous_nodes = [nid for nid, n in self.nodes.items()
                           if n.type == "dangerous"]

        paths = []
        for entry in entry_nodes:
            for target in dangerous_nodes:
                try:
                    path = nx.shortest_path(self.graph, entry, target)
                    path_names = [self.nodes[p].name for p in path if p in self.nodes]
                    target_node = self.nodes.get(target)
                    paths.append({
                        "entry": self.nodes[entry].name if entry in self.nodes else entry,
                        "target": target_node.name if target_node else target,
                        "target_dangerous": target_node.dangerous_calls if target_node else [],
                        "path": path_names,
                        "length": len(path),
                        "attack_score": target_node.attack_score if target_node else 0,
                    })
                except nx.NetworkXNoPath:
                    pass

        # Sort by score descending, length ascending
        paths.sort(key=lambda x: (-x["attack_score"], x["length"]))
        return paths[:top_n]

    def get_top_targets(self, n: int = 5) -> list[CFGNode]:
        """Return top N nodes by attack score."""
        sorted_nodes = sorted(
            self.nodes.values(),
            key=lambda x: x.attack_score,
            reverse=True
        )
        return sorted_nodes[:n]


# ══════════════════════════════════════════════════════════════════════════════
# VISUAL GRAPH EXPORTER
# ══════════════════════════════════════════════════════════════════════════════

class GraphVisualizer:
    """
    Generates an interactive HTML visualization of the CFG.
    Uses D3.js force-directed graph (no external dependencies).
    """

    def export_html(
        self,
        nodes: list[CFGNode],
        graph: object,  # nx.DiGraph
        output_path: str,
        title: str = "Glitchicons CFG",
    ) -> Path:
        """Export CFG as interactive D3.js HTML visualization."""
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)

        # Build D3 data
        node_data = []
        for node in nodes:
            colors = NODE_TYPES.get(node.type, NODE_TYPES["normal"])
            node_data.append({
                "id": node.id,
                "name": node.name,
                "type": node.type,
                "color": colors["color"],
                "score": node.attack_score,
                "dangerous": len(node.dangerous_calls),
                "file": node.file,
                "line": node.line,
            })

        # Build edges
        link_data = []
        if graph is not None:
            for src, dst in graph.edges():
                link_data.append({"source": src, "target": dst})

        nodes_json = json.dumps(node_data)
        links_json = json.dumps(link_data)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>GLITCHICONS ⬡ — CFG Map</title>
<style>
  body {{ background:#06060D; color:#E8E8F8; font-family:'Courier New',monospace;
          margin:0; overflow:hidden; }}
  #header {{ position:fixed;top:0;left:0;right:0;z-index:100;
             background:rgba(6,6,13,.95);border-bottom:1px solid #6B00FF;
             padding:.6rem 1.5rem;display:flex;align-items:center;gap:1rem; }}
  #header h1 {{ font-size:.85rem;color:#A855F7;letter-spacing:.15em;margin:0; }}
  #header .meta {{ font-size:.6rem;color:#6B6B90; }}
  #legend {{ position:fixed;bottom:1rem;left:1rem;z-index:100;
             background:rgba(13,13,26,.9);border:1px solid #2D2D4A;
             padding:.75rem;font-size:.65rem; }}
  .legend-item {{ display:flex;align-items:center;gap:.4rem;margin:.2rem 0; }}
  .legend-dot {{ width:10px;height:10px;border-radius:50%; }}
  #tooltip {{ position:fixed;display:none;background:rgba(13,13,26,.95);
              border:1px solid #6B00FF;padding:.75rem;font-size:.72rem;
              max-width:280px;z-index:200;pointer-events:none; }}
  .tooltip-name {{ color:#A855F7;font-weight:bold;margin-bottom:.3rem; }}
  .tooltip-row {{ color:#9090B0;margin:.1rem 0; }}
  .tooltip-row span {{ color:#E8E8F8; }}
  svg {{ position:fixed;top:0;left:0; }}
</style>
</head>
<body>

<div id="header">
  <h1>⬡ GLITCHICONS CFG MAP</h1>
  <div class="meta">
    {title} &nbsp;·&nbsp; {len(node_data)} nodes &nbsp;·&nbsp;
    {len(link_data)} edges &nbsp;·&nbsp; {timestamp}
  </div>
</div>

<div id="legend">
  <div class="legend-item"><div class="legend-dot" style="background:#00FF88"></div> Entry Point</div>
  <div class="legend-item"><div class="legend-dot" style="background:#FF0040"></div> Dangerous Function</div>
  <div class="legend-item"><div class="legend-dot" style="background:#6B00FF"></div> Normal Function</div>
  <div class="legend-item"><div class="legend-dot" style="background:#FFB300"></div> Exit</div>
  <div style="margin-top:.5rem;color:#6B6B90;font-size:.58rem">
    Node size = attack score<br>
    Drag to rearrange · Scroll to zoom
  </div>
</div>

<div id="tooltip">
  <div class="tooltip-name" id="tt-name"></div>
  <div class="tooltip-row">File: <span id="tt-file"></span></div>
  <div class="tooltip-row">Line: <span id="tt-line"></span></div>
  <div class="tooltip-row">Type: <span id="tt-type"></span></div>
  <div class="tooltip-row">Attack Score: <span id="tt-score"></span></div>
  <div class="tooltip-row">Dangerous Calls: <span id="tt-danger"></span></div>
</div>

<svg id="graph"></svg>

<script src="https://cdnjs.cloudflare.com/ajax/libs/d3/7.8.5/d3.min.js"></script>
<script>
const nodes = {nodes_json};
const links = {links_json};

const W = window.innerWidth, H = window.innerHeight;
const svg = d3.select('#graph').attr('width', W).attr('height', H);
const g = svg.append('g');

// Zoom
svg.call(d3.zoom().on('zoom', e => g.attr('transform', e.transform)));

// Arrow marker
svg.append('defs').append('marker')
  .attr('id', 'arrow')
  .attr('viewBox', '0 -5 10 10')
  .attr('refX', 20).attr('refY', 0)
  .attr('markerWidth', 6).attr('markerHeight', 6)
  .attr('orient', 'auto')
  .append('path').attr('d', 'M0,-5L10,0L0,5').attr('fill', '#6B00FF');

// Simulation
const sim = d3.forceSimulation(nodes)
  .force('link', d3.forceLink(links).id(d => d.id).distance(120))
  .force('charge', d3.forceManyBody().strength(-300))
  .force('center', d3.forceCenter(W/2, H/2))
  .force('collision', d3.forceCollide(40));

// Links
const link = g.append('g').selectAll('line')
  .data(links).join('line')
  .attr('stroke', '#2D2D4A')
  .attr('stroke-width', 1.5)
  .attr('marker-end', 'url(#arrow)');

// Nodes
const node = g.append('g').selectAll('g')
  .data(nodes).join('g')
  .call(d3.drag()
    .on('start', (e,d) => {{ if (!e.active) sim.alphaTarget(0.3).restart(); d.fx=d.x; d.fy=d.y; }})
    .on('drag',  (e,d) => {{ d.fx=e.x; d.fy=e.y; }})
    .on('end',   (e,d) => {{ if (!e.active) sim.alphaTarget(0); d.fx=null; d.fy=null; }}));

// Circle per node (size by attack score)
node.append('circle')
  .attr('r', d => Math.max(8, Math.min(28, 8 + d.score * 4)))
  .attr('fill', d => d.color)
  .attr('fill-opacity', 0.85)
  .attr('stroke', d => d.color)
  .attr('stroke-width', 2)
  .attr('stroke-opacity', 0.4);

// Glow for dangerous nodes
node.filter(d => d.type === 'dangerous')
  .append('circle')
  .attr('r', d => Math.max(10, Math.min(30, 10 + d.score * 4)))
  .attr('fill', 'none')
  .attr('stroke', '#FF0040')
  .attr('stroke-width', 2)
  .attr('stroke-opacity', 0.3)
  .attr('stroke-dasharray', '4 2');

// Labels
node.append('text')
  .text(d => d.name.length > 12 ? d.name.slice(0,12)+'…' : d.name)
  .attr('text-anchor', 'middle')
  .attr('dy', d => Math.max(8, Math.min(28, 8 + d.score * 4)) + 14)
  .attr('font-size', '10px')
  .attr('fill', '#9090B0')
  .attr('font-family', 'Courier New');

// Tooltip
const tt = document.getElementById('tooltip');
node.on('mouseover', (e, d) => {{
  document.getElementById('tt-name').textContent = d.name + '()';
  document.getElementById('tt-file').textContent = d.file || '—';
  document.getElementById('tt-line').textContent = d.line || '—';
  document.getElementById('tt-type').textContent = d.type;
  document.getElementById('tt-score').textContent = d.score.toFixed(3);
  document.getElementById('tt-danger').textContent = d.dangerous || 0;
  tt.style.display = 'block';
  tt.style.left = (e.pageX + 12) + 'px';
  tt.style.top  = (e.pageY - 20) + 'px';
}}).on('mousemove', e => {{
  tt.style.left = (e.pageX + 12) + 'px';
  tt.style.top  = (e.pageY - 20) + 'px';
}}).on('mouseout', () => {{ tt.style.display = 'none'; }});

// Tick
sim.on('tick', () => {{
  link.attr('x1', d => d.source.x).attr('y1', d => d.source.y)
      .attr('x2', d => d.target.x).attr('y2', d => d.target.y);
  node.attr('transform', d => `translate(${{d.x}},${{d.y}})`);
}});
</script>
</body>
</html>"""

        out.write_text(html)
        return out


# ══════════════════════════════════════════════════════════════════════════════
# MAIN CODE MAPPER
# ══════════════════════════════════════════════════════════════════════════════

class CodeMapper:
    """
    Main interface: source code → CFG → attack surface analysis.

    Pipeline:
    1. Parse source → CFG nodes
    2. Build directed graph
    3. Compute attack scores via centrality + danger
    4. Find attack paths (entry → dangerous)
    5. Export interactive HTML visualization
    6. Return insights for LLM seed targeting
    """

    def __init__(
        self,
        output_dir: str = "./cfg_reports",
        model: str = "qwen2.5-coder:3b",
    ):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.model = model

        self.builder = CFGBuilder()
        self.analyzer = GraphAnalyzer()
        self.visualizer = GraphVisualizer()

    def analyze(self, source_path: str) -> dict:
        """
        Full analysis pipeline on a source file.

        Returns insights dict with:
        - top_targets: functions to prioritize in fuzzing
        - attack_paths: entry → dangerous call chains
        - seed_hints: what inputs to generate
        - report_path: HTML visualization
        """
        console.print(Panel(
            f"[bold purple]⬡ GNN CODE MAPPER[/bold purple]\n\n"
            f"[dim]Source  :[/dim] {source_path}\n"
            f"[dim]Output  :[/dim] {self.output_dir}",
            border_style="purple"
        ))

        # Step 1: Build CFG nodes
        console.print("[dim]→ Parsing source code → CFG nodes...[/dim]")
        cfg_nodes = self.builder.build(source_path)

        if not cfg_nodes:
            console.print("[yellow]⚠ No functions found in source.[/yellow]")
            return {}

        console.print(f"  [green]✓[/green] {len(cfg_nodes)} functions extracted")
        for node in cfg_nodes:
            danger_str = f" [red]({len(node.dangerous_calls)} dangerous calls)[/red]" \
                         if node.dangerous_calls else ""
            console.print(
                f"    [{NODE_TYPES[node.type]['color']}]●[/] "
                f"{node.name}() — {node.type}{danger_str}"
            )

        # Step 2: Build graph
        console.print("[dim]→ Building control flow graph...[/dim]")
        if not self.analyzer.build_graph(cfg_nodes):
            return {}

        console.print(
            f"  [green]✓[/green] Graph: "
            f"{self.analyzer.graph.number_of_nodes()} nodes, "
            f"{self.analyzer.graph.number_of_edges()} edges"
        )

        # Step 3: Compute attack scores
        console.print("[dim]→ Computing attack scores...[/dim]")
        scores = self.analyzer.compute_attack_scores()

        # Step 4: Find attack paths
        paths = self.analyzer.get_attack_paths(top_n=5)
        targets = self.analyzer.get_top_targets(n=5)

        # Step 5: Print findings
        self._print_findings(targets, paths)

        # Step 6: Generate seed hints
        seed_hints = self._generate_seed_hints(targets, paths)

        # Step 7: Export HTML
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        source_name = Path(source_path).stem
        html_path = self.output_dir / f"cfg_{source_name}_{timestamp}.html"

        self.visualizer.export_html(
            nodes=cfg_nodes,
            graph=self.analyzer.graph,
            output_path=str(html_path),
            title=f"CFG: {source_name}",
        )
        console.print(f"\n[green]⬡ CFG map saved:[/green] {html_path}")
        console.print("[dim]  Open in browser for interactive exploration[/dim]")

        return {
            "source": source_path,
            "functions_found": len(cfg_nodes),
            "dangerous_functions": [n.name for n in cfg_nodes
                                    if n.type == "dangerous"],
            "top_targets": [t.to_dict() for t in targets],
            "attack_paths": paths,
            "seed_hints": seed_hints,
            "report_path": str(html_path),
        }

    def _print_findings(self, targets: list[CFGNode], paths: list[dict]):
        """Pretty print analysis results."""
        console.print("\n[bold]Top Attack Targets:[/bold]")
        table = Table(show_header=True, header_style="bold purple", box=None)
        table.add_column("Function", style="cyan", width=20)
        table.add_column("Type", width=12)
        table.add_column("Score", width=8)
        table.add_column("Dangerous Calls", width=35)

        for t in targets:
            danger_str = ", ".join(
                f"{d['function']}({d['category']})"
                for d in t.dangerous_calls[:2]
            )
            color = "red" if t.type == "dangerous" else \
                    "green" if t.type == "entry" else "white"
            table.add_row(
                f"[{color}]{t.name}()[/]",
                t.type,
                str(t.attack_score),
                danger_str or "[dim]none[/dim]",
            )
        console.print(table)

        if paths:
            console.print("\n[bold]Attack Paths (entry → dangerous):[/bold]")
            for i, path in enumerate(paths, 1):
                path_str = " → ".join(path["path"])
                console.print(
                    f"  [dim]{i}.[/dim] [cyan]{path_str}[/cyan] "
                    f"[dim](score: {path['attack_score']})[/dim]"
                )

    def _generate_seed_hints(
        self,
        targets: list[CFGNode],
        paths: list[dict],
    ) -> list[str]:
        """
        Generate seed generation hints based on CFG analysis.
        These hints guide the LLM seed generator.
        """
        hints = []

        for target in targets:
            for call in target.dangerous_calls:
                cat = call["category"]
                func = call["function"]

                if cat == "buffer_overflow":
                    hints.append(
                        f"Generate inputs longer than expected for {target.name}() "
                        f"— targets {func}() buffer overflow"
                    )
                elif cat == "format_string":
                    hints.append(
                        f"Include format string sequences (%s %x %n) "
                        f"for {target.name}() → {func}()"
                    )
                elif cat == "command":
                    hints.append(
                        f"Include shell metacharacters (; | && $()) "
                        f"targeting {target.name}() → {func}()"
                    )
                elif cat == "injection":
                    hints.append(
                        f"Include eval/exec payloads for {target.name}()"
                    )

        # Path-based hints
        for path in paths[:3]:
            target_func = path.get("target", "")
            for d in path.get("target_dangerous", [])[:1]:
                hints.append(
                    f"Craft inputs that reach {target_func}() via: "
                    f"{' → '.join(path['path'])}"
                )

        return list(set(hints))[:10]  # deduplicate, max 10


# ══════════════════════════════════════════════════════════════════════════════
# STANDALONE TEST
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import sys

    source = sys.argv[1] if len(sys.argv) > 1 else \
             str(Path.home() / "target.c")

    if not Path(source).exists():
        # Create a test file
        test_c = Path("/tmp/test_mapper.c")
        test_c.write_text("""
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void authenticate(char *user, char *pass) {
    char buf[64];
    strcpy(buf, user);
    printf("Auth attempt: %s\\n", buf);
}

int parse_config(char *filename) {
    FILE *f = fopen(filename, "r");
    char buf[128];
    fread(buf, 1, sizeof(buf), f);
    fclose(f);
    return 0;
}

void execute_command(char *cmd) {
    system(cmd);
}

int main(int argc, char *argv[]) {
    if (argc < 3) return 1;
    authenticate(argv[1], argv[2]);
    parse_config(argv[1]);
    return 0;
}
""")
        source = str(test_c)
        console.print(f"[dim]Using test file: {source}[/dim]\n")

    mapper = CodeMapper(output_dir="./cfg_reports")
    results = mapper.analyze(source)

    if results.get("seed_hints"):
        console.print("\n[bold]Seed Generation Hints:[/bold]")
        for hint in results["seed_hints"]:
            console.print(f"  → {hint}")
