"""
Web Dashboard — modules/dashboard/dashboard.py

FastAPI-based real-time scan dashboard for Glitchicons.

Features:
  - Dark-themed HTML dashboard (self-contained)
  - REST API to start/stop scans
  - Server-Sent Events (SSE) for real-time finding stream
  - Scan history (in-memory)
  - Finding severity breakdown with live counters
  - Module progress tracking
  - No external dependencies beyond fastapi + uvicorn

Requirements:
  pip install fastapi uvicorn

Usage:
    from modules.dashboard.dashboard import GlitchiconsDashboard

    dash = GlitchiconsDashboard(host="0.0.0.0", port=8888)
    dash.run()

    # Or as background task:
    import asyncio
    asyncio.create_task(dash.run_async())

    # Then open browser: http://localhost:8888

Author: ardanov96
"""

import asyncio
import json
import time
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import AsyncGenerator

from rich.console import Console

console = Console()

SEVERITY_COLORS = {
    "CRITICAL": "#FF0040",
    "HIGH":     "#FF6B35",
    "MEDIUM":   "#FFB300",
    "LOW":      "#30D158",
    "INFO":     "#64D2FF",
}

# ── Dashboard HTML ────────────────────────────────────────

DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>GLITCHICONS — Live Dashboard</title>
<style>
:root{--bg:#06060D;--bg2:#0D0D1A;--bg3:#131326;--purple:#6B00FF;--purple-bright:#A855F7;--text:#E8E8F8;--text2:#9898B8;--border:rgba(107,0,255,.2)}
*{margin:0;padding:0;box-sizing:border-box}
body{background:var(--bg);color:var(--text);font-family:'Segoe UI',system-ui,sans-serif;min-height:100vh}
.nav{background:rgba(6,6,13,.9);border-bottom:1px solid var(--border);padding:.75rem 2rem;display:flex;align-items:center;justify-content:space-between;position:sticky;top:0;z-index:100}
.nav-brand{font-size:1.1rem;font-weight:700;color:var(--purple-bright);letter-spacing:.15em}
.status-dot{width:8px;height:8px;border-radius:50%;background:#30D158;display:inline-block;margin-right:.4rem;animation:pulse 2s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}
.container{max-width:1200px;margin:0 auto;padding:1.5rem}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:.75rem;margin-bottom:1.5rem}
.stat{background:var(--bg3);border:1px solid var(--border);padding:1rem;text-align:center;border-top:2px solid var(--border)}
.stat-num{font-size:1.8rem;font-weight:700;font-family:monospace}
.stat-label{font-size:.65rem;letter-spacing:.15em;color:var(--text2);text-transform:uppercase;margin-top:.2rem}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:1rem;margin-bottom:1rem}
@media(max-width:700px){.grid{grid-template-columns:1fr}}
.card{background:var(--bg3);border:1px solid var(--border);padding:1.25rem}
.card-title{font-size:.7rem;letter-spacing:.2em;color:var(--purple-bright);text-transform:uppercase;margin-bottom:.75rem;padding-bottom:.5rem;border-bottom:1px solid var(--border)}
.scan-form{display:flex;gap:.5rem;flex-wrap:wrap}
.scan-form input{flex:1;min-width:200px;background:var(--bg);border:1px solid rgba(107,0,255,.3);color:var(--text);padding:.5rem .75rem;font-size:.85rem;outline:none}
.scan-form input:focus{border-color:var(--purple-bright)}
.btn{background:var(--purple);border:none;color:#fff;padding:.5rem 1.25rem;font-size:.8rem;font-weight:600;cursor:pointer;letter-spacing:.08em;transition:background .2s}
.btn:hover{background:var(--purple-bright)}
.btn-stop{background:rgba(255,0,64,.2);border:1px solid rgba(255,0,64,.4);color:#FF0040}
.btn-stop:hover{background:rgba(255,0,64,.35)}
.findings-list{max-height:400px;overflow-y:auto}
.finding{border-left:3px solid var(--border);padding:.6rem .75rem;margin-bottom:.4rem;background:var(--bg2);font-size:.82rem;animation:slideIn .3s ease}
@keyframes slideIn{from{opacity:0;transform:translateX(-10px)}to{opacity:1;transform:translateX(0)}}
.f-sev{font-size:.65rem;font-weight:700;padding:.1rem .4rem;margin-right:.4rem;display:inline-block}
.f-title{color:var(--text);font-weight:500}
.f-target{color:var(--text2);font-size:.72rem;margin-top:.2rem}
.log{background:var(--bg);border:1px solid var(--border);padding:.75rem;font-family:monospace;font-size:.75rem;color:var(--text2);max-height:200px;overflow-y:auto}
.log-line{padding:.15rem 0;border-bottom:1px solid rgba(255,255,255,.04)}
.log-line.ok{color:#30D158}
.log-line.err{color:#FF0040}
.log-line.warn{color:#FFB300}
.progress-bar{background:rgba(107,0,255,.1);height:4px;border-radius:2px;overflow:hidden;margin-bottom:1rem}
.progress-fill{height:100%;background:linear-gradient(90deg,var(--purple),var(--purple-bright));transition:width .5s;width:0%}
.empty{text-align:center;color:var(--text2);padding:2rem;font-size:.85rem}
</style>
</head>
<body>
<nav class="nav">
  <div class="nav-brand">⬡ GLITCHICONS</div>
  <div style="font-size:.75rem;color:var(--text2)">
    <span class="status-dot" id="statusDot"></span>
    <span id="statusText">READY</span>
  </div>
</nav>

<div class="container">
  <div class="stats">
    <div class="stat" style="border-top-color:#FF0040"><div class="stat-num" id="crit">0</div><div class="stat-label">Critical</div></div>
    <div class="stat" style="border-top-color:#FF6B35"><div class="stat-num" id="high">0</div><div class="stat-label">High</div></div>
    <div class="stat" style="border-top-color:#FFB300"><div class="stat-num" id="med">0</div><div class="stat-label">Medium</div></div>
    <div class="stat" style="border-top-color:#30D158"><div class="stat-num" id="low">0</div><div class="stat-label">Low</div></div>
    <div class="stat" style="border-top-color:#A855F7"><div class="stat-num" id="total">0</div><div class="stat-label">Total</div></div>
    <div class="stat" style="border-top-color:#64D2FF"><div class="stat-num" id="elapsed">0s</div><div class="stat-label">Elapsed</div></div>
  </div>

  <div class="progress-bar"><div class="progress-fill" id="progressFill"></div></div>

  <div class="grid">
    <div class="card">
      <div class="card-title">Start Scan</div>
      <div class="scan-form">
        <input id="targetUrl" type="text" placeholder="https://target.com" value="">
        <input id="modules"   type="text" placeholder="cors,graphql,subdomain" value="">
        <button class="btn" onclick="startScan()">▶ SCAN</button>
        <button class="btn btn-stop" onclick="stopScan()" id="stopBtn" style="display:none">■ STOP</button>
      </div>
      <div style="margin-top:.75rem">
        <div class="log" id="scanLog"><div class="log-line">// Waiting for scan...</div></div>
      </div>
    </div>

    <div class="card">
      <div class="card-title">Live Findings</div>
      <div class="findings-list" id="findingsList">
        <div class="empty">No findings yet</div>
      </div>
    </div>
  </div>

  <div class="card">
    <div class="card-title">Scan History</div>
    <div id="historyList"><div class="empty">No scan history</div></div>
  </div>
</div>

<script>
let evtSource = null;
let scanStart = null;
let elapsedInterval = null;
const counts = {CRITICAL:0, HIGH:0, MEDIUM:0, LOW:0, INFO:0, total:0};

const sevColors = {CRITICAL:'#FF0040',HIGH:'#FF6B35',MEDIUM:'#FFB300',LOW:'#30D158',INFO:'#64D2FF'};

function setStatus(text, active) {
  document.getElementById('statusText').textContent = text;
  document.getElementById('statusDot').style.background = active ? '#FF6B35' : '#30D158';
}

function addLog(msg, cls='') {
  const log = document.getElementById('scanLog');
  const line = document.createElement('div');
  line.className = 'log-line ' + cls;
  line.textContent = '[' + new Date().toLocaleTimeString() + '] ' + msg;
  log.appendChild(line);
  log.scrollTop = log.scrollHeight;
}

function addFinding(f) {
  const list = document.getElementById('findingsList');
  const empty = list.querySelector('.empty');
  if(empty) empty.remove();

  const sev = f.severity || 'INFO';
  const color = sevColors[sev] || '#64D2FF';
  const el = document.createElement('div');
  el.className = 'finding';
  el.style.borderLeftColor = color;
  el.innerHTML =
    '<span class="f-sev" style="background:' + color + '22;color:' + color + '">' + sev + '</span>' +
    '<span class="f-title">' + (f.title || 'Finding').substring(0,60) + '</span>' +
    '<div class="f-target">CVSS ' + (f.cvss||'N/A') + ' · ' + (f.cwe||'') + ' · ' + (f.target||'').substring(0,50) + '</div>';
  list.insertBefore(el, list.firstChild);

  // Update counters
  counts[sev] = (counts[sev]||0) + 1;
  counts.total++;
  document.getElementById('crit').textContent  = counts.CRITICAL || 0;
  document.getElementById('high').textContent  = counts.HIGH     || 0;
  document.getElementById('med').textContent   = counts.MEDIUM   || 0;
  document.getElementById('low').textContent   = counts.LOW      || 0;
  document.getElementById('total').textContent = counts.total;
}

function startScan() {
  const url     = document.getElementById('targetUrl').value.trim();
  const modules = document.getElementById('modules').value.trim();
  if(!url) { addLog('Target URL required', 'err'); return; }

  // Reset
  Object.keys(counts).forEach(k => counts[k]=0);
  ['crit','high','med','low','total'].forEach(id => document.getElementById(id).textContent='0');
  document.getElementById('findingsList').innerHTML = '<div class="empty">Scanning...</div>';
  document.getElementById('progressFill').style.width = '10%';

  if(evtSource) evtSource.close();

  const params = new URLSearchParams({target: url});
  if(modules) params.set('modules', modules);

  setStatus('SCANNING', true);
  document.getElementById('stopBtn').style.display = '';
  scanStart = Date.now();
  elapsedInterval = setInterval(() => {
    document.getElementById('elapsed').textContent = Math.round((Date.now()-scanStart)/1000) + 's';
  }, 1000);

  addLog('Starting scan: ' + url);

  evtSource = new EventSource('/api/scan/stream?' + params.toString());

  evtSource.addEventListener('finding', e => {
    try { addFinding(JSON.parse(e.data)); } catch(err) {}
  });
  evtSource.addEventListener('log', e => {
    addLog(e.data);
    document.getElementById('progressFill').style.width =
      Math.min(90, parseInt(document.getElementById('progressFill').style.width||'10') + 5) + '%';
  });
  evtSource.addEventListener('done', e => {
    const data = JSON.parse(e.data || '{}');
    addLog('Scan complete: ' + (data.finding_count||0) + ' findings in ' + (data.duration_s||0) + 's', 'ok');
    setStatus('DONE', false);
    document.getElementById('progressFill').style.width = '100%';
    document.getElementById('stopBtn').style.display = 'none';
    clearInterval(elapsedInterval);
    evtSource.close();
    loadHistory();
  });
  evtSource.addEventListener('error', e => {
    addLog('Connection error', 'err');
    setStatus('ERROR', false);
    clearInterval(elapsedInterval);
  });
}

function stopScan() {
  if(evtSource) { evtSource.close(); evtSource = null; }
  fetch('/api/scan/stop', {method:'POST'});
  setStatus('STOPPED', false);
  clearInterval(elapsedInterval);
  document.getElementById('stopBtn').style.display = 'none';
  addLog('Scan stopped by user', 'warn');
}

async function loadHistory() {
  try {
    const r = await fetch('/api/history');
    const data = await r.json();
    const list = document.getElementById('historyList');
    if(!data.length) { list.innerHTML = '<div class="empty">No scan history</div>'; return; }
    list.innerHTML = data.map(s =>
      '<div style="display:flex;gap:1rem;padding:.5rem;border-bottom:1px solid rgba(255,255,255,.05);font-size:.8rem">' +
      '<span style="color:var(--text2);min-width:160px">' + s.started_at.substring(0,19).replace('T',' ') + '</span>' +
      '<span style="color:var(--purple-bright);flex:1">' + s.target + '</span>' +
      '<span style="color:#FFB300">' + s.finding_count + ' findings</span>' +
      '<span style="color:var(--text2)">' + s.duration_s + 's</span>' +
      '</div>'
    ).join('');
  } catch(e) {}
}

loadHistory();
</script>
</body>
</html>"""


# ── Scan Session ──────────────────────────────────────────

@dataclass
class ScanSession:
    """Represents an active or completed scan session."""
    session_id:  str
    target:      str
    modules:     list[str]
    started_at:  str
    findings:    list[dict] = field(default_factory=list)
    logs:        list[str]  = field(default_factory=list)
    status:      str = "running"   # running | done | stopped | error
    duration_s:  float = 0.0
    finished_at: str = ""

    @property
    def finding_count(self) -> int:
        return len(self.findings)


# ── Dashboard Server ──────────────────────────────────────

class GlitchiconsDashboard:
    """
    FastAPI-based web dashboard for Glitchicons.

    Serves a real-time scan interface with:
    - SSE-based live finding stream
    - REST API for scan control
    - In-memory scan history

    Usage:
        dash = GlitchiconsDashboard(port=8888)
        dash.run()
    """

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 8888,
        output_dir: str = "./findings/dashboard",
        scan_fn=None,
    ):
        self.host       = host
        self.port       = port
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.scan_fn    = scan_fn  # Optional custom scan function

        self._sessions:  list[ScanSession] = []
        self._active:    ScanSession | None = None
        self._stop_flag  = False
        self._app        = None

    def _build_app(self):
        """Build FastAPI application."""
        try:
            from fastapi import FastAPI
            from fastapi.responses import HTMLResponse, StreamingResponse, JSONResponse
            from fastapi.middleware.cors import CORSMiddleware
        except ImportError:
            raise ImportError(
                "FastAPI not installed. Run: pip install fastapi uvicorn"
            )

        app = FastAPI(title="GLITCHICONS Dashboard", version="2.0.0")
        app.add_middleware(
            CORSMiddleware,
            allow_origins=["*"],
            allow_methods=["*"],
            allow_headers=["*"],
        )

        @app.get("/", response_class=HTMLResponse)
        async def index():
            return HTMLResponse(DASHBOARD_HTML)

        @app.get("/api/scan/stream")
        async def scan_stream(target: str, modules: str = ""):
            """SSE endpoint for real-time scan updates."""
            module_list = [m.strip() for m in modules.split(",") if m.strip()]
            session = ScanSession(
                session_id=str(uuid.uuid4())[:8],
                target=target,
                modules=module_list,
                started_at=datetime.now(timezone.utc).isoformat(),
            )
            self._active  = session
            self._stop_flag = False

            async def event_stream() -> AsyncGenerator[str, None]:
                start = time.monotonic()
                try:
                    yield _sse("log", f"Initializing scan: {target}")
                    yield _sse("log", f"Modules: {module_list or ['default']}")

                    # Run scan (use custom fn or mock)
                    if self.scan_fn:
                        findings = await asyncio.get_event_loop().run_in_executor(
                            None, self.scan_fn, target, module_list
                        )
                    else:
                        # Demo mode: generate sample findings
                        findings = self._demo_scan(target)

                    for f in findings:
                        if self._stop_flag:
                            break
                        session.findings.append(f)
                        yield _sse("finding", json.dumps(f, default=str))
                        yield _sse("log", f"[{f.get('severity','?')}] {f.get('title','')[:50]}")
                        await asyncio.sleep(0.1)  # Rate limit SSE stream

                    duration = round(time.monotonic() - start, 2)
                    session.duration_s  = duration
                    session.finished_at = datetime.now(timezone.utc).isoformat()
                    session.status      = "stopped" if self._stop_flag else "done"
                    self._sessions.append(session)
                    self._save_session(session)

                    yield _sse("done", json.dumps({
                        "finding_count": session.finding_count,
                        "duration_s":    duration,
                        "status":        session.status,
                    }))

                except Exception as e:
                    yield _sse("log", f"Error: {e}")
                    session.status = "error"
                    yield _sse("done", json.dumps({"error": str(e)}))

            return StreamingResponse(
                event_stream(),
                media_type="text/event-stream",
                headers={
                    "Cache-Control":               "no-cache",
                    "X-Accel-Buffering":           "no",
                    "Access-Control-Allow-Origin": "*",
                },
            )

        @app.post("/api/scan/stop")
        async def stop_scan():
            self._stop_flag = True
            return {"status": "stopping"}

        @app.get("/api/history")
        async def get_history():
            return JSONResponse([
                {
                    "session_id":   s.session_id,
                    "target":       s.target,
                    "finding_count": s.finding_count,
                    "duration_s":   s.duration_s,
                    "started_at":   s.started_at,
                    "status":       s.status,
                }
                for s in reversed(self._sessions[-20:])
            ])

        @app.get("/api/findings/{session_id}")
        async def get_findings(session_id: str):
            session = next((s for s in self._sessions if s.session_id == session_id), None)
            if not session:
                return JSONResponse({"error": "Session not found"}, status_code=404)
            return JSONResponse(session.findings)

        @app.get("/api/status")
        async def get_status():
            return JSONResponse({
                "version":       "2.0.0",
                "active_scan":   self._active.target if self._active else None,
                "total_sessions": len(self._sessions),
            })

        self._app = app
        return app

    def _demo_scan(self, target: str) -> list[dict]:
        """Generate demo findings for dashboard testing."""
        import random
        severities = ["CRITICAL", "HIGH", "HIGH", "MEDIUM", "MEDIUM", "LOW", "INFO"]
        demos = [
            ("SQL Injection", "CRITICAL", 9.8, "CWE-89"),
            ("Reflected XSS", "HIGH",     7.5, "CWE-79"),
            ("CORS Misconfiguration", "HIGH", 7.4, "CWE-942"),
            ("Missing HSTS", "MEDIUM", 5.3, "CWE-319"),
            ("Verbose Error Messages", "LOW", 2.7, "CWE-209"),
        ]
        findings = []
        for title, sev, cvss, cwe in demos[:random.randint(2, 5)]:
            findings.append({
                "title":       title,
                "severity":    sev,
                "cvss":        cvss,
                "cwe":         cwe,
                "target":      target,
                "description": f"Demo finding: {title}",
                "evidence":    "Detected during automated scan",
                "remediation": "Apply security patch",
                "source":      "module:demo",
                "timestamp":   datetime.now(timezone.utc).isoformat(),
            })
        return findings

    def run(self) -> None:
        """Start the dashboard server (blocking)."""
        try:
            import uvicorn
        except ImportError:
            raise ImportError("uvicorn not installed. Run: pip install uvicorn")

        app = self._build_app()
        console.print(f"\n  [bold cyan]⬡ GLITCHICONS Dashboard[/bold cyan]")
        console.print(f"  URL: http://{self.host}:{self.port}")
        console.print(f"  Press Ctrl+C to stop\n")
        uvicorn.run(app, host=self.host, port=self.port, log_level="warning")

    async def run_async(self) -> None:
        """Start the dashboard server (async, non-blocking)."""
        try:
            import uvicorn
        except ImportError:
            raise ImportError("uvicorn not installed. Run: pip install uvicorn")

        app = self._build_app()
        config = uvicorn.Config(app, host=self.host, port=self.port, log_level="warning")
        server = uvicorn.Server(config)
        await server.serve()

    def _save_session(self, session: ScanSession) -> Path:
        out = self.output_dir / f"session_{session.session_id}.json"
        data = {
            "session_id":   session.session_id,
            "target":       session.target,
            "modules":      session.modules,
            "started_at":   session.started_at,
            "finished_at":  session.finished_at,
            "status":       session.status,
            "finding_count": session.finding_count,
            "duration_s":   session.duration_s,
            "findings":     session.findings,
        }
        out.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
        return out

    @property
    def session_count(self) -> int:
        return len(self._sessions)


def _sse(event: str, data: str) -> str:
    """Format a Server-Sent Event string."""
    return f"event: {event}\ndata: {data}\n\n"
