"""
Go Integration Architecture — modules/go/go_runner.py

Defines HOW Python calls Go binaries in Glitchicons.
All future Go modules (glitchrace, glitchscan, glitchfuzz, etc.)
must follow this interface.

Architecture:
  Python (orchestration, LLM, reporting)
       ↕  subprocess + JSON
  Go binaries (performance-critical scanning)

Standard output format (all Go binaries must emit this):
  {
    "tool":     "glitchrace",
    "version":  "1.0.0",
    "target":   "https://target.com/api/checkout",
    "started":  "2026-05-28T12:00:00Z",
    "finished": "2026-05-28T12:00:05Z",
    "findings": [...],   # standard finding schema
    "stats":    {...},   # tool-specific metrics
    "exit_code": 0
  }

Components:
  1. GoRunner         — subprocess executor with timeout + streaming
  2. GoOutputParser   — parse JSON output from Go binaries
  3. GoBinaryLocator  — find Go binaries (PATH, local build, download)
  4. GoFindingAdapter — convert Go findings to Python finding schema
  5. GoHealthChecker  — verify Go binaries are installed + correct version

Planned Go modules:
  glitchrace  v1.1.0  — race condition exploiter (ns precision)
  glitchscan  v1.1.0  — port + service scanner (10k ports/sec)
  glitchfuzz  v1.2.0  — HTTP directory fuzzer (50k req/sec)
  glitchdns   v1.2.0  — DNS brute forcer (100k queries/sec)
  glitchtls   v1.3.0  — TLS/SSL cipher analyzer
  glitchproxy v1.3.0  — intercepting HTTP proxy

Usage:
    from modules.go.go_runner import GoRunner, GoBinaryLocator

    # Check if glitchrace is installed
    locator = GoBinaryLocator()
    binary = locator.find("glitchrace")

    # Run a Go binary
    runner = GoRunner(timeout=60)
    result = runner.run("glitchrace", [
        "--target", "https://target.com/api/checkout",
        "--param", "coupon_code",
        "--threads", "50",
        "--output", "json",
    ])

    if result.success:
        for finding in result.findings:
            print(finding["title"], finding["severity"])

Author: ardanov96
"""

import json
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator
from rich.console import Console

console = Console()


# ── Go binary registry ────────────────────────────────────

GO_BINARY_REGISTRY: dict[str, dict] = {
    "glitchrace": {
        "description":   "Race condition exploiter — nanosecond precision",
        "version":       "1.1.0",
        "planned_at":    "v1.1.0",
        "github":        "https://github.com/ardanov96/glitchrace",
        "install":       "go install github.com/ardanov96/glitchrace@latest",
        "capabilities":  ["race_condition", "toctou", "parallel_requests"],
        "replaces":      "modules/business_logic/race_condition.py",
        "speedup":       "100x (ns vs ms precision)",
    },
    "glitchscan": {
        "description":   "Port + service scanner",
        "version":       "1.1.0",
        "planned_at":    "v1.1.0",
        "github":        "https://github.com/ardanov96/glitchscan",
        "install":       "go install github.com/ardanov96/glitchscan@latest",
        "capabilities":  ["port_scan", "service_detect", "os_fingerprint", "banner_grab"],
        "replaces":      "external nmap dependency",
        "speedup":       "20x (10k ports/sec vs ~500/sec)",
    },
    "glitchfuzz": {
        "description":   "HTTP directory + parameter fuzzer",
        "version":       "1.2.0",
        "planned_at":    "v1.2.0",
        "github":        "https://github.com/ardanov96/glitchfuzz",
        "install":       "go install github.com/ardanov96/glitchfuzz@latest",
        "capabilities":  ["dir_brute", "vhost_brute", "param_discover", "content_discovery"],
        "replaces":      "modules/config/siege_runner.py protocol fuzzer",
        "speedup":       "25x (50k req/sec vs 2k/sec)",
    },
    "glitchdns": {
        "description":   "DNS brute forcer + zone transfer",
        "version":       "1.2.0",
        "planned_at":    "v1.2.0",
        "github":        "https://github.com/ardanov96/glitchdns",
        "install":       "go install github.com/ardanov96/glitchdns@latest",
        "capabilities":  ["subdomain_brute", "zone_transfer", "wildcard_detect", "dnssec"],
        "replaces":      "modules/recon/subdomain_takeover.py DNS layer",
        "speedup":       "20x (100k queries/sec vs 5k/sec)",
    },
    "glitchtls": {
        "description":   "TLS/SSL cipher suite analyzer",
        "version":       "1.3.0",
        "planned_at":    "v1.3.0",
        "github":        "https://github.com/ardanov96/glitchtls",
        "install":       "go install github.com/ardanov96/glitchtls@latest",
        "capabilities":  ["cipher_enum", "cert_chain", "heartbleed", "beast", "poodle", "hsts"],
        "replaces":      "no Python equivalent",
        "speedup":       "N/A (new capability)",
    },
    "glitchproxy": {
        "description":   "Intercepting HTTP proxy",
        "version":       "1.3.0",
        "planned_at":    "v1.3.0",
        "github":        "https://github.com/ardanov96/glitchproxy",
        "install":       "go install github.com/ardanov96/glitchproxy@latest",
        "capabilities":  ["intercept", "modify", "replay", "tls_mitm", "websocket"],
        "replaces":      "no Python equivalent",
        "speedup":       "N/A (new capability)",
    },
}


# ── Standard output schema ────────────────────────────────

def validate_go_output(data: dict) -> list[str]:
    """
    Validate Go binary JSON output against standard schema.
    Returns list of validation errors (empty = valid).
    """
    errors = []
    required_top = {"tool", "version", "target", "findings", "exit_code"}
    missing = required_top - set(data.keys())
    if missing:
        errors.append(f"Missing top-level fields: {missing}")

    findings = data.get("findings", [])
    if not isinstance(findings, list):
        errors.append("'findings' must be a list")
        return errors

    required_finding = {"title", "severity", "cvss", "cwe", "description"}
    valid_severities = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}

    for i, f in enumerate(findings):
        missing_f = required_finding - set(f.keys())
        if missing_f:
            errors.append(f"Finding[{i}] missing: {missing_f}")
        sev = f.get("severity", "")
        if sev not in valid_severities:
            errors.append(f"Finding[{i}] invalid severity: {sev!r}")
        cvss = f.get("cvss", -1)
        if not isinstance(cvss, (int, float)) or not (0.0 <= cvss <= 10.0):
            errors.append(f"Finding[{i}] invalid cvss: {cvss}")

    return errors


# ── Data classes ──────────────────────────────────────────

@dataclass
class GoRunResult:
    """Result of running a Go binary."""
    binary:      str
    args:        list[str]
    exit_code:   int
    stdout:      str
    stderr:      str
    duration_s:  float
    findings:    list[dict] = field(default_factory=list)
    stats:       dict       = field(default_factory=dict)
    raw_output:  dict       = field(default_factory=dict)
    errors:      list[str]  = field(default_factory=list)

    @property
    def success(self) -> bool:
        return self.exit_code == 0 and not self.errors

    @property
    def finding_count(self) -> int:
        return len(self.findings)

    def summary(self) -> str:
        status = "OK" if self.success else "FAILED"
        return (
            f"{self.binary} [{status}] "
            f"exit={self.exit_code} "
            f"findings={self.finding_count} "
            f"duration={self.duration_s:.1f}s"
        )


@dataclass
class BinaryInfo:
    """Information about a located Go binary."""
    name:     str
    path:     str
    version:  str
    is_mock:  bool = False

    @property
    def available(self) -> bool:
        return bool(self.path)


# ── Binary locator ────────────────────────────────────────

class GoBinaryLocator:
    """
    Finds Go binaries in order of preference:
    1. Local build at ./bin/<name>
    2. PATH (go install puts binaries in $GOPATH/bin)
    3. Platform-specific locations

    Falls back to a Python mock if binary not found and
    allow_mock=True (useful for CI and development).
    """

    SEARCH_PATHS = [
        Path("./bin"),
        Path.home() / "go" / "bin",
        Path("/usr/local/go/bin"),
        Path("/usr/local/bin"),
    ]

    def find(self, name: str, allow_mock: bool = False) -> BinaryInfo:
        """
        Find a Go binary by name.

        Args:
            name:       Binary name (e.g. "glitchrace")
            allow_mock: Return mock info if binary not found

        Returns:
            BinaryInfo with path (empty string if not found)
        """
        # 1. Check PATH first
        path = shutil.which(name)
        if path:
            version = self._get_version(path, name)
            return BinaryInfo(name=name, path=path, version=version)

        # 2. Check known search paths
        for search_dir in self.SEARCH_PATHS:
            candidate = search_dir / name
            if candidate.exists() and candidate.is_file():
                path = str(candidate)
                version = self._get_version(path, name)
                return BinaryInfo(name=name, path=path, version=version)

        # 3. Not found — return empty or mock
        if allow_mock:
            return BinaryInfo(name=name, path="", version="mock", is_mock=True)

        return BinaryInfo(name=name, path="", version="")

    def find_all(self) -> dict[str, BinaryInfo]:
        """Find all registered Go binaries."""
        return {name: self.find(name) for name in GO_BINARY_REGISTRY}

    def _get_version(self, path: str, name: str) -> str:
        """Try to get binary version via --version flag."""
        try:
            result = subprocess.run(
                [path, "--version"],
                capture_output=True, text=True, timeout=3,
            )
            # Parse "glitchrace 1.0.0" or "v1.0.0"
            output = result.stdout.strip() or result.stderr.strip()
            for part in output.split():
                if part.startswith("v") or part[0].isdigit():
                    return part.lstrip("v")
        except Exception:
            pass
        return "unknown"


# ── Go output parser ──────────────────────────────────────

class GoOutputParser:
    """
    Parses JSON output from Go binaries into Python finding dicts.
    Handles both streaming (one JSON per line) and single-blob modes.
    """

    def parse(self, raw: str, binary_name: str = "") -> tuple[list[dict], dict, list[str]]:
        """
        Parse Go binary stdout.

        Args:
            raw:         Raw stdout string from Go binary
            binary_name: Binary name for error context

        Returns:
            (findings, stats, errors)
        """
        if not raw.strip():
            return [], {}, ["No output from binary"]

        # Try single JSON blob first
        try:
            data = json.loads(raw)
            errors = validate_go_output(data)
            if errors:
                return [], {}, errors
            findings = self._adapt_findings(data.get("findings", []), binary_name)
            return findings, data.get("stats", {}), []
        except json.JSONDecodeError:
            pass

        # Try NDJSON (one JSON object per line)
        findings = []
        errors = []
        stats = {}
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                if "findings" in obj:
                    findings.extend(self._adapt_findings(obj["findings"], binary_name))
                    stats.update(obj.get("stats", {}))
                elif "title" in obj:  # single finding per line
                    findings.append(self._adapt_one(obj, binary_name))
            except json.JSONDecodeError as e:
                errors.append(f"JSON parse error: {e} — line: {line[:100]}")

        return findings, stats, errors

    def _adapt_findings(self, raw_findings: list[dict], source: str) -> list[dict]:
        return [self._adapt_one(f, source) for f in raw_findings]

    def _adapt_one(self, f: dict, source: str) -> dict:
        """Normalize a Go finding to Python finding schema."""
        return {
            "id":          f.get("id", ""),
            "title":       f.get("title", ""),
            "severity":    f.get("severity", "INFO"),
            "cvss":        float(f.get("cvss", 0.0)),
            "cwe":         f.get("cwe", "CWE-0"),
            "target":      f.get("target", "") or f.get("url", ""),
            "description": f.get("description", "") or f.get("detail", ""),
            "evidence":    f.get("evidence", "") or f.get("proof", ""),
            "remediation": f.get("remediation", "") or f.get("fix", ""),
            "source":      f"go:{source}",
            "timestamp":   f.get("timestamp", datetime.now(timezone.utc).isoformat()),
            # Preserve extra fields from Go binary
            **{k: v for k, v in f.items()
               if k not in {"id","title","severity","cvss","cwe","target",
                             "description","evidence","remediation","timestamp"}},
        }


# ── Go runner ─────────────────────────────────────────────

class GoRunner:
    """
    Executes Go binaries as subprocesses and parses their output.

    Handles:
    - Timeout enforcement
    - Stderr capture (for debug)
    - Streaming progress output
    - JSON output parsing
    - Error recovery
    """

    def __init__(
        self,
        timeout: int = 300,
        output_dir: str = "./findings/go",
        stream_stderr: bool = True,
    ):
        self.timeout = timeout
        self.output_dir = Path(output_dir)
        self.stream_stderr = stream_stderr
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self._parser = GoOutputParser()
        self._locator = GoBinaryLocator()

    def run(
        self,
        binary: str,
        args: list[str],
        env: dict | None = None,
        stdin: str | None = None,
    ) -> GoRunResult:
        """
        Run a Go binary and return parsed results.

        Args:
            binary: Binary name or full path
            args:   Command-line arguments
            env:    Additional environment variables
            stdin:  Optional stdin input

        Returns:
            GoRunResult with findings and stats
        """
        # Resolve binary path
        if not Path(binary).is_absolute():
            info = self._locator.find(binary)
            if not info.available:
                return GoRunResult(
                    binary=binary, args=args,
                    exit_code=127,
                    stdout="", stderr="",
                    duration_s=0.0,
                    errors=[
                        f"Binary '{binary}' not found. "
                        f"Install: {GO_BINARY_REGISTRY.get(binary, {}).get('install', 'unknown')}"
                    ],
                )
            binary_path = info.path
        else:
            binary_path = binary

        cmd = [binary_path] + args
        console.print(f"  [cyan]>> {binary}[/cyan] {' '.join(args[:4])}")

        start = time.time()
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                env=env,
                input=stdin,
            )
            duration = time.time() - start

            if self.stream_stderr and proc.stderr:
                for line in proc.stderr.splitlines()[:5]:
                    console.print(f"  [dim]{line}[/dim]")

            findings, stats, errors = self._parser.parse(proc.stdout, binary)

            result = GoRunResult(
                binary=binary,
                args=args,
                exit_code=proc.returncode,
                stdout=proc.stdout,
                stderr=proc.stderr,
                duration_s=duration,
                findings=findings,
                stats=stats,
                errors=errors,
            )

            self._save_result(result)
            console.print(f"  {result.summary()}")
            return result

        except subprocess.TimeoutExpired:
            duration = time.time() - start
            return GoRunResult(
                binary=binary, args=args,
                exit_code=124,
                stdout="", stderr="",
                duration_s=duration,
                errors=[f"Timeout after {self.timeout}s"],
            )
        except FileNotFoundError:
            return GoRunResult(
                binary=binary, args=args,
                exit_code=127,
                stdout="", stderr="",
                duration_s=0.0,
                errors=[f"Binary not found: {binary_path}"],
            )
        except Exception as e:
            return GoRunResult(
                binary=binary, args=args,
                exit_code=1,
                stdout="", stderr="",
                duration_s=time.time() - start,
                errors=[f"Unexpected error: {e}"],
            )

    def stream(
        self,
        binary: str,
        args: list[str],
    ) -> Iterator[str]:
        """
        Stream stdout lines from a Go binary in real-time.
        Useful for long-running scans with progress output.
        """
        info = self._locator.find(binary)
        if not info.available:
            yield f'{{"error": "Binary {binary} not found"}}'
            return

        cmd = [info.path] + args
        try:
            with subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            ) as proc:
                for line in proc.stdout:
                    yield line.rstrip()
        except Exception as e:
            yield f'{{"error": "{e}"}}'

    def _save_result(self, result: GoRunResult) -> Path:
        """Save run result to JSON."""
        data = {
            "binary":     result.binary,
            "args":       result.args,
            "exit_code":  result.exit_code,
            "duration_s": round(result.duration_s, 2),
            "success":    result.success,
            "findings":   result.findings,
            "stats":      result.stats,
            "errors":     result.errors,
            "timestamp":  datetime.now(timezone.utc).isoformat(),
        }
        slug = result.binary.replace("/", "_")
        out = self.output_dir / f"{slug}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        out.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
        return out


# ── Health checker ────────────────────────────────────────

class GoHealthChecker:
    """Check which Go binaries are installed and their versions."""

    def __init__(self):
        self._locator = GoBinaryLocator()

    def check_all(self) -> dict[str, dict]:
        """
        Check all registered Go binaries.

        Returns:
            {binary_name: {installed, path, version, planned_at, install_cmd}}
        """
        results = {}
        for name, info in GO_BINARY_REGISTRY.items():
            binary = self._locator.find(name)
            results[name] = {
                "installed":   binary.available,
                "path":        binary.path or None,
                "version":     binary.version if binary.available else None,
                "planned_at":  info["planned_at"],
                "description": info["description"],
                "install_cmd": info["install"],
                "speedup":     info.get("speedup", "N/A"),
                "replaces":    info.get("replaces", ""),
            }
        return results

    def check_go_toolchain(self) -> dict:
        """Check if Go toolchain is installed."""
        go_path = shutil.which("go")
        if not go_path:
            return {"installed": False, "version": None, "path": None}

        try:
            result = subprocess.run(
                ["go", "version"],
                capture_output=True, text=True, timeout=5,
            )
            version_str = result.stdout.strip()
            # "go version go1.22.0 linux/amd64" -> "1.22.0"
            parts = version_str.split()
            version = parts[2].replace("go", "") if len(parts) >= 3 else "unknown"
            return {"installed": True, "version": version, "path": go_path}
        except Exception:
            return {"installed": True, "version": "unknown", "path": go_path}

    def print_status(self):
        """Print health check table to console."""
        from rich.table import Table
        go = self.check_go_toolchain()
        go_status = f"[green]Go {go['version']}[/green]" if go["installed"] else "[red]NOT INSTALLED[/red]"
        console.print(f"\n  Go toolchain: {go_status}")

        table = Table(show_header=True, header_style="bold magenta",
                      title="Glitchicons Go Modules")
        table.add_column("Binary",      style="cyan", width=14)
        table.add_column("Status",      width=12)
        table.add_column("Planned",     width=8)
        table.add_column("Speedup",     width=10)
        table.add_column("Description")

        for name, status in self.check_all().items():
            if status["installed"]:
                s = f"[green]v{status['version']}[/green]"
            else:
                s = f"[yellow]{status['planned_at']}[/yellow]"
            table.add_row(
                name,
                s,
                status["planned_at"],
                status["speedup"],
                status["description"],
            )
        console.print(table)
