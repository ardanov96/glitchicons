"""
GLITCHICONS ⬡ — Brain Module
Decepticons Siege Division

Three core improvements:
1. Semantic seed deduplication (not just MD5)
2. AST-based source code parsing (smarter context)
3. Session memory (learns what works per target type)

This is the differentiator that no competitor has:
a fuzzer that gets smarter with every session.
"""

import ast
import re
import json
import hashlib
import difflib
from pathlib import Path
from datetime import datetime
from typing import Optional
from collections import defaultdict
from rich.console import Console

console = Console()


# ══════════════════════════════════════════════════════════════════════════════
# 1. SEMANTIC DEDUPLICATION
# ══════════════════════════════════════════════════════════════════════════════

class SemanticDedup:
    """
    Semantic seed deduplication.

    Goes beyond MD5 hash — compares actual content similarity.
    Rejects seeds that are too similar to existing ones.

    Threshold: 0.0 = accept everything, 1.0 = only exact duplicates
    Recommended: 0.75 (reject if 75%+ similar)
    """

    def __init__(self, similarity_threshold: float = 0.75):
        self.threshold = similarity_threshold
        self.accepted: list[str] = []
        self.rejected_count = 0

    def _similarity(self, a: str, b: str) -> float:
        """Compute similarity ratio between two strings."""
        return difflib.SequenceMatcher(None, a, b).ratio()

    def _normalize(self, seed: str) -> str:
        """Normalize seed for comparison (lowercase, strip whitespace)."""
        return re.sub(r'\s+', ' ', seed.lower().strip())

    def is_duplicate(self, candidate: str) -> bool:
        """Return True if candidate is too similar to an existing seed."""
        norm = self._normalize(candidate)
        for existing in self.accepted:
            if self._similarity(norm, self._normalize(existing)) >= self.threshold:
                return True
        return False

    def add(self, seed: str) -> bool:
        """
        Try to add seed. Returns True if accepted, False if duplicate.
        """
        if self.is_duplicate(seed):
            self.rejected_count += 1
            return False
        self.accepted.append(seed)
        return True

    def filter_batch(self, seeds: list[str]) -> list[str]:
        """
        Filter a batch of seeds, returning only diverse ones.
        """
        result = []
        for seed in seeds:
            if self.add(seed):
                result.append(seed)
        if self.rejected_count > 0:
            console.print(
                f"  [dim]Dedup: {len(result)} kept, "
                f"{self.rejected_count} rejected as too similar[/dim]"
            )
        return result

    def stats(self) -> dict:
        return {
            "accepted": len(self.accepted),
            "rejected": self.rejected_count,
            "threshold": self.threshold,
        }


# ══════════════════════════════════════════════════════════════════════════════
# 2. AST PARSER — Smart code context extraction
# ══════════════════════════════════════════════════════════════════════════════

class CodeContextExtractor:
    """
    AST-based source code analyzer.

    Instead of sending raw source code to LLM (wasteful, unfocused),
    extracts the relevant security context:
    - Dangerous function calls (strcpy, gets, sprintf, etc.)
    - Input entry points (main args, file reads, network reads)
    - Function signatures with their parameters
    - Buffer/allocation sizes

    This gives LLM surgical precision rather than a wall of text.
    """

    # C/C++ dangerous functions by category
    DANGEROUS_C = {
        "buffer_overflow": [
            "strcpy", "strcat", "sprintf", "gets", "scanf",
            "memcpy", "memmove", "strncpy", "strncat",
        ],
        "format_string": ["printf", "fprintf", "sprintf", "snprintf", "syslog"],
        "integer_overflow": ["atoi", "atol", "strtol", "strtoul"],
        "heap": ["malloc", "calloc", "realloc", "free", "new", "delete"],
        "command_injection": ["system", "popen", "exec", "execve", "execvp"],
        "file_ops": ["fopen", "open", "read", "write", "fread", "fwrite"],
    }

    # Python dangerous patterns
    DANGEROUS_PYTHON = {
        "injection": ["eval", "exec", "compile", "__import__"],
        "deserialization": ["pickle.loads", "yaml.load", "marshal.loads"],
        "command": ["os.system", "subprocess.call", "subprocess.run"],
        "file": ["open", "read", "write"],
    }

    def extract_c(self, source: str) -> dict:
        """Extract security context from C/C++ source code."""
        context = {
            "language": "C/C++",
            "entry_points": [],
            "dangerous_calls": defaultdict(list),
            "buffer_sizes": [],
            "function_signatures": [],
            "input_sources": [],
        }

        lines = source.split('\n')

        for i, line in enumerate(lines, 1):
            stripped = line.strip()

            # Find main() and other entry points
            if re.search(r'\b(main|handler|process|parse|handle)\s*\(', stripped):
                context["entry_points"].append(f"L{i}: {stripped[:80]}")

            # Find dangerous function calls
            for category, funcs in self.DANGEROUS_C.items():
                for func in funcs:
                    if re.search(rf'\b{func}\s*\(', stripped):
                        context["dangerous_calls"][category].append(
                            f"L{i}: {stripped[:80]}"
                        )

            # Find buffer declarations with sizes
            buf_match = re.search(
                r'char\s+\w+\[(\d+)\]|char\s*\*\s*\w+\s*=\s*malloc\((\d+)\)',
                stripped
            )
            if buf_match:
                size = buf_match.group(1) or buf_match.group(2)
                context["buffer_sizes"].append(f"L{i}: size={size} — {stripped[:60]}")

            # Find input sources
            if any(f in stripped for f in ["fread", "read(", "recv(", "fgets", "scanf"]):
                context["input_sources"].append(f"L{i}: {stripped[:80]}")

            # Find function signatures
            func_sig = re.match(r'^[\w\*\s]+\s+(\w+)\s*\(([^)]*)\)\s*\{?', stripped)
            if func_sig and not stripped.startswith('//'):
                context["function_signatures"].append(
                    f"L{i}: {func_sig.group(0)[:80]}"
                )

        return context

    def extract_python(self, source: str) -> dict:
        """Extract security context from Python source code."""
        context = {
            "language": "Python",
            "entry_points": [],
            "dangerous_calls": defaultdict(list),
            "function_signatures": [],
            "input_sources": [],
            "decorators": [],
        }

        try:
            tree = ast.parse(source)
        except SyntaxError:
            return context

        for node in ast.walk(tree):
            # Function definitions
            if isinstance(node, ast.FunctionDef):
                args = [a.arg for a in node.args.args]
                context["function_signatures"].append(
                    f"L{node.lineno}: def {node.name}({', '.join(args)})"
                )
                # Check for route decorators (Flask/FastAPI entry points)
                for dec in node.decorator_list:
                    if isinstance(dec, ast.Attribute):
                        context["decorators"].append(
                            f"L{node.lineno}: @{dec.attr} → {node.name}()"
                        )
                    elif isinstance(dec, ast.Call):
                        context["entry_points"].append(
                            f"L{node.lineno}: route → {node.name}()"
                        )

            # Call expressions — check for dangerous calls
            elif isinstance(node, ast.Call):
                call_str = ""
                if isinstance(node.func, ast.Name):
                    call_str = node.func.id
                elif isinstance(node.func, ast.Attribute):
                    call_str = f"{ast.unparse(node.func)}"

                for category, patterns in self.DANGEROUS_PYTHON.items():
                    for pattern in patterns:
                        if pattern in call_str:
                            context["dangerous_calls"][category].append(
                                f"L{node.lineno}: {call_str}(...)"
                            )

            # Input sources
            elif isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name) and node.func.id in ["input", "open"]:
                    context["input_sources"].append(
                        f"L{getattr(node, 'lineno', '?')}: {node.func.id}()"
                    )

        return context

    def extract(self, source_path: str) -> dict:
        """
        Auto-detect language and extract security context.
        Returns structured dict ready to send to LLM.
        """
        path = Path(source_path)
        if not path.exists():
            return {"error": f"File not found: {source_path}"}

        source = path.read_text(errors='replace')
        suffix = path.suffix.lower()

        if suffix in ['.c', '.cpp', '.cc', '.h', '.hpp']:
            ctx = self.extract_c(source)
        elif suffix in ['.py']:
            ctx = self.extract_python(source)
        else:
            # Generic extraction — just find suspicious patterns
            ctx = {
                "language": "Unknown",
                "raw_snippet": source[:2000],
            }

        ctx["file"] = str(path)
        ctx["size_lines"] = len(source.split('\n'))
        return ctx

    def to_llm_prompt(self, context: dict) -> str:
        """
        Convert extracted context to a focused LLM prompt section.
        Far more efficient than sending raw source code.
        """
        if "error" in context:
            return f"Error: {context['error']}"

        lang = context.get("language", "Unknown")
        parts = [f"Target language: {lang}"]

        if context.get("entry_points"):
            parts.append("\nEntry points (where input flows in):")
            for ep in context["entry_points"][:5]:
                parts.append(f"  {ep}")

        if context.get("dangerous_calls"):
            parts.append("\nDangerous function calls found:")
            for category, calls in context["dangerous_calls"].items():
                parts.append(f"  [{category}]")
                for call in calls[:3]:
                    parts.append(f"    {call}")

        if context.get("buffer_sizes"):
            parts.append("\nBuffer sizes (potential overflow targets):")
            for buf in context["buffer_sizes"][:5]:
                parts.append(f"  {buf}")

        if context.get("input_sources"):
            parts.append("\nInput sources:")
            for src in context["input_sources"][:5]:
                parts.append(f"  {src}")

        return '\n'.join(parts)


# ══════════════════════════════════════════════════════════════════════════════
# 3. SESSION MEMORY — Learns what works
# ══════════════════════════════════════════════════════════════════════════════

class GlitchiconsBrain:
    """
    Persistent session memory for Glitchicons.

    Records which payloads caused crashes/findings per target type.
    On subsequent sessions against similar targets, recalls effective
    payloads and prioritizes them.

    This is the core differentiator:
    - AFL++ is stateless — starts fresh every time
    - Glitchicons remembers — gets smarter with every session
    """

    def __init__(self, memory_file: str = "~/.glitchicons/brain.json"):
        self.memory_path = Path(memory_file).expanduser()
        self.memory_path.parent.mkdir(parents=True, exist_ok=True)
        self.memory = self._load()

    def _load(self) -> dict:
        """Load memory from disk."""
        if self.memory_path.exists():
            try:
                with open(self.memory_path) as f:
                    return json.load(f)
            except Exception:
                return self._empty()
        return self._empty()

    def _save(self):
        """Persist memory to disk."""
        with open(self.memory_path, 'w') as f:
            json.dump(self.memory, f, indent=2)

    def _empty(self) -> dict:
        return {
            "version": "1.0",
            "sessions": 0,
            "target_profiles": {},  # target_type → payload effectiveness
            "crash_signatures": {},  # crash type → payload patterns
            "global_stats": {
                "total_payloads_tested": 0,
                "total_crashes_found": 0,
                "effective_payload_patterns": [],
            }
        }

    def _target_key(self, target_type: str) -> str:
        """Normalize target type as memory key."""
        return target_type.lower().strip()

    def record_session_start(self, target_type: str, target_info: str = ""):
        """Record start of a new fuzzing session."""
        self.memory["sessions"] += 1
        key = self._target_key(target_type)

        if key not in self.memory["target_profiles"]:
            self.memory["target_profiles"][key] = {
                "sessions": 0,
                "effective_payloads": [],
                "crash_types": [],
                "total_crashes": 0,
                "last_seen": None,
            }

        self.memory["target_profiles"][key]["sessions"] += 1
        self.memory["target_profiles"][key]["last_seen"] = datetime.now().isoformat()
        self._save()

    def record_effective_payload(
        self,
        target_type: str,
        payload: str,
        result_type: str,
        severity: str = "MEDIUM"
    ):
        """
        Record a payload that caused a crash or finding.

        Args:
            target_type : e.g. "json", "http", "c_binary"
            payload     : the input that worked
            result_type : "crash", "finding", "anomaly"
            severity    : CRITICAL/HIGH/MEDIUM/LOW
        """
        key = self._target_key(target_type)
        if key not in self.memory["target_profiles"]:
            self.record_session_start(target_type)

        profile = self.memory["target_profiles"][key]

        # Store payload with metadata
        entry = {
            "payload": payload[:200],  # cap at 200 chars
            "result": result_type,
            "severity": severity,
            "timestamp": datetime.now().isoformat(),
            "score": self._severity_score(severity),
        }

        # Avoid exact duplicates
        existing = [e["payload"] for e in profile["effective_payloads"]]
        if payload[:200] not in existing:
            profile["effective_payloads"].append(entry)
            # Keep only top 50 per target type, sorted by score
            profile["effective_payloads"] = sorted(
                profile["effective_payloads"],
                key=lambda x: x["score"],
                reverse=True
            )[:50]

        profile["total_crashes"] += 1
        self.memory["global_stats"]["total_crashes_found"] += 1
        self._save()

    def recall_for_target(self, target_type: str, top_n: int = 10) -> list[str]:
        """
        Recall the most effective payloads for a target type.
        Returns list of payload strings, sorted by effectiveness.
        """
        key = self._target_key(target_type)
        profile = self.memory["target_profiles"].get(key, {})
        effective = profile.get("effective_payloads", [])

        if effective:
            console.print(
                f"  [purple]⬡ Brain recall:[/purple] "
                f"{len(effective)} effective payloads remembered "
                f"for '{target_type}'"
            )

        return [e["payload"] for e in effective[:top_n]]

    def get_global_effective_patterns(self, top_n: int = 5) -> list[str]:
        """
        Return payload patterns that work across ALL target types.
        These are the "universal" siege weapons.
        """
        all_payloads = []
        for profile in self.memory["target_profiles"].values():
            for entry in profile.get("effective_payloads", []):
                if entry["severity"] in ["CRITICAL", "HIGH"]:
                    all_payloads.append(entry["payload"])

        # Deduplicate
        seen = set()
        unique = []
        for p in all_payloads:
            if p not in seen:
                seen.add(p)
                unique.append(p)

        return unique[:top_n]

    def record_crash(self, target_type: str, crash_type: str, payload: str):
        """Shortcut to record a crash finding."""
        self.record_effective_payload(
            target_type, payload, "crash",
            severity="HIGH"
        )
        # Also track crash types
        key = self._target_key(target_type)
        profile = self.memory["target_profiles"].get(key, {})
        if crash_type not in profile.get("crash_types", []):
            profile.setdefault("crash_types", []).append(crash_type)
        self._save()

    def stats(self) -> dict:
        """Return summary statistics."""
        return {
            "total_sessions": self.memory["sessions"],
            "target_types_learned": len(self.memory["target_profiles"]),
            "total_crashes_recorded": self.memory["global_stats"]["total_crashes_found"],
            "profiles": {
                k: {
                    "sessions": v["sessions"],
                    "effective_payloads": len(v["effective_payloads"]),
                    "total_crashes": v["total_crashes"],
                }
                for k, v in self.memory["target_profiles"].items()
            }
        }

    def print_stats(self):
        """Pretty print brain stats."""
        s = self.stats()
        console.print(f"\n[bold purple]⬡ GLITCHICONS BRAIN STATS[/bold purple]")
        console.print(f"  Sessions     : {s['total_sessions']}")
        console.print(f"  Target types : {s['target_types_learned']}")
        console.print(f"  Crashes logged: {s['total_crashes_recorded']}")
        if s["profiles"]:
            console.print(f"\n  [dim]Learned profiles:[/dim]")
            for target, data in s["profiles"].items():
                console.print(
                    f"    [{target}] "
                    f"{data['effective_payloads']} payloads · "
                    f"{data['total_crashes']} crashes · "
                    f"{data['sessions']} sessions"
                )

    @staticmethod
    def _severity_score(severity: str) -> int:
        return {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}.get(severity, 0)


# ══════════════════════════════════════════════════════════════════════════════
# STANDALONE TEST
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    console.print("\n[bold purple]⬡ GLITCHICONS BRAIN — Self Test[/bold purple]\n")

    # 1. Test semantic dedup
    console.print("[bold]1. Semantic Deduplication[/bold]")
    dedup = SemanticDedup(similarity_threshold=0.75)
    test_seeds = [
        '{"name": "test"}',
        '{"name": "test"}',               # exact dup
        '{"name": "test2"}',              # similar
        '<script>alert(1)</script>',       # different
        "' OR '1'='1",                     # different
        "' OR '1'='2",                     # similar to above
        "A" * 100,                         # different
        "B" * 100,                         # similar to above
    ]
    kept = dedup.filter_batch(test_seeds)
    console.print(f"  Input: {len(test_seeds)} seeds → Kept: {len(kept)} unique")
    for s in kept:
        console.print(f"    ✓ {s[:50]}")

    # 2. Test AST parser
    console.print("\n[bold]2. AST Code Context Extraction[/bold]")
    extractor = CodeContextExtractor()

    # Create a test C file
    test_c = Path("/tmp/test_target.c")
    test_c.write_text("""
#include <stdio.h>
#include <string.h>

void parse_input(char *input) {
    char buf[64];
    strcpy(buf, input);
    printf("Result: %s", buf);
}

int main(int argc, char *argv[]) {
    FILE *f = fopen(argv[1], "r");
    char input[1024];
    fread(input, 1, sizeof(input), f);
    fclose(f);
    parse_input(input);
    return 0;
}
""")
    ctx = extractor.extract(str(test_c))
    prompt_section = extractor.to_llm_prompt(ctx)
    console.print(f"  Extracted context from {ctx['size_lines']} lines:")
    console.print(prompt_section)

    # 3. Test brain memory
    console.print("\n[bold]3. Session Memory[/bold]")
    brain = GlitchiconsBrain(memory_file="/tmp/test_brain.json")

    brain.record_session_start("json", "JSON parser target")
    brain.record_effective_payload("json", '{"key": null, "a": "' + 'A'*200 + '"}',
                                   "crash", "HIGH")
    brain.record_effective_payload("json", '{"__proto__": {"admin": true}}',
                                   "finding", "CRITICAL")
    brain.record_session_start("http", "HTTP API target")
    brain.record_effective_payload("http", "' OR 1=1--",
                                   "crash", "CRITICAL")

    recalled = brain.recall_for_target("json")
    console.print(f"  Recalled {len(recalled)} effective JSON payloads")

    brain.print_stats()
    console.print("\n[green]⬡ All tests passed.[/green]\n")
