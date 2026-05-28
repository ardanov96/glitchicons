# tests/test_go_runner.py
"""
Unit tests untuk modules/go/go_runner.py
Subprocess calls di-mock — tidak butuh Go binary nyata.
"""

import json
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock, call
import subprocess

from modules.go.go_runner import (
    GoRunner,
    GoOutputParser,
    GoBinaryLocator,
    GoHealthChecker,
    GoRunResult,
    BinaryInfo,
    GO_BINARY_REGISTRY,
    validate_go_output,
)


# ── Sample data ───────────────────────────────────────────

VALID_GO_OUTPUT = {
    "tool":     "glitchrace",
    "version":  "1.0.0",
    "target":   "https://target.com/api/checkout",
    "started":  "2026-05-28T12:00:00Z",
    "finished": "2026-05-28T12:00:05Z",
    "exit_code": 0,
    "findings": [
        {
            "id":          "RACE-001",
            "title":       "Race Condition — Coupon Double-Spend",
            "severity":    "CRITICAL",
            "cvss":        9.0,
            "cwe":         "CWE-362",
            "target":      "https://target.com/api/checkout",
            "description": "Concurrent requests bypass coupon single-use check.",
            "evidence":    "50/50 threads accepted same coupon",
            "remediation": "Use atomic DB transactions.",
        }
    ],
    "stats": {
        "threads":     50,
        "requests":    50,
        "duration_ms": 4800,
        "success_rate": 1.0,
    }
}

INVALID_GO_OUTPUT_MISSING_FIELDS = {
    "tool": "glitchrace",
    # missing version, target, findings, exit_code
}

VALID_GO_OUTPUT_EMPTY = {
    "tool":     "glitchscan",
    "version":  "1.0.0",
    "target":   "192.168.1.1",
    "exit_code": 0,
    "findings": [],
    "stats":    {"ports_scanned": 1000, "open_ports": 0},
}


# ── Fixtures ──────────────────────────────────────────────

@pytest.fixture
def runner(tmp_path):
    return GoRunner(
        timeout=10,
        output_dir=str(tmp_path / "go"),
        stream_stderr=False,
    )


@pytest.fixture
def parser():
    return GoOutputParser()


@pytest.fixture
def locator():
    return GoBinaryLocator()


# ── Tests: validate_go_output ─────────────────────────────

class TestValidateGoOutput:

    @pytest.mark.unit
    def test_valid_output_no_errors(self):
        errors = validate_go_output(VALID_GO_OUTPUT)
        assert errors == []

    @pytest.mark.unit
    def test_valid_empty_findings(self):
        errors = validate_go_output(VALID_GO_OUTPUT_EMPTY)
        assert errors == []

    @pytest.mark.unit
    def test_missing_top_level_fields(self):
        errors = validate_go_output(INVALID_GO_OUTPUT_MISSING_FIELDS)
        assert len(errors) >= 1
        assert any("Missing" in e for e in errors)

    @pytest.mark.unit
    def test_invalid_finding_severity(self):
        data = dict(VALID_GO_OUTPUT)
        data["findings"] = [{
            **VALID_GO_OUTPUT["findings"][0],
            "severity": "EXTREME",
        }]
        errors = validate_go_output(data)
        assert any("severity" in e for e in errors)

    @pytest.mark.unit
    def test_invalid_cvss_out_of_range(self):
        data = dict(VALID_GO_OUTPUT)
        data["findings"] = [{
            **VALID_GO_OUTPUT["findings"][0],
            "cvss": 11.0,
        }]
        errors = validate_go_output(data)
        assert any("cvss" in e for e in errors)

    @pytest.mark.unit
    def test_findings_not_list(self):
        data = {**VALID_GO_OUTPUT, "findings": "not a list"}
        errors = validate_go_output(data)
        assert any("list" in e for e in errors)

    @pytest.mark.unit
    def test_missing_finding_fields(self):
        data = dict(VALID_GO_OUTPUT)
        data["findings"] = [{"title": "T"}]  # missing severity, cvss, cwe, description
        errors = validate_go_output(data)
        assert len(errors) >= 1


# ── Tests: GoOutputParser ─────────────────────────────────

class TestGoOutputParser:

    @pytest.mark.unit
    def test_parse_valid_json_blob(self, parser):
        raw = json.dumps(VALID_GO_OUTPUT)
        findings, stats, errors = parser.parse(raw, "glitchrace")
        assert len(findings) == 1
        assert errors == []
        assert stats["threads"] == 50

    @pytest.mark.unit
    def test_parse_empty_output(self, parser):
        findings, stats, errors = parser.parse("", "glitchrace")
        assert findings == []
        assert len(errors) >= 1

    @pytest.mark.unit
    def test_parse_empty_findings(self, parser):
        raw = json.dumps(VALID_GO_OUTPUT_EMPTY)
        findings, stats, errors = parser.parse(raw, "glitchscan")
        assert findings == []
        assert errors == []
        assert stats["ports_scanned"] == 1000

    @pytest.mark.unit
    def test_parse_ndjson(self, parser):
        """One JSON object per line (NDJSON format)."""
        line1 = json.dumps({"findings": [VALID_GO_OUTPUT["findings"][0]], "stats": {}})
        line2 = json.dumps({"findings": [], "stats": {"done": True}})
        raw = line1 + "\n" + line2
        findings, stats, errors = parser.parse(raw, "glitchrace")
        assert len(findings) == 1

    @pytest.mark.unit
    def test_adapt_finding_source_tagged(self, parser):
        raw = json.dumps(VALID_GO_OUTPUT)
        findings, _, _ = parser.parse(raw, "glitchrace")
        assert findings[0]["source"] == "go:glitchrace"

    @pytest.mark.unit
    def test_adapt_finding_maps_fields(self, parser):
        raw = json.dumps(VALID_GO_OUTPUT)
        findings, _, _ = parser.parse(raw, "glitchrace")
        f = findings[0]
        assert f["title"] == "Race Condition — Coupon Double-Spend"
        assert f["severity"] == "CRITICAL"
        assert f["cvss"] == 9.0
        assert f["cwe"] == "CWE-362"

    @pytest.mark.unit
    def test_adapt_finding_maps_url_alias(self, parser):
        """Go binary may use 'url' instead of 'target'."""
        # Use finding WITHOUT 'target' — only 'url'
        finding_no_target = {k: v for k, v in VALID_GO_OUTPUT["findings"][0].items()
                             if k != "target"}
        finding_no_target["url"] = "https://url-alias.com"
        raw = json.dumps({**VALID_GO_OUTPUT, "findings": [finding_no_target]})
        findings, _, _ = parser.parse(raw, "glitchrace")
        assert findings[0]["target"] == "https://url-alias.com"

    @pytest.mark.unit
    def test_parse_invalid_json(self, parser):
        findings, stats, errors = parser.parse("not json at all", "test")
        assert len(errors) >= 1 or findings == []

    @pytest.mark.unit
    def test_cvss_coerced_to_float(self, parser):
        data = dict(VALID_GO_OUTPUT)
        data["findings"] = [{**VALID_GO_OUTPUT["findings"][0], "cvss": 9}]  # int
        raw = json.dumps(data)
        findings, _, _ = parser.parse(raw, "test")
        assert isinstance(findings[0]["cvss"], float)


# ── Tests: GoBinaryLocator ────────────────────────────────

class TestGoBinaryLocator:

    @pytest.mark.unit
    def test_find_missing_binary_returns_empty_path(self, locator):
        info = locator.find("glitchrace_nonexistent_xyz")
        assert info.path == ""
        assert not info.available

    @pytest.mark.unit
    def test_find_with_mock_allowed(self, locator):
        info = locator.find("glitchrace_nonexistent_xyz", allow_mock=True)
        assert info.is_mock is True
        assert info.version == "mock"

    @pytest.mark.unit
    def test_find_all_returns_dict(self, locator):
        result = locator.find_all()
        assert isinstance(result, dict)
        for name in GO_BINARY_REGISTRY:
            assert name in result

    @pytest.mark.unit
    def test_binary_info_available_false_for_empty_path(self):
        info = BinaryInfo(name="test", path="", version="")
        assert info.available is False

    @pytest.mark.unit
    def test_binary_info_available_true_for_path(self):
        info = BinaryInfo(name="test", path="/usr/local/bin/test", version="1.0.0")
        assert info.available is True

    @pytest.mark.unit
    def test_find_python_binary(self, locator):
        """'python' atau 'python3' harus ditemukan di PATH."""
        import shutil
        python = shutil.which("python") or shutil.which("python3")
        if python:
            bin_name = "python" if shutil.which("python") else "python3"
            info = locator.find(bin_name)
            assert info.available is True


# ── Tests: GoRunner ───────────────────────────────────────

class TestGoRunner:

    @pytest.mark.unit
    def test_run_missing_binary_returns_error(self, runner):
        result = runner.run("glitchrace_notinstalled_xyz", [])
        assert result.success is False
        assert result.exit_code == 127
        assert len(result.errors) >= 1

    @pytest.mark.unit
    @patch("subprocess.run")
    def test_run_success(self, mock_run, runner):
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=json.dumps(VALID_GO_OUTPUT),
            stderr="",
        )
        with patch.object(runner._locator, "find") as mock_find:
            mock_find.return_value = BinaryInfo(
                name="glitchrace", path="/usr/local/bin/glitchrace", version="1.0.0"
            )
            result = runner.run("glitchrace", ["--target", "https://t.com"])

        assert result.success is True
        assert result.exit_code == 0
        assert len(result.findings) == 1
        assert result.findings[0]["severity"] == "CRITICAL"

    @pytest.mark.unit
    @patch("subprocess.run")
    def test_run_saves_result_file(self, mock_run, runner):
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=json.dumps(VALID_GO_OUTPUT_EMPTY),
            stderr="",
        )
        with patch.object(runner._locator, "find") as mock_find:
            mock_find.return_value = BinaryInfo(
                name="glitchscan", path="/bin/glitchscan", version="1.0.0"
            )
            result = runner.run("glitchscan", ["--target", "192.168.1.1"])

        saved_files = list(runner.output_dir.glob("glitchscan_*.json"))
        assert len(saved_files) == 1

    @pytest.mark.unit
    @patch("subprocess.run")
    def test_run_timeout_returns_error(self, mock_run, runner):
        mock_run.side_effect = subprocess.TimeoutExpired(cmd=["test"], timeout=10)
        with patch.object(runner._locator, "find") as mock_find:
            mock_find.return_value = BinaryInfo(name="t", path="/bin/t", version="1.0")
            result = runner.run("t", [])

        assert result.exit_code == 124
        assert any("Timeout" in e for e in result.errors)

    @pytest.mark.unit
    def test_go_run_result_summary(self):
        result = GoRunResult(
            binary="glitchrace", args=["--target", "https://t.com"],
            exit_code=0, stdout="", stderr="",
            duration_s=4.5, findings=[{"title": "F"}], stats={}, errors=[],
        )
        summary = result.summary()
        assert "glitchrace" in summary
        assert "OK" in summary
        assert "1" in summary  # 1 finding

    @pytest.mark.unit
    def test_go_run_result_success_false_on_error(self):
        result = GoRunResult(
            binary="t", args=[], exit_code=0,
            stdout="", stderr="", duration_s=1.0,
            errors=["something went wrong"],
        )
        assert result.success is False


# ── Tests: GoHealthChecker ────────────────────────────────

class TestGoHealthChecker:

    @pytest.mark.unit
    def test_check_all_returns_all_binaries(self):
        checker = GoHealthChecker()
        results = checker.check_all()
        for name in GO_BINARY_REGISTRY:
            assert name in results

    @pytest.mark.unit
    def test_check_all_has_required_fields(self):
        checker = GoHealthChecker()
        results = checker.check_all()
        required = {"installed", "planned_at", "description", "install_cmd"}
        for name, info in results.items():
            missing = required - set(info.keys())
            assert not missing, f"{name} missing: {missing}"

    @pytest.mark.unit
    def test_check_go_toolchain(self):
        checker = GoHealthChecker()
        result = checker.check_go_toolchain()
        assert "installed" in result
        assert "version" in result
        assert "path" in result

    @pytest.mark.unit
    def test_uninstalled_binary_not_available(self):
        checker = GoHealthChecker()
        results = checker.check_all()
        # glitchrace shouldn't be installed in test env
        for name, info in results.items():
            if not info["installed"]:
                assert info["path"] is None
                assert info["version"] is None


# ── Tests: Go Binary Registry ─────────────────────────────

class TestGoBinaryRegistry:

    @pytest.mark.unit
    def test_all_planned_binaries_registered(self):
        expected = {"glitchrace", "glitchscan", "glitchfuzz",
                    "glitchdns", "glitchtls", "glitchproxy"}
        assert expected == set(GO_BINARY_REGISTRY.keys())

    @pytest.mark.unit
    def test_each_binary_has_required_fields(self):
        required = {"description", "version", "planned_at",
                    "github", "install", "capabilities"}
        for name, info in GO_BINARY_REGISTRY.items():
            missing = required - set(info.keys())
            assert not missing, f"{name} missing: {missing}"

    @pytest.mark.unit
    def test_install_commands_use_go_install(self):
        for name, info in GO_BINARY_REGISTRY.items():
            assert "go install" in info["install"], \
                f"{name} install command should use 'go install'"

    @pytest.mark.unit
    def test_github_urls_valid(self):
        for name, info in GO_BINARY_REGISTRY.items():
            assert info["github"].startswith("https://github.com"), \
                f"{name} github URL invalid"

    @pytest.mark.unit
    def test_capabilities_not_empty(self):
        for name, info in GO_BINARY_REGISTRY.items():
            assert len(info["capabilities"]) >= 1, \
                f"{name} must have at least 1 capability"

    @pytest.mark.unit
    def test_version_progression(self):
        """glitchrace/glitchscan planned v1.1.0, later ones later."""
        assert GO_BINARY_REGISTRY["glitchrace"]["planned_at"] == "v1.1.0"
        assert GO_BINARY_REGISTRY["glitchscan"]["planned_at"] == "v1.1.0"
        assert GO_BINARY_REGISTRY["glitchfuzz"]["planned_at"] == "v1.2.0"
        assert GO_BINARY_REGISTRY["glitchdns"]["planned_at"]  == "v1.2.0"
