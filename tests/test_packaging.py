# tests/test_packaging.py
"""
Unit tests untuk v1.0.0 packaging:
  - glitchicons/__init__.py public API
  - glitchicons/cli.py commands
  - glitchicons/plugin_system.py plugin interface
"""

import json
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock


# ── Tests: __init__.py public API ─────────────────────────

class TestPublicAPI:

    @pytest.mark.unit
    def test_version_exists(self):
        from glitchicons import __version__
        assert __version__ == "1.0.0"

    @pytest.mark.unit
    def test_version_format(self):
        from glitchicons import __version__
        parts = __version__.split(".")
        assert len(parts) == 3
        assert all(p.isdigit() for p in parts)

    @pytest.mark.unit
    def test_author_exists(self):
        from glitchicons import __author__
        assert __author__ == "ardanov96"

    @pytest.mark.unit
    def test_license_exists(self):
        from glitchicons import __license__
        assert __license__ == "MIT"

    @pytest.mark.unit
    def test_url_is_github(self):
        from glitchicons import __url__
        assert "github.com" in __url__
        assert "glitchicons" in __url__

    @pytest.mark.unit
    def test_graphql_fuzzer_importable(self):
        from glitchicons import GraphQLFuzzer
        assert GraphQLFuzzer is not None

    @pytest.mark.unit
    def test_websocket_fuzzer_importable(self):
        from glitchicons import WebSocketFuzzer
        assert WebSocketFuzzer is not None

    @pytest.mark.unit
    def test_cors_checker_importable(self):
        from glitchicons import CORSChecker
        assert CORSChecker is not None

    @pytest.mark.unit
    def test_openapi_parser_importable(self):
        from glitchicons import OpenAPIParser
        assert OpenAPIParser is not None

    @pytest.mark.unit
    def test_llm_mutator_importable(self):
        from glitchicons import LLMMutator
        assert LLMMutator is not None

    @pytest.mark.unit
    def test_fp_reducer_importable(self):
        from glitchicons import FalsePositiveReducer
        assert FalsePositiveReducer is not None

    @pytest.mark.unit
    def test_severity_reasoner_importable(self):
        from glitchicons import SeverityReasoner
        assert SeverityReasoner is not None

    @pytest.mark.unit
    def test_waf_evasion_importable(self):
        from glitchicons import WAFEvasionEngine
        assert WAFEvasionEngine is not None

    @pytest.mark.unit
    def test_html_reporter_importable(self):
        from glitchicons import HTMLReporter
        assert HTMLReporter is not None

    @pytest.mark.unit
    def test_config_loader_importable(self):
        from glitchicons import ConfigLoader
        assert ConfigLoader is not None

    @pytest.mark.unit
    def test_all_exports_importable(self):
        """Semua yang ada di __all__ harus bisa di-import."""
        import glitchicons
        for name in glitchicons.__all__:
            assert hasattr(glitchicons, name), f"Missing export: {name}"

    @pytest.mark.unit
    def test_cvss_calculator_importable(self):
        from glitchicons import CVSSCalculator
        assert CVSSCalculator is not None


# ── Tests: Plugin System ──────────────────────────────────

class TestPluginSystem:

    @pytest.mark.unit
    def test_plugin_base_class_importable(self):
        from glitchicons.plugin_system import GlitchiconPlugin
        assert GlitchiconPlugin is not None

    @pytest.mark.unit
    def test_plugin_registry_importable(self):
        from glitchicons.plugin_system import PluginRegistry
        assert PluginRegistry is not None

    @pytest.mark.unit
    def test_make_finding_importable(self):
        from glitchicons.plugin_system import make_finding
        assert make_finding is not None

    @pytest.mark.unit
    def test_example_plugin_importable(self):
        from glitchicons.plugin_system import ExamplePlugin
        assert ExamplePlugin is not None

    @pytest.mark.unit
    def test_plugin_is_abstract(self):
        """GlitchiconPlugin tidak bisa di-instantiate langsung."""
        from glitchicons.plugin_system import GlitchiconPlugin
        with pytest.raises(TypeError):
            GlitchiconPlugin()

    @pytest.mark.unit
    def test_concrete_plugin_must_implement_run(self):
        """Plugin tanpa run() harus raise TypeError."""
        from glitchicons.plugin_system import GlitchiconPlugin
        class IncompletePlugin(GlitchiconPlugin):
            name = "incomplete"
        with pytest.raises(TypeError):
            IncompletePlugin()

    @pytest.mark.unit
    def test_concrete_plugin_works(self):
        """Plugin yang implement run() harus bisa di-instantiate."""
        from glitchicons.plugin_system import GlitchiconPlugin
        class ConcretePlugin(GlitchiconPlugin):
            name = "test-plugin"
            version = "1.0.0"
            description = "Test"
            def run(self, target, **kwargs):
                return []
        p = ConcretePlugin()
        assert p.name == "test-plugin"
        assert p.run(target="https://t.com") == []

    @pytest.mark.unit
    def test_plugin_repr(self):
        from glitchicons.plugin_system import GlitchiconPlugin
        class MyPlugin(GlitchiconPlugin):
            name = "my-plugin"
            version = "2.0.0"
            def run(self, target, **kwargs): return []
        p = MyPlugin()
        assert "my-plugin" in repr(p)
        assert "2.0.0" in repr(p)

    @pytest.mark.unit
    def test_registry_discover_no_plugins(self):
        """Jika tidak ada plugin terinstall, discover() return list kosong."""
        from glitchicons.plugin_system import PluginRegistry
        registry = PluginRegistry()
        with patch("glitchicons.plugin_system.entry_points", return_value=[],
                   create=True):
            plugins = registry.discover()
            assert isinstance(plugins, list)

    @pytest.mark.unit
    def test_registry_get_none_for_missing(self):
        from glitchicons.plugin_system import PluginRegistry
        registry = PluginRegistry()
        registry._discovered = True
        registry._plugins = []
        result = registry.get("nonexistent-plugin")
        assert result is None

    @pytest.mark.unit
    def test_registry_count_property(self):
        from glitchicons.plugin_system import PluginRegistry
        registry = PluginRegistry()
        registry._discovered = True
        registry._plugins = []
        assert registry.count == 0

    @pytest.mark.unit
    def test_registry_repr(self):
        from glitchicons.plugin_system import PluginRegistry
        registry = PluginRegistry()
        registry._discovered = True
        registry._plugins = []
        assert "PluginRegistry" in repr(registry)


# ── Tests: make_finding() ─────────────────────────────────

class TestMakeFinding:

    @pytest.mark.unit
    def test_valid_finding_created(self):
        from glitchicons.plugin_system import make_finding
        f = make_finding(
            title="Test Finding",
            severity="HIGH",
            cvss=7.5,
            cwe="CWE-89",
            description="SQLi found",
            evidence="Error in SQL syntax",
            remediation="Use parameterized queries",
            target="https://target.com",
        )
        assert f["title"] == "Test Finding"
        assert f["severity"] == "HIGH"
        assert f["cvss"] == 7.5

    @pytest.mark.unit
    def test_finding_has_timestamp(self):
        from glitchicons.plugin_system import make_finding
        f = make_finding("T", "HIGH", 7.5, "CWE-89", "d", "e", "r", "https://t.com")
        assert "timestamp" in f
        assert "2026" in f["timestamp"] or "202" in f["timestamp"]

    @pytest.mark.unit
    def test_finding_has_source(self):
        from glitchicons.plugin_system import make_finding
        f = make_finding("T", "HIGH", 7.5, "CWE-89", "d", "e", "r", "https://t.com",
                         plugin_name="my-plugin")
        assert "plugin:my-plugin" in f["source"]

    @pytest.mark.unit
    def test_invalid_severity_raises(self):
        from glitchicons.plugin_system import make_finding
        with pytest.raises(AssertionError):
            make_finding("T", "EXTREME", 7.5, "CWE-89", "d", "e", "r", "https://t.com")

    @pytest.mark.unit
    def test_cvss_out_of_range_raises(self):
        from glitchicons.plugin_system import make_finding
        with pytest.raises(AssertionError):
            make_finding("T", "HIGH", 11.0, "CWE-89", "d", "e", "r", "https://t.com")

    @pytest.mark.unit
    def test_invalid_cwe_format_raises(self):
        from glitchicons.plugin_system import make_finding
        with pytest.raises(AssertionError):
            make_finding("T", "HIGH", 7.5, "89", "d", "e", "r", "https://t.com")

    @pytest.mark.unit
    def test_extra_fields_preserved(self):
        from glitchicons.plugin_system import make_finding
        f = make_finding("T", "HIGH", 7.5, "CWE-89", "d", "e", "r", "https://t.com",
                         custom_field="custom_value")
        assert f["custom_field"] == "custom_value"

    @pytest.mark.unit
    def test_all_severities_accepted(self):
        from glitchicons.plugin_system import make_finding
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            f = make_finding("T", sev, 5.0, "CWE-1", "d", "e", "r", "https://t.com")
            assert f["severity"] == sev


# ── Tests: Plugin validation ──────────────────────────────

class TestPluginValidation:

    @pytest.fixture
    def plugin(self):
        from glitchicons.plugin_system import GlitchiconPlugin
        class TestPlugin(GlitchiconPlugin):
            name = "test"
            def run(self, target, **kwargs): return []
        return TestPlugin()

    @pytest.mark.unit
    def test_validate_finding_valid(self, plugin):
        finding = {
            "title": "T", "severity": "HIGH", "cvss": 7.5,
            "cwe": "CWE-89", "description": "d",
            "evidence": "e", "remediation": "r",
        }
        assert plugin.validate_finding(finding) is True

    @pytest.mark.unit
    def test_validate_finding_missing_field(self, plugin):
        finding = {
            "title": "T", "severity": "HIGH",
            # missing cvss, cwe, description, evidence, remediation
        }
        assert plugin.validate_finding(finding) is False

    @pytest.mark.unit
    def test_check_requirements_no_deps(self, plugin):
        plugin.requires = []
        assert plugin.check_requirements() == []

    @pytest.mark.unit
    def test_check_requirements_installed(self, plugin):
        plugin.requires = ["json", "os"]  # stdlib always available
        assert plugin.check_requirements() == []

    @pytest.mark.unit
    def test_check_requirements_missing(self, plugin):
        plugin.requires = ["nonexistent_package_xyz"]
        missing = plugin.check_requirements()
        assert "nonexistent_package_xyz" in missing


# ── Tests: pyproject.toml ─────────────────────────────────

class TestPyprojectToml:

    @pytest.mark.unit
    def test_pyproject_exists(self):
        assert Path("pyproject.toml").exists()

    @pytest.mark.unit
    def test_pyproject_has_version_100(self):
        content = Path("pyproject.toml").read_text()
        assert 'version = "1.0.0"' in content

    @pytest.mark.unit
    def test_pyproject_has_entry_point(self):
        content = Path("pyproject.toml").read_text()
        assert "glitchicons.cli:main" in content or "glitchicons = " in content

    @pytest.mark.unit
    def test_pyproject_has_plugin_entry_point(self):
        content = Path("pyproject.toml").read_text()
        assert "glitchicons.plugins" in content

    @pytest.mark.unit
    def test_pyproject_python_requires(self):
        content = Path("pyproject.toml").read_text()
        assert ">=3.10" in content

    @pytest.mark.unit
    def test_pyproject_has_classifiers(self):
        content = Path("pyproject.toml").read_text()
        assert "Production/Stable" in content
        assert "Topic :: Security" in content
