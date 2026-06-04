# tests/test_plugin_marketplace.py
"""
Unit tests untuk modules/marketplace/plugin_marketplace.py
No network calls — pip subprocess di-mock.
"""

import json
import pytest
import time
from pathlib import Path
from unittest.mock import patch, MagicMock

from modules.marketplace.plugin_marketplace import (
    PluginRegistry, PluginInstaller, PluginValidator,
    PluginSandbox, PluginMarketplace,
    GlitchiconPluginBase, PluginMeta, MarketplaceEntry,
    ValidationResult, SandboxResult, InstallResult,
    COMMUNITY_CATALOG, RESERVED_NAMES,
)


# ── Sample plugins ────────────────────────────────────────

class GoodPlugin(GlitchiconPluginBase):
    name        = "test-scanner"
    version     = "1.2.3"
    description = "A well-formed test plugin for unit testing purposes"
    author      = "test-author"
    tags        = ["test", "scanner"]

    def run(self, target: str, **kwargs) -> list[dict]:
        return [{"title": "Test Finding", "severity": "LOW",
                 "target": target, "cvss": 0.0}]


class SlowPlugin(GlitchiconPluginBase):
    name        = "slow-plugin"
    version     = "1.0.0"
    description = "Plugin that sleeps forever for timeout testing"
    author      = "test"
    tags        = ["test"]

    def run(self, target: str, **kwargs) -> list[dict]:
        time.sleep(999)
        return []


class ErrorPlugin(GlitchiconPluginBase):
    name        = "error-plugin"
    version     = "1.0.0"
    description = "Plugin that always raises an exception"
    author      = "test"
    tags        = ["test"]

    def run(self, target: str, **kwargs) -> list[dict]:
        raise RuntimeError("Intentional error for testing")


class SpamPlugin(GlitchiconPluginBase):
    name        = "spam-plugin"
    version     = "1.0.0"
    description = "Plugin that returns too many findings"
    author      = "test"
    tags        = ["test"]

    def run(self, target: str, **kwargs) -> list[dict]:
        return [{"title": f"Finding {i}", "severity": "INFO"}
                for i in range(1000)]


class MissingRunPlugin:
    name        = "no-run-plugin"
    version     = "1.0.0"
    description = "Plugin missing the run method"
    author      = "test"
    tags        = []


class BadNamePlugin(GlitchiconPluginBase):
    name        = "ab"  # too short
    version     = "1.0.0"
    description = "Plugin with too-short name"
    author      = "test"
    tags        = []

    def run(self, target: str, **kwargs) -> list[dict]:
        return []


class ReservedNamePlugin(GlitchiconPluginBase):
    name        = "admin"
    version     = "1.0.0"
    description = "Plugin with reserved name for testing"
    author      = "test"
    tags        = []

    def run(self, target: str, **kwargs) -> list[dict]:
        return []


# ── Fixtures ──────────────────────────────────────────────

@pytest.fixture
def registry(tmp_path):
    return PluginRegistry(registry_path=str(tmp_path / "plugins.json"))


@pytest.fixture
def installer(registry):
    return PluginInstaller(registry=registry)


@pytest.fixture
def validator():
    return PluginValidator()


@pytest.fixture
def sandbox(registry):
    return PluginSandbox(timeout=2.0, max_findings=100, registry=registry)


@pytest.fixture
def marketplace(tmp_path, installer, registry):
    return PluginMarketplace(
        cache_dir=str(tmp_path / ".glitchicons"),
        installer=installer,
        registry=registry,
    )


# ── Tests: PluginRegistry ─────────────────────────────────

class TestPluginRegistry:

    @pytest.mark.unit
    def test_init_creates_file(self, tmp_path):
        reg = PluginRegistry(registry_path=str(tmp_path / "plugins.json"))
        assert (tmp_path / "plugins.json").exists()

    @pytest.mark.unit
    def test_register_plugin(self, registry):
        meta = registry.register(GoodPlugin)
        assert meta.name == "test-scanner"
        assert meta.version == "1.2.3"

    @pytest.mark.unit
    def test_get_registered_class(self, registry):
        registry.register(GoodPlugin)
        cls = registry.get("test-scanner")
        assert cls is GoodPlugin

    @pytest.mark.unit
    def test_get_meta(self, registry):
        registry.register(GoodPlugin)
        meta = registry.get_meta("test-scanner")
        assert meta is not None
        assert meta.author == "test-author"

    @pytest.mark.unit
    def test_get_unknown_returns_none(self, registry):
        assert registry.get("nonexistent") is None

    @pytest.mark.unit
    def test_list_all(self, registry):
        registry.register(GoodPlugin)
        all_plugins = registry.list_all()
        assert any(m.name == "test-scanner" for m in all_plugins)

    @pytest.mark.unit
    def test_list_enabled(self, registry):
        registry.register(GoodPlugin)
        registry.disable("test-scanner")
        enabled = registry.list_enabled()
        assert not any(m.name == "test-scanner" for m in enabled)

    @pytest.mark.unit
    def test_enable_disable(self, registry):
        registry.register(GoodPlugin)
        assert registry.disable("test-scanner") is True
        assert registry.get_meta("test-scanner").enabled is False
        assert registry.enable("test-scanner") is True
        assert registry.get_meta("test-scanner").enabled is True

    @pytest.mark.unit
    def test_enable_unknown_returns_false(self, registry):
        assert registry.enable("nonexistent") is False

    @pytest.mark.unit
    def test_list_by_tag(self, registry):
        registry.register(GoodPlugin)
        tagged = registry.list_by_tag("scanner")
        assert any(m.name == "test-scanner" for m in tagged)

    @pytest.mark.unit
    def test_list_by_tag_no_match(self, registry):
        registry.register(GoodPlugin)
        tagged = registry.list_by_tag("nonexistent-tag")
        assert tagged == []

    @pytest.mark.unit
    def test_record_run(self, registry):
        registry.register(GoodPlugin)
        registry.record_run("test-scanner")
        meta = registry.get_meta("test-scanner")
        assert meta.run_count == 1
        assert meta.last_run != ""

    @pytest.mark.unit
    def test_record_run_error(self, registry):
        registry.register(GoodPlugin)
        registry.record_run("test-scanner", error=True)
        meta = registry.get_meta("test-scanner")
        assert meta.error_count == 1

    @pytest.mark.unit
    def test_persistence_roundtrip(self, tmp_path):
        path = tmp_path / "plugins.json"
        reg1 = PluginRegistry(registry_path=str(path))
        reg1.register(GoodPlugin)
        reg1.record_run("test-scanner")

        reg2 = PluginRegistry(registry_path=str(path))
        meta = reg2.get_meta("test-scanner")
        assert meta is not None
        assert meta.run_count == 1

    @pytest.mark.unit
    def test_count_property(self, registry):
        assert registry.count == 0
        registry.register(GoodPlugin)
        assert registry.count == 1

    @pytest.mark.unit
    def test_tags_stored_as_list(self, registry):
        registry.register(GoodPlugin)
        meta = registry.get_meta("test-scanner")
        assert isinstance(meta.tags, list)
        assert "scanner" in meta.tags


# ── Tests: PluginInstaller ────────────────────────────────

class TestPluginInstaller:

    @pytest.mark.unit
    def test_normalize_name_with_prefix(self, installer):
        assert installer._normalize_name("glitchicons-jwt") == "glitchicons-jwt"

    @pytest.mark.unit
    def test_normalize_name_without_prefix(self, installer):
        assert installer._normalize_name("jwt") == "glitchicons-jwt"

    @pytest.mark.unit
    def test_install_success(self, installer):
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "Successfully installed glitchicons-jwt 1.0.0"
        mock_result.stderr = ""
        with patch("subprocess.run", return_value=mock_result):
            with patch.object(installer, "_get_installed_version", return_value="1.0.0"):
                result = installer.install("glitchicons-jwt-extra")
        assert result.success is True
        assert result.package_name == "glitchicons-jwt-extra"

    @pytest.mark.unit
    def test_install_failure(self, installer):
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stdout = ""
        mock_result.stderr = "ERROR: No matching distribution found"
        with patch("subprocess.run", return_value=mock_result):
            result = installer.install("glitchicons-nonexistent")
        assert result.success is False

    @pytest.mark.unit
    def test_install_timeout(self, installer):
        import subprocess as sp
        with patch("subprocess.run",
                   side_effect=sp.TimeoutExpired(cmd=["pip"], timeout=120)):
            result = installer.install("glitchicons-jwt-extra")
        assert result.success is False
        assert "timed out" in result.message.lower() or "timeout" in result.message.lower()

    @pytest.mark.unit
    def test_uninstall_success(self, installer):
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "Successfully uninstalled glitchicons-jwt"
        mock_result.stderr = ""
        with patch("subprocess.run", return_value=mock_result):
            result = installer.uninstall("glitchicons-jwt")
        assert result.success is True
        assert result.action == "uninstall"

    @pytest.mark.unit
    def test_is_installed_true(self, installer):
        with patch.object(installer, "_get_installed_version", return_value="1.0.0"):
            assert installer.is_installed("glitchicons-jwt") is True

    @pytest.mark.unit
    def test_is_installed_false(self, installer):
        with patch.object(installer, "_get_installed_version", return_value=""):
            assert installer.is_installed("glitchicons-notexist") is False

    @pytest.mark.unit
    def test_install_with_version(self, installer):
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "Successfully installed"
        mock_result.stderr = ""
        with patch("subprocess.run", return_value=mock_result) as mock_run:
            with patch.object(installer, "_get_installed_version", return_value="1.2.0"):
                installer.install("glitchicons-jwt", version="1.2.0")
        call_args = mock_run.call_args[0][0]
        assert "glitchicons-jwt==1.2.0" in call_args


# ── Tests: PluginValidator ────────────────────────────────

class TestPluginValidator:

    @pytest.mark.unit
    def test_valid_plugin_passes(self, validator):
        result = validator.validate(GoodPlugin)
        assert result.valid is True
        assert result.errors == []

    @pytest.mark.unit
    def test_missing_run_fails(self, validator):
        result = validator.validate(MissingRunPlugin)
        assert result.valid is False
        assert any("run" in e for e in result.errors)

    @pytest.mark.unit
    def test_name_too_short_fails(self, validator):
        result = validator.validate(BadNamePlugin)
        assert result.valid is False
        assert any("short" in e.lower() for e in result.errors)

    @pytest.mark.unit
    def test_reserved_name_fails(self, validator):
        result = validator.validate(ReservedNamePlugin)
        assert result.valid is False
        assert any("reserved" in e.lower() for e in result.errors)

    @pytest.mark.unit
    def test_valid_semver(self, validator):
        assert validator._valid_semver("1.2.3") is True
        assert validator._valid_semver("0.0.1") is True
        assert validator._valid_semver("2.0") is True

    @pytest.mark.unit
    def test_invalid_semver_warning(self, validator):
        class WeirdVersion(GoodPlugin):
            version = "not-a-version"
        result = validator.validate(WeirdVersion)
        assert any("version" in w.lower() for w in result.warnings)

    @pytest.mark.unit
    def test_passed_property(self, validator):
        result = validator.validate(GoodPlugin)
        assert result.passed is True

    @pytest.mark.unit
    def test_validate_many(self, validator):
        results = validator.validate_many([GoodPlugin, BadNamePlugin])
        assert len(results) == 2
        assert results[0].valid is True
        assert results[1].valid is False

    @pytest.mark.unit
    def test_plugin_name_in_result(self, validator):
        result = validator.validate(GoodPlugin)
        assert result.plugin_name == "test-scanner"

    @pytest.mark.unit
    def test_reserved_names_not_empty(self):
        assert len(RESERVED_NAMES) >= 4
        assert "admin" in RESERVED_NAMES
        assert "system" in RESERVED_NAMES


# ── Tests: PluginSandbox ──────────────────────────────────

class TestPluginSandbox:

    @pytest.mark.unit
    def test_run_success(self, sandbox):
        plugin = GoodPlugin()
        result = sandbox.run(plugin, "https://target.com")
        assert result.status == "success"
        assert len(result.findings) >= 1
        assert result.duration_s >= 0

    @pytest.mark.unit
    def test_run_class_instantiated(self, sandbox):
        result = sandbox.run(GoodPlugin, "https://target.com")
        assert result.status == "success"

    @pytest.mark.unit
    def test_run_timeout(self, sandbox):
        sandbox.timeout = 0.1
        result = sandbox.run(SlowPlugin(), "https://target.com")
        assert result.status == "timeout"
        assert result.findings == []
        assert "timeout" in result.error.lower()

    @pytest.mark.unit
    def test_run_error(self, sandbox):
        result = sandbox.run(ErrorPlugin(), "https://target.com")
        assert result.status == "error"
        assert result.findings == []
        assert "Intentional error" in result.error

    @pytest.mark.unit
    def test_run_truncated(self, sandbox):
        sandbox.max_findings = 10
        result = sandbox.run(SpamPlugin(), "https://target.com")
        assert result.status == "truncated"
        assert len(result.findings) == 10

    @pytest.mark.unit
    def test_run_updates_registry(self, sandbox, registry):
        registry.register(GoodPlugin)
        sandbox.run(GoodPlugin(), "https://target.com")
        meta = registry.get_meta("test-scanner")
        assert meta.run_count >= 1

    @pytest.mark.unit
    def test_run_records_error_in_registry(self, sandbox, registry):
        registry.register(ErrorPlugin)
        sandbox.run(ErrorPlugin(), "https://target.com")
        meta = registry.get_meta("error-plugin")
        assert meta.error_count >= 1

    @pytest.mark.unit
    def test_run_all(self, sandbox):
        plugins = [GoodPlugin(), GoodPlugin()]
        results = sandbox.run_all(plugins, "https://target.com")
        assert len(results) == 2
        assert all(r.status == "success" for r in results)

    @pytest.mark.unit
    def test_plugin_name_in_result(self, sandbox):
        result = sandbox.run(GoodPlugin(), "https://target.com")
        assert result.plugin_name == "test-scanner"

    @pytest.mark.unit
    def test_target_in_result(self, sandbox):
        result = sandbox.run(GoodPlugin(), "https://target.com")
        assert result.target == "https://target.com"


# ── Tests: PluginMarketplace ──────────────────────────────

class TestPluginMarketplace:

    @pytest.mark.unit
    def test_init_loads_catalog(self, marketplace):
        assert marketplace.catalog_size > 0

    @pytest.mark.unit
    def test_search_by_query(self, marketplace):
        results = marketplace.search("jwt")
        assert any("jwt" in e.package_name.lower() for e in results)

    @pytest.mark.unit
    def test_search_by_tag(self, marketplace):
        results = marketplace.search(tag="auth")
        assert isinstance(results, list)

    @pytest.mark.unit
    def test_search_verified_only(self, marketplace):
        results = marketplace.search(verified_only=True)
        assert all(e.verified for e in results)

    @pytest.mark.unit
    def test_search_empty_returns_all(self, marketplace):
        all_results = marketplace.search()
        assert len(all_results) == marketplace.catalog_size

    @pytest.mark.unit
    def test_search_sorted_by_stars(self, marketplace):
        results = marketplace.search()
        stars = [e.stars for e in results]
        assert stars == sorted(stars, reverse=True)

    @pytest.mark.unit
    def test_get_by_package_name(self, marketplace):
        entry = marketplace.get("glitchicons-jwt-extra")
        assert entry is not None
        assert entry.display_name == "JWT Extra Checks"

    @pytest.mark.unit
    def test_get_unknown_returns_none(self, marketplace):
        assert marketplace.get("glitchicons-nonexistent") is None

    @pytest.mark.unit
    def test_install_calls_installer(self, marketplace):
        mock_result = InstallResult("glitchicons-jwt-extra", "install", True, "ok", "2.1.0")
        with patch.object(marketplace.installer, "install", return_value=mock_result) as mock_install:
            result = marketplace.install("glitchicons-jwt-extra")
        mock_install.assert_called_once()
        assert result.success is True

    @pytest.mark.unit
    def test_refresh_reloads_catalog(self, marketplace):
        count = marketplace.refresh()
        assert count == len(COMMUNITY_CATALOG)

    @pytest.mark.unit
    def test_verified_count(self, marketplace):
        expected = sum(1 for e in COMMUNITY_CATALOG if e["verified"])
        assert marketplace.verified_count == expected

    @pytest.mark.unit
    def test_catalog_persistence(self, tmp_path):
        m1 = PluginMarketplace(cache_dir=str(tmp_path / ".glitchicons"))
        size = m1.catalog_size
        m2 = PluginMarketplace(cache_dir=str(tmp_path / ".glitchicons"))
        assert m2.catalog_size == size

    @pytest.mark.unit
    def test_community_catalog_structure(self):
        assert len(COMMUNITY_CATALOG) >= 5
        required = {"package_name", "display_name", "description",
                    "author", "version", "tags", "verified"}
        for entry in COMMUNITY_CATALOG:
            missing = required - set(entry.keys())
            assert not missing, f"{entry['package_name']} missing: {missing}"

    @pytest.mark.unit
    def test_community_catalog_has_verified(self):
        verified = [e for e in COMMUNITY_CATALOG if e["verified"]]
        assert len(verified) >= 3
