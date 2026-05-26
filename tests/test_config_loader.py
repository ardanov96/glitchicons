# tests/test_config_loader.py
"""
Unit tests untuk modules/config/config_loader.py
"""

import os
import pytest
from pathlib import Path


# ── Fixtures ──────────────────────────────────────────────

@pytest.fixture
def valid_config_yaml():
    return """
target:
  domain: target.com
  base_url: https://target.com
  scope:
    - "*.target.com"
  exclude:
    - logout.target.com

llm:
  provider: ollama
  model: qwen2.5-coder:3b
  temperature: 0.7

output:
  dir: ./findings/test
  formats: [markdown, json]
  org: "Test Corp"
  report_type: internal

stealth:
  use_tor: false
  delay: 1.5

modules:
  recon:
    enabled: true
    mode: passive
  scan:
    enabled: true
    profile: standard
    severity: [high, critical]
  graphql:
    enabled: true
    introspect: true
    dos_test: false
  jwt:
    enabled: false
  idor:
    enabled: false
  inject:
    xss: true
    sqli: true
    ssrf: false
    endpoints:
      - /search
      - /api/query
  brute_force:
    enabled: false
  auth:
    oauth: false
    session: false
"""


@pytest.fixture
def config_file(tmp_path, valid_config_yaml):
    """Write valid config to temp file."""
    p = tmp_path / "engagement.yaml"
    p.write_text(valid_config_yaml)
    return p


@pytest.fixture
def loader():
    from modules.config.config_loader import ConfigLoader
    return ConfigLoader


# ── Tests: File Loading ───────────────────────────────────

class TestFileLoading:

    @pytest.mark.unit
    def test_load_valid_config(self, config_file, loader):
        """Config valid harus berhasil di-load."""
        cfg = loader.load(config_file)
        assert cfg.target.domain == "target.com"
        assert cfg.target.base_url == "https://target.com"

    @pytest.mark.unit
    def test_file_not_found_raises(self, loader):
        """File yang tidak ada harus raise FileNotFoundError."""
        with pytest.raises(FileNotFoundError):
            loader.load("/nonexistent/path/engagement.yaml")

    @pytest.mark.unit
    def test_non_yaml_extension_raises(self, tmp_path, loader):
        """File .txt bukan .yaml harus raise ConfigValidationError."""
        from modules.config.config_loader import ConfigValidationError
        p = tmp_path / "config.txt"
        p.write_text("target:\n  domain: test.com")
        with pytest.raises(ConfigValidationError, match=".yaml or .yml"):
            loader.load(p)

    @pytest.mark.unit
    def test_yml_extension_accepted(self, tmp_path, loader, valid_config_yaml):
        """.yml extension harus diterima."""
        p = tmp_path / "engagement.yml"
        p.write_text(valid_config_yaml)
        cfg = loader.load(p)
        assert cfg.target.domain == "target.com"

    @pytest.mark.unit
    def test_source_file_recorded(self, config_file, loader):
        """source_file harus menyimpan path absolut config."""
        cfg = loader.load(config_file)
        assert str(config_file.resolve()) == cfg.source_file

    @pytest.mark.unit
    def test_output_dir_created(self, config_file, loader):
        """Output directory harus dibuat otomatis saat load."""
        cfg = loader.load(config_file)
        assert Path(cfg.output.dir).exists()


# ── Tests: Validation ─────────────────────────────────────

class TestValidation:

    @pytest.mark.unit
    def test_missing_target_raises(self, tmp_path, loader):
        """Config tanpa 'target' harus raise ConfigValidationError."""
        from modules.config.config_loader import ConfigValidationError
        p = tmp_path / "bad.yaml"
        p.write_text("llm:\n  provider: ollama\n")
        with pytest.raises(ConfigValidationError, match="target"):
            loader.load(p)

    @pytest.mark.unit
    def test_missing_domain_raises(self, tmp_path, loader):
        """Config tanpa target.domain harus raise error."""
        from modules.config.config_loader import ConfigValidationError
        p = tmp_path / "bad.yaml"
        p.write_text("target:\n  base_url: https://test.com\n")
        with pytest.raises(ConfigValidationError, match="domain"):
            loader.load(p)

    @pytest.mark.unit
    def test_missing_base_url_raises(self, tmp_path, loader):
        """Config tanpa target.base_url harus raise error."""
        from modules.config.config_loader import ConfigValidationError
        p = tmp_path / "bad.yaml"
        p.write_text("target:\n  domain: test.com\n")
        with pytest.raises(ConfigValidationError, match="base_url"):
            loader.load(p)

    @pytest.mark.unit
    def test_invalid_base_url_raises(self, tmp_path, loader):
        """base_url tanpa http/https harus raise error."""
        from modules.config.config_loader import ConfigValidationError
        p = tmp_path / "bad.yaml"
        p.write_text("target:\n  domain: test.com\n  base_url: test.com\n")
        with pytest.raises(ConfigValidationError, match="http"):
            loader.load(p)

    @pytest.mark.unit
    def test_invalid_llm_provider_raises(self, tmp_path, loader, valid_config_yaml):
        """LLM provider yang tidak valid harus raise error."""
        from modules.config.config_loader import ConfigValidationError
        bad = valid_config_yaml.replace("provider: ollama", "provider: gpt5")
        p = tmp_path / "bad.yaml"
        p.write_text(bad)
        with pytest.raises(ConfigValidationError, match="provider"):
            loader.load(p)

    @pytest.mark.unit
    def test_invalid_scan_profile_raises(self, tmp_path, loader, valid_config_yaml):
        """Scan profile yang tidak valid harus raise error."""
        from modules.config.config_loader import ConfigValidationError
        bad = valid_config_yaml.replace("profile: standard", "profile: ultra")
        p = tmp_path / "bad.yaml"
        p.write_text(bad)
        with pytest.raises(ConfigValidationError, match="profile"):
            loader.load(p)

    @pytest.mark.unit
    def test_invalid_severity_raises(self, tmp_path, loader, valid_config_yaml):
        """Severity yang tidak valid harus raise error."""
        from modules.config.config_loader import ConfigValidationError
        bad = valid_config_yaml.replace("severity: [high, critical]", "severity: [extreme, fatal]")
        p = tmp_path / "bad.yaml"
        p.write_text(bad)
        with pytest.raises(ConfigValidationError, match="severit"):
            loader.load(p)

    @pytest.mark.unit
    def test_invalid_recon_mode_raises(self, tmp_path, loader, valid_config_yaml):
        """Recon mode yang tidak valid harus raise error."""
        from modules.config.config_loader import ConfigValidationError
        bad = valid_config_yaml.replace("mode: passive", "mode: stealth")
        p = tmp_path / "bad.yaml"
        p.write_text(bad)
        with pytest.raises(ConfigValidationError, match="mode"):
            loader.load(p)


# ── Tests: Config Values ──────────────────────────────────

class TestConfigValues:

    @pytest.mark.unit
    def test_target_values(self, config_file, loader):
        """Target config harus ter-parse dengan benar."""
        cfg = loader.load(config_file)
        assert cfg.target.domain == "target.com"
        assert cfg.target.base_url == "https://target.com"
        assert "*.target.com" in cfg.target.scope
        assert "logout.target.com" in cfg.target.exclude

    @pytest.mark.unit
    def test_llm_defaults(self, config_file, loader):
        """LLM config harus ter-parse dengan benar."""
        cfg = loader.load(config_file)
        assert cfg.llm.provider == "ollama"
        assert cfg.llm.model == "qwen2.5-coder:3b"
        assert cfg.llm.temperature == 0.7

    @pytest.mark.unit
    def test_output_values(self, config_file, loader):
        """Output config harus ter-parse dengan benar."""
        cfg = loader.load(config_file)
        assert "markdown" in cfg.output.formats
        assert "json" in cfg.output.formats
        assert cfg.output.org == "Test Corp"
        assert cfg.output.report_type == "internal"

    @pytest.mark.unit
    def test_stealth_values(self, config_file, loader):
        """Stealth config harus ter-parse dengan benar."""
        cfg = loader.load(config_file)
        assert cfg.stealth.use_tor is False
        assert cfg.stealth.delay == 1.5

    @pytest.mark.unit
    def test_modules_recon(self, config_file, loader):
        """Recon module config harus ter-parse dengan benar."""
        cfg = loader.load(config_file)
        assert cfg.modules.recon.enabled is True
        assert cfg.modules.recon.mode == "passive"

    @pytest.mark.unit
    def test_modules_graphql(self, config_file, loader):
        """GraphQL module config harus ter-parse dengan benar."""
        cfg = loader.load(config_file)
        assert cfg.modules.graphql.enabled is True
        assert cfg.modules.graphql.introspect is True
        assert cfg.modules.graphql.dos_test is False

    @pytest.mark.unit
    def test_modules_inject(self, config_file, loader):
        """Inject module config harus ter-parse dengan benar."""
        cfg = loader.load(config_file)
        assert cfg.modules.inject.xss is True
        assert cfg.modules.inject.sqli is True
        assert cfg.modules.inject.ssrf is False
        assert "/search" in cfg.modules.inject.endpoints

    @pytest.mark.unit
    def test_base_url_trailing_slash_stripped(self, tmp_path, loader):
        """Trailing slash di base_url harus di-strip."""
        p = tmp_path / "e.yaml"
        p.write_text("target:\n  domain: test.com\n  base_url: https://test.com/\n")
        cfg = loader.load(p)
        assert not cfg.target.base_url.endswith("/")


# ── Tests: enabled_modules() ──────────────────────────────

class TestEnabledModules:

    @pytest.mark.unit
    def test_enabled_modules_list(self, config_file, loader):
        """enabled_modules() harus return list modul aktif."""
        cfg = loader.load(config_file)
        enabled = cfg.enabled_modules()
        assert "recon" in enabled
        assert "scan" in enabled
        assert "graphql" in enabled
        assert "inject" in enabled
        # disabled modules tidak boleh ada
        assert "jwt" not in enabled
        assert "idor" not in enabled
        assert "brute_force" not in enabled

    @pytest.mark.unit
    def test_no_modules_enabled(self, tmp_path, loader):
        """Jika semua module off, enabled_modules() harus return list kosong."""
        p = tmp_path / "e.yaml"
        p.write_text("""
target:
  domain: test.com
  base_url: https://test.com
modules:
  recon:
    enabled: false
  scan:
    enabled: false
  graphql:
    enabled: false
  inject:
    xss: false
    sqli: false
    ssrf: false
  jwt:
    enabled: false
  idor:
    enabled: false
  brute_force:
    enabled: false
  auth:
    oauth: false
    session: false
""")
        cfg = loader.load(p)
        assert cfg.enabled_modules() == []


# ── Tests: Environment Variable Interpolation ─────────────

class TestEnvVarInterpolation:

    @pytest.mark.unit
    def test_env_var_interpolated(self, tmp_path, loader, monkeypatch):
        """${VAR} harus diganti dengan nilai environment variable."""
        monkeypatch.setenv("TEST_API_KEY", "sk-test-12345")
        p = tmp_path / "e.yaml"
        p.write_text("""
target:
  domain: test.com
  base_url: https://test.com
llm:
  provider: anthropic
  model: claude-sonnet-4-20250514
  api_key: ${TEST_API_KEY}
""")
        cfg = loader.load(p)
        assert cfg.llm.api_key == "sk-test-12345"

    @pytest.mark.unit
    def test_missing_env_var_becomes_null(self, tmp_path, loader):
        """${MISSING_VAR} yang tidak ada di env harus jadi null."""
        p = tmp_path / "e.yaml"
        p.write_text("""
target:
  domain: test.com
  base_url: https://test.com
llm:
  provider: ollama
  api_key: ${NONEXISTENT_VAR_12345}
""")
        cfg = loader.load(p)
        assert cfg.llm.api_key is None


# ── Tests: create_template() ──────────────────────────────

class TestCreateTemplate:

    @pytest.mark.unit
    def test_create_template_file(self, tmp_path, loader):
        """create_template() harus membuat file YAML yang valid."""
        out = tmp_path / "new_engagement.yaml"
        result = loader.create_template(out, domain="example.com")
        assert result.exists()
        assert result.suffix == ".yaml"

    @pytest.mark.unit
    def test_template_contains_domain(self, tmp_path, loader):
        """Template yang dibuat harus berisi domain yang diberikan."""
        out = tmp_path / "new_engagement.yaml"
        loader.create_template(out, domain="myapp.io")
        content = out.read_text()
        assert "myapp.io" in content

    @pytest.mark.unit
    def test_template_is_loadable(self, tmp_path, loader):
        """Template yang dibuat harus bisa di-load kembali."""
        out = tmp_path / "new_engagement.yaml"
        loader.create_template(out, domain="testsite.com")
        cfg = loader.load(out)
        assert cfg.target.domain == "testsite.com"
