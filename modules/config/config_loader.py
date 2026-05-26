"""
Config Loader — modules/config/config_loader.py

Load, validate, and normalize YAML engagement config files.
Supports environment variable interpolation: ${VAR_NAME}

Usage:
    from modules.config.config_loader import ConfigLoader

    cfg = ConfigLoader.load("engagement.yaml")
    print(cfg.target.domain)
    print(cfg.modules.graphql.enabled)

Author: ardanov96
"""

import os
import re
import yaml
from pathlib import Path
from dataclasses import dataclass, field
from typing import Any


# ── Data Classes (typed config) ───────────────────────────

@dataclass
class TargetConfig:
    domain: str
    base_url: str
    scope: list[str] = field(default_factory=list)
    exclude: list[str] = field(default_factory=list)


@dataclass
class LLMConfig:
    provider: str = "ollama"
    model: str = "qwen2.5-coder:3b"
    temperature: float = 0.7
    api_key: str | None = None


@dataclass
class OutputConfig:
    dir: str = "./findings"
    formats: list[str] = field(default_factory=lambda: ["markdown", "json"])
    org: str = "Unknown"
    report_type: str = "internal"


@dataclass
class StealthConfig:
    use_tor: bool = False
    delay: float = 1.0
    user_agent: str = "Mozilla/5.0 (compatible; Glitchicons/0.7)"
    proxy: str | None = None


@dataclass
class ReconModuleConfig:
    enabled: bool = True
    mode: str = "passive"
    depth: int = 2


@dataclass
class ScanModuleConfig:
    enabled: bool = True
    profile: str = "standard"
    severity: list[str] = field(default_factory=lambda: ["high", "critical"])


@dataclass
class GraphQLModuleConfig:
    enabled: bool = False
    endpoint: str | None = None
    introspect: bool = True
    dos_test: bool = False


@dataclass
class JWTModuleConfig:
    enabled: bool = False
    token: str | None = None


@dataclass
class IDORModuleConfig:
    enabled: bool = False
    endpoint: str = "/api/user/{id}"
    method: str = "GET"


@dataclass
class InjectModuleConfig:
    xss: bool = True
    sqli: bool = True
    ssrf: bool = True
    ssti: bool = False
    xxe: bool = False
    endpoints: list[str] = field(default_factory=lambda: ["/"])


@dataclass
class BruteForceModuleConfig:
    enabled: bool = False
    emails: str = "wordlists/emails.txt"
    passwords: str = "wordlists/passwords.txt"
    delay: float = 2.0
    max_attempts: int = 500


@dataclass
class AuthModuleConfig:
    oauth: bool = False
    session: bool = False


@dataclass
class SeedsConfig:
    enabled: bool = False
    types: list[str] = field(default_factory=lambda: ["json", "http"])
    count: int = 20
    target_binary: str | None = None


@dataclass
class ModulesConfig:
    recon: ReconModuleConfig = field(default_factory=ReconModuleConfig)
    scan: ScanModuleConfig = field(default_factory=ScanModuleConfig)
    graphql: GraphQLModuleConfig = field(default_factory=GraphQLModuleConfig)
    jwt: JWTModuleConfig = field(default_factory=JWTModuleConfig)
    idor: IDORModuleConfig = field(default_factory=IDORModuleConfig)
    inject: InjectModuleConfig = field(default_factory=InjectModuleConfig)
    brute_force: BruteForceModuleConfig = field(default_factory=BruteForceModuleConfig)
    auth: AuthModuleConfig = field(default_factory=AuthModuleConfig)


@dataclass
class EngagementConfig:
    """Full engagement config — validated and typed."""
    target: TargetConfig
    llm: LLMConfig = field(default_factory=LLMConfig)
    output: OutputConfig = field(default_factory=OutputConfig)
    stealth: StealthConfig = field(default_factory=StealthConfig)
    modules: ModulesConfig = field(default_factory=ModulesConfig)
    seeds: SeedsConfig = field(default_factory=SeedsConfig)
    source_file: str = ""

    def enabled_modules(self) -> list[str]:
        """Return list of enabled module names."""
        enabled = []
        if self.modules.recon.enabled:
            enabled.append("recon")
        if self.modules.scan.enabled:
            enabled.append("scan")
        if self.modules.graphql.enabled:
            enabled.append("graphql")
        if self.modules.jwt.enabled:
            enabled.append("jwt")
        if self.modules.idor.enabled:
            enabled.append("idor")
        if self.modules.brute_force.enabled:
            enabled.append("brute_force")
        if self.modules.auth.oauth or self.modules.auth.session:
            enabled.append("auth")
        if self.seeds.enabled:
            enabled.append("seeds")

        # Inject is always conditionally included
        inject = self.modules.inject
        if any([inject.xss, inject.sqli, inject.ssrf, inject.ssti, inject.xxe]):
            enabled.append("inject")

        return enabled

    def to_dict(self) -> dict:
        """Serialize config back to dict for logging."""
        return {
            "target": {
                "domain": self.target.domain,
                "base_url": self.target.base_url,
                "scope": self.target.scope,
            },
            "llm": {
                "provider": self.llm.provider,
                "model": self.llm.model,
            },
            "output": {
                "dir": self.output.dir,
                "formats": self.output.formats,
                "org": self.output.org,
            },
            "enabled_modules": self.enabled_modules(),
            "stealth": {
                "use_tor": self.stealth.use_tor,
                "delay": self.stealth.delay,
            },
        }


# ── Validation Errors ─────────────────────────────────────

class ConfigValidationError(Exception):
    """Raised when config file has validation errors."""
    pass


# ── Config Loader ─────────────────────────────────────────

class ConfigLoader:
    """Load and validate YAML engagement config files."""

    VALID_PROVIDERS = {"ollama", "anthropic", "openai"}
    VALID_MODES = {"passive", "active"}
    VALID_PROFILES = {"quick", "standard", "deep", "cves", "auth"}
    VALID_REPORT_TYPES = {"internal", "external", "bounty"}
    VALID_SEVERITIES = {"low", "medium", "high", "critical", "info"}
    VALID_FORMATS = {"markdown", "json", "html"}

    @classmethod
    def load(cls, path: str | Path) -> EngagementConfig:
        """
        Load config from YAML file, interpolate env vars, validate, return typed config.

        Args:
            path: Path to YAML config file.

        Returns:
            EngagementConfig: Validated, typed config object.

        Raises:
            FileNotFoundError: Config file doesn't exist.
            ConfigValidationError: Config has validation errors.
        """
        config_path = Path(path)

        if not config_path.exists():
            raise FileNotFoundError(f"Config file not found: {config_path}")

        if config_path.suffix not in (".yaml", ".yml"):
            raise ConfigValidationError(
                f"Config file must be .yaml or .yml, got: {config_path.suffix}"
            )

        raw = config_path.read_text(encoding="utf-8")
        raw = cls._interpolate_env_vars(raw)

        try:
            data = yaml.safe_load(raw)
        except yaml.YAMLError as e:
            raise ConfigValidationError(f"Invalid YAML syntax: {e}")

        if not isinstance(data, dict):
            raise ConfigValidationError("Config must be a YAML mapping (dict), not a list or scalar.")

        errors = cls._validate(data)
        if errors:
            error_list = "\n".join(f"  - {e}" for e in errors)
            raise ConfigValidationError(f"Config validation failed:\n{error_list}")

        config = cls._build(data)
        config.source_file = str(config_path.resolve())

        # Create output dir
        Path(config.output.dir).mkdir(parents=True, exist_ok=True)

        return config

    @classmethod
    def _interpolate_env_vars(cls, raw: str) -> str:
        """Replace ${VAR_NAME} with environment variable values."""
        pattern = re.compile(r"\$\{([^}]+)\}")

        def replace(match):
            var_name = match.group(1)
            value = os.environ.get(var_name)
            if value is None:
                return "null"
            return value

        return pattern.sub(replace, raw)

    @classmethod
    def _validate(cls, data: dict) -> list[str]:
        """Validate config structure. Return list of error messages."""
        errors = []

        # Required: target
        if "target" not in data:
            errors.append("Missing required section: 'target'")
        else:
            t = data["target"]
            if not isinstance(t, dict):
                errors.append("'target' must be a mapping")
            else:
                if not t.get("domain"):
                    errors.append("'target.domain' is required")
                if not t.get("base_url"):
                    errors.append("'target.base_url' is required")
                elif not t["base_url"].startswith(("http://", "https://")):
                    errors.append("'target.base_url' must start with http:// or https://")

        # LLM provider
        if "llm" in data and isinstance(data["llm"], dict):
            provider = data["llm"].get("provider", "ollama")
            if provider not in cls.VALID_PROVIDERS:
                errors.append(
                    f"'llm.provider' must be one of {cls.VALID_PROVIDERS}, got: '{provider}'"
                )
            temp = data["llm"].get("temperature", 0.7)
            if not isinstance(temp, (int, float)) or not (0.0 <= temp <= 2.0):
                errors.append("'llm.temperature' must be a float between 0.0 and 2.0")

        # Output
        if "output" in data and isinstance(data["output"], dict):
            report_type = data["output"].get("report_type", "internal")
            if report_type not in cls.VALID_REPORT_TYPES:
                errors.append(
                    f"'output.report_type' must be one of {cls.VALID_REPORT_TYPES}, got: '{report_type}'"
                )
            formats = data["output"].get("formats", [])
            if isinstance(formats, list):
                invalid_fmt = [f for f in formats if f not in cls.VALID_FORMATS]
                if invalid_fmt:
                    errors.append(f"Invalid output formats: {invalid_fmt}. Valid: {cls.VALID_FORMATS}")

        # Modules
        if "modules" in data and isinstance(data["modules"], dict):
            mods = data["modules"]

            # Recon mode
            if "recon" in mods and isinstance(mods["recon"], dict):
                mode = mods["recon"].get("mode", "passive")
                if mode not in cls.VALID_MODES:
                    errors.append(
                        f"'modules.recon.mode' must be one of {cls.VALID_MODES}, got: '{mode}'"
                    )

            # Scan profile
            if "scan" in mods and isinstance(mods["scan"], dict):
                profile = mods["scan"].get("profile", "standard")
                if profile not in cls.VALID_PROFILES:
                    errors.append(
                        f"'modules.scan.profile' must be one of {cls.VALID_PROFILES}, got: '{profile}'"
                    )
                severities = mods["scan"].get("severity", [])
                if isinstance(severities, list):
                    invalid_sev = [s for s in severities if s not in cls.VALID_SEVERITIES]
                    if invalid_sev:
                        errors.append(f"Invalid severities: {invalid_sev}. Valid: {cls.VALID_SEVERITIES}")

            # Stealth delay
            if "stealth" in data and isinstance(data.get("stealth"), dict):
                delay = data["stealth"].get("delay", 1.0)
                if not isinstance(delay, (int, float)) or delay < 0:
                    errors.append("'stealth.delay' must be a non-negative number")

        return errors

    @classmethod
    def _build(cls, data: dict) -> EngagementConfig:
        """Build typed EngagementConfig from validated dict."""

        def g(d: dict, key: str, default: Any = None) -> Any:
            """Safe dict get with default."""
            return d.get(key, default) if isinstance(d, dict) else default

        t = data.get("target", {})
        target = TargetConfig(
            domain=t.get("domain", ""),
            base_url=t.get("base_url", "").rstrip("/"),
            scope=t.get("scope") or [],
            exclude=t.get("exclude") or [],
        )

        l = data.get("llm", {})
        llm = LLMConfig(
            provider=g(l, "provider", "ollama"),
            model=g(l, "model", "qwen2.5-coder:3b"),
            temperature=g(l, "temperature", 0.7),
            api_key=g(l, "api_key"),
        )

        o = data.get("output", {})
        output = OutputConfig(
            dir=g(o, "dir", "./findings"),
            formats=g(o, "formats", ["markdown", "json"]),
            org=g(o, "org", "Unknown"),
            report_type=g(o, "report_type", "internal"),
        )

        s = data.get("stealth", {})
        stealth = StealthConfig(
            use_tor=g(s, "use_tor", False),
            delay=g(s, "delay", 1.0),
            user_agent=g(s, "user_agent", "Mozilla/5.0 (compatible; Glitchicons/0.7)"),
            proxy=g(s, "proxy"),
        )

        m = data.get("modules", {})

        r = g(m, "recon", {})
        recon = ReconModuleConfig(
            enabled=g(r, "enabled", True),
            mode=g(r, "mode", "passive"),
            depth=g(r, "depth", 2),
        )

        sc = g(m, "scan", {})
        scan = ScanModuleConfig(
            enabled=g(sc, "enabled", True),
            profile=g(sc, "profile", "standard"),
            severity=g(sc, "severity", ["high", "critical"]),
        )

        gql = g(m, "graphql", {})
        graphql = GraphQLModuleConfig(
            enabled=g(gql, "enabled", False),
            endpoint=g(gql, "endpoint"),
            introspect=g(gql, "introspect", True),
            dos_test=g(gql, "dos_test", False),
        )

        jw = g(m, "jwt", {})
        jwt = JWTModuleConfig(
            enabled=g(jw, "enabled", False),
            token=g(jw, "token"),
        )

        id_ = g(m, "idor", {})
        idor = IDORModuleConfig(
            enabled=g(id_, "enabled", False),
            endpoint=g(id_, "endpoint", "/api/user/{id}"),
            method=g(id_, "method", "GET"),
        )

        inj = g(m, "inject", {})
        inject = InjectModuleConfig(
            xss=g(inj, "xss", True),
            sqli=g(inj, "sqli", True),
            ssrf=g(inj, "ssrf", True),
            ssti=g(inj, "ssti", False),
            xxe=g(inj, "xxe", False),
            endpoints=g(inj, "endpoints", ["/"]),
        )

        bf = g(m, "brute_force", {})
        brute_force = BruteForceModuleConfig(
            enabled=g(bf, "enabled", False),
            emails=g(bf, "emails", "wordlists/emails.txt"),
            passwords=g(bf, "passwords", "wordlists/passwords.txt"),
            delay=g(bf, "delay", 2.0),
            max_attempts=g(bf, "max_attempts", 500),
        )

        au = g(m, "auth", {})
        auth = AuthModuleConfig(
            oauth=g(au, "oauth", False),
            session=g(au, "session", False),
        )

        modules = ModulesConfig(
            recon=recon, scan=scan, graphql=graphql,
            jwt=jwt, idor=idor, inject=inject,
            brute_force=brute_force, auth=auth,
        )

        sd = data.get("seeds", {})
        seeds = SeedsConfig(
            enabled=g(sd, "enabled", False),
            types=g(sd, "types", ["json", "http"]),
            count=g(sd, "count", 20),
            target_binary=g(sd, "target_binary"),
        )

        return EngagementConfig(
            target=target, llm=llm, output=output,
            stealth=stealth, modules=modules, seeds=seeds,
        )

    @classmethod
    def create_template(cls, path: str | Path, domain: str = "target.com") -> Path:
        """
        Create a new engagement config file from template.

        Args:
            path: Where to save the new config file.
            domain: Target domain to pre-fill.

        Returns:
            Path to created file.
        """
        template_path = Path(__file__).parent.parent.parent / "engagement_template.yaml"

        if template_path.exists():
            content = template_path.read_text(encoding="utf-8")
            content = content.replace("target.com", domain)
            content = content.replace("https://target.com", f"https://{domain}")
            content = content.replace("./findings/target-com", f"./findings/{domain.replace('.', '-')}")
        else:
            content = cls._minimal_template(domain)

        out = Path(path)
        out.write_text(content, encoding="utf-8")
        return out

    @staticmethod
    def _minimal_template(domain: str) -> str:
        """Fallback minimal template if engagement_template.yaml not found."""
        return f"""# GLITCHICONS Engagement Config
# Generated by: glitchicons config init

target:
  domain: {domain}
  base_url: https://{domain}
  scope:
    - "*.{domain}"
  exclude: []

llm:
  provider: ollama
  model: qwen2.5-coder:3b

output:
  dir: ./findings/{domain.replace('.', '-')}
  formats: [markdown, json]
  org: "Client Name"
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
    enabled: false
  jwt:
    enabled: false
  idor:
    enabled: false
  inject:
    xss: true
    sqli: true
    ssrf: true
  brute_force:
    enabled: false
"""
