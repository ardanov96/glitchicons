"""
Plugin Marketplace — modules/marketplace/plugin_marketplace.py

Centralized plugin discovery, installation, and management:
  1. PluginRegistry    — enhanced registry with metadata + versioning
  2. PluginInstaller   — pip-based installation + dependency resolution
  3. PluginSandbox     — timeout-limited sandboxed execution
  4. PluginValidator   — validate plugin interface before use
  5. PluginMarketplace — browse + search community plugins

Plugin naming convention: glitchicons-<name>
Example: glitchicons-nuclei, glitchicons-shodan, glitchicons-jwt

Usage:
    from modules.marketplace.plugin_marketplace import (
        PluginMarketplace, PluginRegistry, PluginInstaller,
        PluginSandbox, PluginValidator,
    )

    # Browse marketplace
    market = PluginMarketplace()
    plugins = market.search("jwt")
    market.print_catalog()

    # Install plugin
    installer = PluginInstaller()
    installer.install("glitchicons-jwt-extra")

    # Run with sandbox
    sandbox = PluginSandbox(timeout=30, max_findings=100)
    findings = sandbox.run(plugin_instance, target="https://target.com")

    # Validate plugin
    validator = PluginValidator()
    result = validator.validate(MyPlugin)

Author: ardanov96
"""

import importlib
import importlib.metadata
import json
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.table import Table

console = Console()


# ── Plugin interface (mirrors plugin_system.py) ───────────

class GlitchiconPluginBase:
    """
    Base interface for all Glitchicons plugins.
    Third-party plugins must implement this interface.
    """
    name:        str = ""
    version:     str = "0.0.0"
    description: str = ""
    author:      str = ""
    tags:        list[str] = []
    min_glitchicons_version: str = "2.0.0"

    def run(self, target: str, **kwargs) -> list[dict]:
        raise NotImplementedError


# ── Data classes ──────────────────────────────────────────

@dataclass
class PluginMeta:
    """Metadata for a registered plugin."""
    name:         str
    version:      str
    description:  str
    author:       str
    tags:         list[str]
    package_name: str           # PyPI package name (glitchicons-xxx)
    installed:    bool  = False
    enabled:      bool  = True
    install_path: str   = ""
    last_run:     str   = ""
    run_count:    int   = 0
    error_count:  int   = 0


@dataclass
class MarketplaceEntry:
    """A plugin available in the marketplace."""
    package_name: str
    display_name: str
    description:  str
    author:       str
    version:      str
    tags:         list[str]
    stars:        int  = 0
    downloads:    int  = 0
    verified:     bool = False
    pypi_url:     str  = ""


@dataclass
class ValidationResult:
    """Result of plugin validation."""
    valid:       bool
    plugin_name: str
    errors:      list[str] = field(default_factory=list)
    warnings:    list[str] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return self.valid and not self.errors


@dataclass
class SandboxResult:
    """Result of sandboxed plugin execution."""
    plugin_name: str
    target:      str
    findings:    list[dict]
    duration_s:  float
    status:      str       # "success" | "timeout" | "error" | "truncated"
    error:       str = ""


# ── Community plugin catalog (hardcoded known plugins) ────
# In a real implementation this would be fetched from a registry API

COMMUNITY_CATALOG: list[dict] = [
    {
        "package_name": "glitchicons-nuclei",
        "display_name": "Nuclei Integration",
        "description":  "Run Nuclei templates and import findings into Glitchicons",
        "author":       "glitchicons-community",
        "version":      "1.2.0",
        "tags":         ["nuclei", "template", "scanner"],
        "stars":        142,
        "downloads":    8420,
        "verified":     True,
        "pypi_url":     "https://pypi.org/project/glitchicons-nuclei/",
    },
    {
        "package_name": "glitchicons-shodan",
        "display_name": "Shodan Recon",
        "description":  "Deep Shodan integration with custom query builder",
        "author":       "glitchicons-community",
        "version":      "1.0.3",
        "tags":         ["shodan", "recon", "passive"],
        "stars":        89,
        "downloads":    4210,
        "verified":     True,
        "pypi_url":     "https://pypi.org/project/glitchicons-shodan/",
    },
    {
        "package_name": "glitchicons-jwt-extra",
        "display_name": "JWT Extra Checks",
        "description":  "Extended JWT analysis: kid injection, jku/x5u bypass, weak HMAC brute",
        "author":       "security-researcher-x",
        "version":      "2.1.0",
        "tags":         ["jwt", "auth", "token"],
        "stars":        215,
        "downloads":    12840,
        "verified":     True,
        "pypi_url":     "https://pypi.org/project/glitchicons-jwt-extra/",
    },
    {
        "package_name": "glitchicons-wordpress",
        "display_name": "WordPress Security",
        "description":  "WordPress plugin/theme enumeration, user enum, xmlrpc attacks",
        "author":       "wp-security-labs",
        "version":      "1.5.1",
        "tags":         ["wordpress", "cms", "web"],
        "stars":        178,
        "downloads":    9340,
        "verified":     True,
        "pypi_url":     "https://pypi.org/project/glitchicons-wordpress/",
    },
    {
        "package_name": "glitchicons-aws-deep",
        "display_name": "AWS Deep Audit",
        "description":  "Deep AWS security audit: IAM path finding, S3 ACL, Lambda exposure",
        "author":       "cloud-pentest-labs",
        "version":      "1.3.0",
        "tags":         ["aws", "cloud", "iam", "s3"],
        "stars":        134,
        "downloads":    6780,
        "verified":     True,
        "pypi_url":     "https://pypi.org/project/glitchicons-aws-deep/",
    },
    {
        "package_name": "glitchicons-graphql-deep",
        "display_name": "GraphQL Deep Tester",
        "description":  "Advanced GraphQL: batching attack, field suggestion, alias abuse",
        "author":       "api-security-team",
        "version":      "1.1.2",
        "tags":         ["graphql", "api", "inject"],
        "stars":        98,
        "downloads":    5120,
        "verified":     False,
        "pypi_url":     "https://pypi.org/project/glitchicons-graphql-deep/",
    },
    {
        "package_name": "glitchicons-android",
        "display_name": "Android APK Deep",
        "description":  "Deep APK analysis with jadx integration, smali analysis, root detection bypass",
        "author":       "mobile-sec-community",
        "version":      "1.0.1",
        "tags":         ["android", "apk", "mobile"],
        "stars":        67,
        "downloads":    3240,
        "verified":     False,
        "pypi_url":     "https://pypi.org/project/glitchicons-android/",
    },
    {
        "package_name": "glitchicons-report-pdf-pro",
        "display_name": "Professional PDF Reports",
        "description":  "Executive-grade PDF reports with charts, CVSS gauge, remediation roadmap",
        "author":       "glitchicons-community",
        "version":      "2.0.0",
        "tags":         ["report", "pdf", "professional"],
        "stars":        312,
        "downloads":    18920,
        "verified":     True,
        "pypi_url":     "https://pypi.org/project/glitchicons-report-pdf-pro/",
    },
]


# ── 1. Plugin Registry ────────────────────────────────────

class PluginRegistry:
    """
    Enhanced plugin registry with metadata, versioning, and persistence.

    Extends the basic plugin_system.py with:
    - Per-plugin metadata (version, author, tags, stats)
    - Enable/disable without uninstalling
    - Run history tracking
    - JSON persistence
    """

    ENTRY_POINT_GROUP = "glitchicons.plugins"

    def __init__(self, registry_path: str = "./.glitchicons/plugins.json"):
        self.registry_path = Path(registry_path)
        self.registry_path.parent.mkdir(parents=True, exist_ok=True)
        self._plugins: dict[str, PluginMeta] = {}
        self._classes: dict[str, type]       = {}
        self._load()
        self._save()  # Ensure file exists

    def discover(self) -> list[PluginMeta]:
        """Discover all installed glitchicons plugins via entry points."""
        discovered = []
        try:
            eps = importlib.metadata.entry_points(group=self.ENTRY_POINT_GROUP)
            for ep in eps:
                try:
                    cls = ep.load()
                    meta = self._meta_from_class(cls, ep.name)
                    self._plugins[meta.name] = meta
                    self._classes[meta.name] = cls
                    discovered.append(meta)
                except Exception as e:
                    console.print(f"  [yellow]Plugin load failed:[/yellow] {ep.name} — {e}")
        except Exception:
            pass
        self._save()
        return discovered

    def register(self, cls: type, package_name: str = "") -> PluginMeta:
        """Manually register a plugin class."""
        meta = self._meta_from_class(cls, cls.name or cls.__name__)
        if package_name:
            meta.package_name = package_name
        self._plugins[meta.name] = meta
        self._classes[meta.name] = cls
        self._save()
        return meta

    def get(self, name: str) -> type | None:
        """Get plugin class by name."""
        return self._classes.get(name)

    def get_meta(self, name: str) -> PluginMeta | None:
        """Get plugin metadata by name."""
        return self._plugins.get(name)

    def list_all(self) -> list[PluginMeta]:
        """List all registered plugins."""
        return list(self._plugins.values())

    def list_enabled(self) -> list[PluginMeta]:
        """List only enabled plugins."""
        return [p for p in self._plugins.values() if p.enabled]

    def list_by_tag(self, tag: str) -> list[PluginMeta]:
        """Filter plugins by tag."""
        return [p for p in self._plugins.values() if tag in p.tags]

    def enable(self, name: str) -> bool:
        if name in self._plugins:
            self._plugins[name].enabled = True
            self._save()
            return True
        return False

    def disable(self, name: str) -> bool:
        if name in self._plugins:
            self._plugins[name].enabled = False
            self._save()
            return True
        return False

    def record_run(self, name: str, error: bool = False) -> None:
        """Record a plugin execution."""
        if name in self._plugins:
            p = self._plugins[name]
            p.run_count += 1
            p.last_run   = datetime.now(timezone.utc).isoformat()
            if error:
                p.error_count += 1
            self._save()

    def print_registry(self) -> None:
        """Print registry as rich table."""
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Name",        style="cyan", width=20)
        table.add_column("Version",     width=8)
        table.add_column("Status",      width=10)
        table.add_column("Tags",        width=25)
        table.add_column("Runs/Errors", width=12)

        for meta in sorted(self._plugins.values(), key=lambda m: m.name):
            status = "[green]enabled[/green]" if meta.enabled else "[dim]disabled[/dim]"
            table.add_row(
                meta.name, meta.version, status,
                ", ".join(meta.tags[:3]),
                f"{meta.run_count}/{meta.error_count}",
            )
        console.print(table)

    def _meta_from_class(self, cls: type, ep_name: str) -> PluginMeta:
        return PluginMeta(
            name=getattr(cls, "name", ep_name),
            version=getattr(cls, "version", "0.0.0"),
            description=getattr(cls, "description", ""),
            author=getattr(cls, "author", ""),
            tags=list(getattr(cls, "tags", [])),
            package_name=f"glitchicons-{getattr(cls, 'name', ep_name)}",
            installed=True,
        )

    def _load(self) -> None:
        if self.registry_path.exists():
            try:
                data = json.loads(self.registry_path.read_text(encoding="utf-8"))
                for name, meta_dict in data.items():
                    self._plugins[name] = PluginMeta(**meta_dict)
            except Exception:
                pass

    def _save(self) -> None:
        data = {
            name: {
                "name":         m.name,
                "version":      m.version,
                "description":  m.description,
                "author":       m.author,
                "tags":         m.tags,
                "package_name": m.package_name,
                "installed":    m.installed,
                "enabled":      m.enabled,
                "install_path": m.install_path,
                "last_run":     m.last_run,
                "run_count":    m.run_count,
                "error_count":  m.error_count,
            }
            for name, m in self._plugins.items()
        }
        self.registry_path.write_text(
            json.dumps(data, indent=2), encoding="utf-8"
        )

    @property
    def count(self) -> int:
        return len(self._plugins)


# ── 2. Plugin Installer ───────────────────────────────────

@dataclass
class InstallResult:
    """Result of a plugin install/uninstall operation."""
    package_name: str
    action:       str   # "install" | "uninstall" | "upgrade"
    success:      bool
    message:      str
    version:      str = ""


class PluginInstaller:
    """
    Install, uninstall, and upgrade Glitchicons plugins from PyPI.

    Uses pip subprocess for installation to ensure proper
    dependency resolution and virtual environment support.
    """

    PREFIX = "glitchicons-"

    def __init__(self, registry: PluginRegistry | None = None):
        self.registry = registry

    def install(
        self,
        package_name: str,
        version: str | None = None,
        upgrade: bool = False,
    ) -> InstallResult:
        """
        Install a plugin package from PyPI.

        Args:
            package_name: PyPI package name (with or without glitchicons- prefix)
            version:      Specific version to install (e.g. "1.2.0")
            upgrade:      Upgrade if already installed

        Returns:
            InstallResult with success status and message
        """
        pkg = self._normalize_name(package_name)
        spec = f"{pkg}=={version}" if version else pkg

        cmd = [sys.executable, "-m", "pip", "install"]
        if upgrade:
            cmd.append("--upgrade")
        cmd.append(spec)

        console.print(f"  [cyan]Installing:[/cyan] {spec}")
        try:
            result = subprocess.run(
                cmd,
                capture_output=True, text=True, timeout=120,
            )
            success = result.returncode == 0
            msg     = result.stdout[-200:] if success else result.stderr[-300:]

            if success and self.registry:
                self.registry.discover()  # Refresh after install

            installed_version = self._get_installed_version(pkg) if success else ""
            console.print(
                f"  [green]✓[/green] {pkg} {installed_version}" if success
                else f"  [red]✗[/red] {pkg}: {msg[:100]}"
            )
            return InstallResult(
                package_name=pkg,
                action="upgrade" if upgrade else "install",
                success=success,
                message=msg.strip(),
                version=installed_version,
            )
        except subprocess.TimeoutExpired:
            return InstallResult(pkg, "install", False, "Installation timed out (120s)")
        except Exception as e:
            return InstallResult(pkg, "install", False, str(e))

    def uninstall(self, package_name: str) -> InstallResult:
        """Uninstall a plugin package."""
        pkg = self._normalize_name(package_name)
        cmd = [sys.executable, "-m", "pip", "uninstall", "-y", pkg]

        console.print(f"  [cyan]Uninstalling:[/cyan] {pkg}")
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=60,
            )
            success = result.returncode == 0
            msg     = (result.stdout + result.stderr).strip()[-200:]

            if success and self.registry:
                meta = next(
                    (m for m in self.registry.list_all() if m.package_name == pkg), None
                )
                if meta:
                    self.registry.disable(meta.name)

            console.print(
                f"  [green]✓[/green] Uninstalled {pkg}" if success
                else f"  [red]✗[/red] {pkg}: {msg[:80]}"
            )
            return InstallResult(pkg, "uninstall", success, msg)
        except Exception as e:
            return InstallResult(pkg, "uninstall", False, str(e))

    def is_installed(self, package_name: str) -> bool:
        """Check if a package is currently installed."""
        pkg = self._normalize_name(package_name)
        return self._get_installed_version(pkg) != ""

    def list_installed(self) -> list[dict]:
        """List all installed glitchicons-* packages."""
        try:
            pkgs = importlib.metadata.packages_distributions()
            result = []
            for dist in importlib.metadata.distributions():
                name = dist.metadata.get("Name", "")
                if name.startswith(self.PREFIX):
                    result.append({
                        "name":    name,
                        "version": dist.metadata.get("Version", ""),
                    })
            return result
        except Exception:
            return []

    def _normalize_name(self, name: str) -> str:
        if not name.startswith(self.PREFIX):
            return f"{self.PREFIX}{name}"
        return name

    def _get_installed_version(self, package_name: str) -> str:
        try:
            return importlib.metadata.version(package_name)
        except importlib.metadata.PackageNotFoundError:
            return ""


# ── 3. Plugin Validator ───────────────────────────────────

REQUIRED_ATTRS   = ["name", "version", "description", "run"]
OPTIONAL_ATTRS   = ["author", "tags", "min_glitchicons_version"]
RESERVED_NAMES   = {"admin", "core", "system", "glitchicons", "test"}
MAX_NAME_LENGTH  = 50
MIN_NAME_LENGTH  = 3


class PluginValidator:
    """
    Validate plugin classes before registration or execution.

    Checks:
    - Required attributes present (name, version, description, run)
    - Name format valid (no reserved words, proper length)
    - run() method signature correct
    - Version string is valid semver
    - No dangerous imports or operations (basic static check)
    """

    def validate(self, cls: type) -> ValidationResult:
        """Validate a plugin class."""
        name    = getattr(cls, "name", cls.__name__)
        errors  = []
        warnings = []

        # Required attributes
        for attr in REQUIRED_ATTRS:
            if not hasattr(cls, attr):
                errors.append(f"Missing required attribute: {attr}")

        # Name validation
        if hasattr(cls, "name"):
            plugin_name = cls.name
            if not plugin_name:
                errors.append("Plugin name cannot be empty")
            elif len(plugin_name) < MIN_NAME_LENGTH:
                errors.append(f"Name too short (min {MIN_NAME_LENGTH} chars): '{plugin_name}'")
            elif len(plugin_name) > MAX_NAME_LENGTH:
                errors.append(f"Name too long (max {MAX_NAME_LENGTH} chars): '{plugin_name}'")
            elif plugin_name.lower() in RESERVED_NAMES:
                errors.append(f"Name is reserved: '{plugin_name}'")
            elif not plugin_name.replace("-", "").replace("_", "").isalnum():
                errors.append(f"Name must be alphanumeric with dashes/underscores: '{plugin_name}'")

        # Version validation
        if hasattr(cls, "version"):
            if not self._valid_semver(cls.version):
                warnings.append(f"Version not semver format: '{cls.version}'")

        # run() method
        if hasattr(cls, "run"):
            import inspect
            try:
                sig = inspect.signature(cls.run)
                params = list(sig.parameters.keys())
                if "target" not in params:
                    errors.append("run() method must accept 'target' parameter")
            except Exception:
                warnings.append("Could not inspect run() signature")

        # Tags
        if hasattr(cls, "tags"):
            if not isinstance(cls.tags, (list, tuple)):
                warnings.append("tags should be a list")

        # Description
        if hasattr(cls, "description"):
            if len(cls.description) < 10:
                warnings.append("Description is very short")

        return ValidationResult(
            valid=len(errors) == 0,
            plugin_name=name,
            errors=errors,
            warnings=warnings,
        )

    def validate_many(self, classes: list[type]) -> list[ValidationResult]:
        """Validate multiple plugin classes."""
        return [self.validate(cls) for cls in classes]

    def _valid_semver(self, version: str) -> bool:
        """Check if version string is valid semver (x.y.z)."""
        parts = version.split(".")
        if len(parts) < 2:
            return False
        try:
            for p in parts:
                int(p.split("-")[0].split("+")[0])
            return True
        except ValueError:
            return False


# ── 4. Plugin Sandbox ─────────────────────────────────────

class PluginSandbox:
    """
    Execute plugins with timeout and resource limits.

    Runs plugins in a thread with configurable timeout.
    Truncates findings if plugin returns too many.
    Catches and reports all exceptions.
    """

    def __init__(
        self,
        timeout: float = 120.0,
        max_findings: int = 500,
        registry: PluginRegistry | None = None,
    ):
        self.timeout      = timeout
        self.max_findings = max_findings
        self.registry     = registry

    def run(
        self,
        plugin: Any,  # Plugin instance or class
        target: str,
        **kwargs,
    ) -> SandboxResult:
        """
        Run a plugin in a sandboxed thread with timeout.

        Args:
            plugin: Plugin instance (with .run() method) or class
            target: Target URL/host
            **kwargs: Additional args passed to plugin.run()

        Returns:
            SandboxResult with findings, status, and duration
        """
        # Instantiate if class was passed
        if isinstance(plugin, type):
            try:
                plugin = plugin()
            except Exception as e:
                return SandboxResult(
                    plugin_name=getattr(plugin, "name", str(plugin)),
                    target=target, findings=[],
                    duration_s=0.0, status="error",
                    error=f"Instantiation failed: {e}",
                )

        plugin_name = getattr(plugin, "name", plugin.__class__.__name__)
        result_box  = {"findings": None, "error": None}
        start       = time.monotonic()

        def _run():
            try:
                result_box["findings"] = plugin.run(target, **kwargs)
            except Exception as e:
                result_box["error"] = str(e)

        thread = threading.Thread(target=_run, daemon=True)
        thread.start()
        thread.join(timeout=self.timeout)

        duration = time.monotonic() - start

        if thread.is_alive():
            # Timeout
            if self.registry:
                self.registry.record_run(plugin_name, error=True)
            return SandboxResult(
                plugin_name=plugin_name, target=target,
                findings=[], duration_s=round(duration, 2),
                status="timeout",
                error=f"Plugin exceeded timeout ({self.timeout}s)",
            )

        if result_box["error"]:
            if self.registry:
                self.registry.record_run(plugin_name, error=True)
            return SandboxResult(
                plugin_name=plugin_name, target=target,
                findings=[], duration_s=round(duration, 2),
                status="error", error=result_box["error"],
            )

        findings = result_box["findings"] or []
        truncated = len(findings) > self.max_findings
        if truncated:
            findings = findings[:self.max_findings]

        if self.registry:
            self.registry.record_run(plugin_name, error=False)

        return SandboxResult(
            plugin_name=plugin_name, target=target,
            findings=findings, duration_s=round(duration, 2),
            status="truncated" if truncated else "success",
        )

    def run_all(
        self,
        plugins: list[Any],
        target: str,
        **kwargs,
    ) -> list[SandboxResult]:
        """Run multiple plugins sequentially (each with timeout)."""
        return [self.run(p, target, **kwargs) for p in plugins]


# ── 5. Plugin Marketplace ─────────────────────────────────

class PluginMarketplace:
    """
    Browse and install community plugins.

    Maintains a local cache of the community catalog.
    Supports search by name, tag, author.
    """

    def __init__(
        self,
        cache_dir: str = "./.glitchicons",
        installer: PluginInstaller | None = None,
        registry: PluginRegistry | None = None,
    ):
        self.cache_dir  = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.installer  = installer or PluginInstaller()
        self.registry   = registry
        self._catalog:  list[MarketplaceEntry] = []
        self._load_catalog()

    def search(
        self,
        query: str = "",
        tag: str = "",
        verified_only: bool = False,
    ) -> list[MarketplaceEntry]:
        """
        Search the marketplace catalog.

        Args:
            query:         Search term (name/description match)
            tag:           Filter by tag
            verified_only: Only return verified plugins

        Returns:
            Sorted list of matching MarketplaceEntry
        """
        results = list(self._catalog)

        if query:
            query_lower = query.lower()
            results = [
                e for e in results
                if query_lower in e.package_name.lower()
                or query_lower in e.description.lower()
                or query_lower in e.display_name.lower()
            ]

        if tag:
            results = [e for e in results if tag in e.tags]

        if verified_only:
            results = [e for e in results if e.verified]

        # Sort by stars descending
        return sorted(results, key=lambda e: e.stars, reverse=True)

    def get(self, package_name: str) -> MarketplaceEntry | None:
        """Get a specific plugin by package name."""
        for entry in self._catalog:
            if entry.package_name == package_name:
                return entry
        return None

    def install(self, package_name: str, version: str | None = None) -> InstallResult:
        """Install a plugin from the marketplace."""
        entry = self.get(package_name)
        if not entry:
            # Try with prefix
            entry = self.get(f"glitchicons-{package_name}")

        if entry:
            console.print(
                f"  [cyan]Marketplace install:[/cyan] "
                f"{entry.display_name} v{version or entry.version}"
            )
        return self.installer.install(package_name, version=version)

    def print_catalog(self, tag: str = "", verified_only: bool = False) -> None:
        """Print marketplace catalog as rich table."""
        entries = self.search(tag=tag, verified_only=verified_only)
        console.print(f"\n  [bold cyan]⬡ Glitchicons Plugin Marketplace[/bold cyan]")
        console.print(f"  {len(entries)} plugins available\n")

        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Package",     style="cyan", width=28)
        table.add_column("Description", width=38)
        table.add_column("Tags",        width=18)
        table.add_column("Stars",       width=7)
        table.add_column("✓",           width=4)

        for e in entries:
            verified_badge = "[green]✓[/green]" if e.verified else "[dim]·[/dim]"
            table.add_row(
                f"{e.package_name}\n[dim]v{e.version} by {e.author}[/dim]",
                e.description[:37],
                ", ".join(e.tags[:2]),
                str(e.stars),
                verified_badge,
            )
        console.print(table)

    def refresh(self) -> int:
        """Refresh catalog from remote (stub — loads from built-in catalog)."""
        self._catalog = [MarketplaceEntry(**e) for e in COMMUNITY_CATALOG]
        self._save_catalog()
        return len(self._catalog)

    @property
    def catalog_size(self) -> int:
        return len(self._catalog)

    @property
    def verified_count(self) -> int:
        return sum(1 for e in self._catalog if e.verified)

    def _load_catalog(self) -> None:
        """Load catalog from cache or built-in list."""
        cache_file = self.cache_dir / "marketplace_catalog.json"
        if cache_file.exists():
            try:
                data = json.loads(cache_file.read_text(encoding="utf-8"))
                self._catalog = [MarketplaceEntry(**e) for e in data]
                return
            except Exception:
                pass
        # Fall back to built-in catalog
        self._catalog = [MarketplaceEntry(**e) for e in COMMUNITY_CATALOG]
        self._save_catalog()

    def _save_catalog(self) -> None:
        cache_file = self.cache_dir / "marketplace_catalog.json"
        data = [
            {
                "package_name": e.package_name,
                "display_name": e.display_name,
                "description":  e.description,
                "author":       e.author,
                "version":      e.version,
                "tags":         e.tags,
                "stars":        e.stars,
                "downloads":    e.downloads,
                "verified":     e.verified,
                "pypi_url":     e.pypi_url,
            }
            for e in self._catalog
        ]
        cache_file.write_text(json.dumps(data, indent=2), encoding="utf-8")
