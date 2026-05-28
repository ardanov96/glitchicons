"""
Plugin System — glitchicons/plugin_system.py

Enables third-party modules to extend Glitchicons via pip install.

Plugin interface:
  - Plugins register via Python entry_points under "glitchicons.plugins"
  - Each plugin must implement the GlitchiconPlugin base class
  - Plugins are auto-discovered on import

Creating a plugin:
    # In your plugin package's pyproject.toml:
    [project.entry-points."glitchicons.plugins"]
    my-plugin = "myplugin.module:MyPlugin"

    # In myplugin/module.py:
    from glitchicons.plugin_system import GlitchiconPlugin

    class MyPlugin(GlitchiconPlugin):
        name        = "my-plugin"
        version     = "1.0.0"
        description = "Does something cool"
        author      = "yourname"

        def run(self, target: str, **kwargs) -> list[dict]:
            # Return list of findings in standard format
            return []

Usage:
    from glitchicons.plugin_system import PluginRegistry
    registry = PluginRegistry()
    plugins = registry.discover()
    for plugin in plugins:
        findings = plugin.run(target="https://target.com")

Author: ardanov96
"""

import importlib
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any
from rich.console import Console

console = Console()


# ── Finding schema ────────────────────────────────────────

def make_finding(
    title: str,
    severity: str,
    cvss: float,
    cwe: str,
    description: str,
    evidence: str,
    remediation: str,
    target: str,
    plugin_name: str = "unknown",
    **extra,
) -> dict:
    """
    Create a standardized finding dict.
    All Glitchicons findings — including plugin findings — must use this schema.
    """
    assert severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"), \
        f"Invalid severity: {severity}"
    assert 0.0 <= cvss <= 10.0, f"CVSS out of range: {cvss}"
    assert cwe.startswith("CWE-"), f"Invalid CWE format: {cwe}"

    return {
        "title":       title,
        "severity":    severity,
        "cvss":        cvss,
        "cwe":         cwe,
        "target":      target,
        "description": description,
        "evidence":    evidence,
        "remediation": remediation,
        "source":      f"plugin:{plugin_name}",
        "timestamp":   datetime.now().isoformat(),
        **extra,
    }


# ── Plugin base class ─────────────────────────────────────

class GlitchiconPlugin(ABC):
    """
    Base class for all Glitchicons plugins.

    Subclass this and implement `run()` to create a plugin.
    Register via pyproject.toml entry_points.
    """

    # Required metadata — set in subclass
    name:        str = "unnamed-plugin"
    version:     str = "0.0.0"
    description: str = ""
    author:      str = ""

    # Optional metadata
    tags:        list[str] = []   # e.g. ["recon", "auth", "inject"]
    requires:    list[str] = []   # pip packages required

    @abstractmethod
    def run(self, target: str, **kwargs) -> list[dict]:
        """
        Run the plugin against target.

        Args:
            target:   URL, domain, or other target identifier
            **kwargs: Additional plugin-specific arguments

        Returns:
            List of finding dicts (use make_finding() to create them)
        """
        raise NotImplementedError

    def validate_finding(self, finding: dict) -> bool:
        """Validate a finding dict has all required fields."""
        required = {"title", "severity", "cvss", "cwe",
                    "description", "evidence", "remediation"}
        return required.issubset(set(finding.keys()))

    def check_requirements(self) -> list[str]:
        """Check if all required pip packages are installed."""
        missing = []
        for pkg in self.requires:
            try:
                importlib.import_module(pkg)
            except ImportError:
                missing.append(pkg)
        return missing

    def __repr__(self):
        return f"<GlitchiconPlugin name={self.name!r} version={self.version!r}>"


# ── Plugin registry ───────────────────────────────────────

@dataclass
class PluginInfo:
    """Metadata about a discovered plugin."""
    name:        str
    version:     str
    description: str
    author:      str
    tags:        list[str]
    plugin_class: type
    entry_point:  str = ""

    def instantiate(self) -> GlitchiconPlugin:
        return self.plugin_class()


class PluginRegistry:
    """
    Discovers and manages installed Glitchicons plugins.

    Uses Python's importlib.metadata to find plugins registered
    under the "glitchicons.plugins" entry_point group.
    """

    ENTRY_POINT_GROUP = "glitchicons.plugins"

    def __init__(self):
        self._plugins: list[PluginInfo] = []
        self._discovered = False

    def discover(self) -> list[PluginInfo]:
        """Discover all installed plugins via entry_points."""
        if self._discovered:
            return self._plugins

        try:
            from importlib.metadata import entry_points
            eps = entry_points(group=self.ENTRY_POINT_GROUP)
        except Exception:
            eps = []

        self._plugins = []
        for ep in eps:
            try:
                plugin_class = ep.load()
                if not (isinstance(plugin_class, type)
                        and issubclass(plugin_class, GlitchiconPlugin)):
                    console.print(
                        f"  [yellow]Warning: {ep.name} is not a GlitchiconPlugin subclass[/yellow]"
                    )
                    continue

                info = PluginInfo(
                    name=getattr(plugin_class, "name", ep.name),
                    version=getattr(plugin_class, "version", "0.0.0"),
                    description=getattr(plugin_class, "description", ""),
                    author=getattr(plugin_class, "author", ""),
                    tags=getattr(plugin_class, "tags", []),
                    plugin_class=plugin_class,
                    entry_point=str(ep),
                )
                self._plugins.append(info)

            except Exception as e:
                console.print(f"  [red]Failed to load plugin {ep.name}: {e}[/red]")

        self._discovered = True
        return self._plugins

    def get(self, name: str) -> PluginInfo | None:
        """Get plugin by name."""
        self.discover()
        return next((p for p in self._plugins if p.name == name), None)

    def run_all(
        self,
        target: str,
        tags: list[str] | None = None,
        **kwargs,
    ) -> list[dict]:
        """
        Run all plugins (optionally filtered by tag) against target.

        Args:
            target: Target URL/domain
            tags:   Filter plugins by tag (None = run all)
            **kwargs: Passed to each plugin's run()

        Returns:
            Combined findings from all plugins
        """
        self.discover()
        all_findings = []
        plugins_to_run = self._plugins

        if tags:
            plugins_to_run = [
                p for p in self._plugins
                if any(t in p.tags for t in tags)
            ]

        for info in plugins_to_run:
            console.print(f"  [cyan]>> Plugin: {info.name} v{info.version}[/cyan]")

            plugin = info.instantiate()
            missing = plugin.check_requirements()
            if missing:
                console.print(
                    f"  [yellow]Skipping {info.name}: "
                    f"missing {missing}. Run: pip install {' '.join(missing)}[/yellow]"
                )
                continue

            try:
                findings = plugin.run(target=target, **kwargs)
                valid = [f for f in (findings or []) if plugin.validate_finding(f)]
                all_findings.extend(valid)
                console.print(f"    {len(valid)} finding(s)")
            except Exception as e:
                console.print(f"  [red]Plugin {info.name} error: {e}[/red]")

        return all_findings

    @property
    def count(self) -> int:
        return len(self.discover())

    def __repr__(self):
        return f"<PluginRegistry plugins={self.count}>"


# ── Built-in plugin examples (template for community) ─────

class ExamplePlugin(GlitchiconPlugin):
    """
    Example plugin — shows the minimal structure.
    Copy this as a starting point for your own plugin.

    To publish:
        pip install build twine
        python -m build
        twine upload dist/*

    Name your package: glitchicons-<your-name>
    """

    name        = "example-plugin"
    version     = "1.0.0"
    description = "Example plugin — does nothing, shows structure"
    author      = "community"
    tags        = ["example"]

    def run(self, target: str, **kwargs) -> list[dict]:
        """No-op example implementation."""
        return []
