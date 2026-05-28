"""
GLITCHICONS — AI-Powered Security Research Platform
====================================================

Version: 1.0.0
License: MIT
Author:  ardanov96
GitHub:  https://github.com/ardanov96/glitchicons

Quick start:
    from glitchicons import GraphQLFuzzer, CORSChecker, OpenAPIParser
    from glitchicons.intelligence import LLMMutator, FalsePositiveReducer
    from glitchicons.report import HTMLReporter

    # CORS check
    checker = CORSChecker(target="https://target.com")
    findings = checker.run()

    # Reduce false positives
    reducer = FalsePositiveReducer(provider="ollama")
    verified = reducer.verify_all(findings)

    # Generate HTML report
    reporter = HTMLReporter(findings=verified, target="target.com")
    path = reporter.generate()
"""

__version__ = "1.0.0"
__author__  = "ardanov96"
__license__ = "MIT"
__url__     = "https://github.com/ardanov96/glitchicons"

# ── Public API — Web offensive ────────────────────────────
from modules.inject.graphql_fuzzer   import GraphQLFuzzer
from modules.inject.websocket_fuzzer import WebSocketFuzzer
from modules.inject.cors_checker     import CORSChecker
from modules.inject.grpc_fuzzer      import GRPCFuzzer

# ── Public API — Recon ────────────────────────────────────
from modules.recon.openapi_parser      import OpenAPIParser, AttackPlan
from modules.recon.subdomain_takeover  import SubdomainTakeoverChecker

# ── Public API — Auth ─────────────────────────────────────
from modules.auth.mfa_bypass import MFABypassTester, OTPGenerator

# ── Public API — Intelligence ─────────────────────────────
from modules.intelligence.llm_mutator       import LLMMutator, MutationResult
from modules.intelligence.fp_reducer        import FalsePositiveReducer
from modules.intelligence.severity_reasoner import SeverityReasoner, CVSSCalculator
from modules.intelligence.waf_evasion       import WAFEvasionEngine, Encoder

# ── Public API — Report ───────────────────────────────────
from modules.report.html_reporter import HTMLReporter

# ── Public API — Config ───────────────────────────────────
from modules.config.config_loader import ConfigLoader, EngagementConfig
from modules.config.siege_runner  import SiegeRunner

__all__ = [
    # Version
    "__version__", "__author__", "__license__", "__url__",

    # Web offensive
    "GraphQLFuzzer", "WebSocketFuzzer", "CORSChecker", "GRPCFuzzer",

    # Recon
    "OpenAPIParser", "AttackPlan", "SubdomainTakeoverChecker",

    # Auth
    "MFABypassTester", "OTPGenerator",

    # Intelligence
    "LLMMutator", "MutationResult",
    "FalsePositiveReducer",
    "SeverityReasoner", "CVSSCalculator",
    "WAFEvasionEngine", "Encoder",

    # Report
    "HTMLReporter",

    # Config
    "ConfigLoader", "EngagementConfig", "SiegeRunner",
]
