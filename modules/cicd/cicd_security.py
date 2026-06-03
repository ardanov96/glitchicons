"""
CI/CD & Supply Chain Security — modules/cicd/cicd_security.py

Audits CI/CD pipelines and supply chain attack surfaces:
  1. GitHubActionsAuditor — workflow file security audit
  2. DockerfileAuditor    — Dockerfile misconfiguration detection
  3. KubernetesAuditor    — K8s manifest security audit
  4. SecretScanner        — hardcoded secret detection in source files

Usage:
    from modules.cicd.cicd_security import (
        GitHubActionsAuditor, DockerfileAuditor,
        KubernetesAuditor, SecretScanner,
    )

    # Audit GitHub Actions workflows
    auditor  = GitHubActionsAuditor(repo_path="./myrepo")
    findings = auditor.run()

    # Audit Dockerfile
    findings = DockerfileAuditor(dockerfile_path="./Dockerfile").run()

    # Audit K8s manifests
    findings = KubernetesAuditor(manifests_dir="./k8s").run()

    # Scan for secrets in source
    findings = SecretScanner(scan_path="./src").run()

Author: ardanov96
"""

import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from rich.console import Console

console = Console()


# ── Finding helper ────────────────────────────────────────

def _finding(
    title: str, severity: str, cvss: float, cwe: str,
    description: str, evidence: str, remediation: str,
    target: str, source: str = "cicd_security",
) -> dict:
    assert severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
    assert 0.0 <= cvss <= 10.0
    assert cwe.startswith("CWE-")
    return {
        "title": title, "severity": severity, "cvss": cvss, "cwe": cwe,
        "target": target, "description": description, "evidence": evidence,
        "remediation": remediation, "source": f"module:{source}",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# ── 1. GitHub Actions Auditor ─────────────────────────────

# Dangerous patterns in GitHub Actions workflows
GHA_INJECTION_PATTERNS = [
    # Script injection via untrusted input
    (r'\$\{\{.*github\.event\..*\}\}', "GitHub event data used in expression"),
    (r'\$\{\{.*github\.head_ref.*\}\}', "PR head ref (attacker-controlled) in expression"),
    (r'\$\{\{.*github\.event\.pull_request\.title.*\}\}', "PR title in expression"),
    (r'\$\{\{.*github\.event\.issue\.title.*\}\}', "Issue title in expression"),
    (r'\$\{\{.*github\.event\.comment\.body.*\}\}', "Comment body in expression"),
    (r'run:.*\$\{\{.*\}\}', "User input directly in run step"),
]

# Overly permissive token permissions
GHA_PERM_PATTERNS = [
    (r'permissions:\s*write-all', "write-all permissions"),
    (r'contents:\s*write', "contents: write permission"),
    (r'packages:\s*write', "packages: write permission"),
    (r'deployments:\s*write', "deployments: write permission"),
    (r'secrets:\s*inherit', "secrets: inherit in reusable workflow"),
]

# Pinning checks — actions should use commit SHA not floating tags
GHA_UNPINNED_PATTERN = re.compile(
    r'uses:\s+([a-zA-Z0-9_\-]+/[a-zA-Z0-9_\-]+)@(v[\d.]+|main|master|latest)',
    re.MULTILINE,
)

# Dangerous workflow triggers
GHA_DANGEROUS_TRIGGERS = [
    ("pull_request_target", "CRITICAL — workflow_run/pull_request_target with write access enables supply chain attack"),
    ("workflow_run",        "HIGH — workflow_run can be triggered by fork PRs"),
]

# Secret exposure patterns
GHA_SECRET_EXPOSURE = [
    (r'echo\s+\$\{\{\s*secrets\.', "Secret echoed to logs"),
    (r'run:.*\$\{\{\s*secrets\..*\}\}.*>>.*\$GITHUB_OUTPUT', "Secret written to GITHUB_OUTPUT"),
    (r'env:.*\n.*=.*\$\{\{\s*secrets\.', "Secret in env may leak"),
]


class GitHubActionsAuditor:
    """
    Audit GitHub Actions workflow files for security vulnerabilities.

    Checks:
    - Script injection via untrusted user input (PR title, issue body)
    - Overly permissive GITHUB_TOKEN permissions
    - Unpinned third-party actions (supply chain risk)
    - Dangerous workflow triggers (pull_request_target, workflow_run)
    - Secret exposure in logs or outputs
    - Self-hosted runner misconfigurations
    """

    WORKFLOW_EXTENSIONS = {".yml", ".yaml"}

    def __init__(
        self,
        repo_path: str = ".",
        output_dir: str = "./findings/cicd",
    ):
        self.repo_path  = Path(repo_path)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.workflows_dir = self.repo_path / ".github" / "workflows"

    def run(self) -> list[dict]:
        """Audit all workflow files in the repo."""
        console.print(f"\n  [bold cyan]GitHub Actions Auditor[/bold cyan] → {self.repo_path}")
        findings = []

        workflow_files = self._find_workflows()
        if not workflow_files:
            console.print("  [dim]No workflow files found[/dim]")
            return findings

        console.print(f"  Workflows found: {len(workflow_files)}")

        for wf_path in workflow_files:
            findings.extend(self._audit_workflow(wf_path))

        self._save(findings)
        console.print(f"  Findings: [bold]{len(findings)}[/bold]")
        return findings

    def audit_content(self, content: str, filename: str = "workflow.yml") -> list[dict]:
        """Audit workflow content directly (for testing)."""
        return self._check_workflow_content(content, filename)

    def _find_workflows(self) -> list[Path]:
        """Find all workflow YAML files."""
        files = []
        # Standard location
        if self.workflows_dir.exists():
            for f in self.workflows_dir.iterdir():
                if f.suffix in self.WORKFLOW_EXTENSIONS:
                    files.append(f)
        # Also check repo root for .github folder
        github_dir = self.repo_path / ".github"
        if github_dir.exists() and not self.workflows_dir.exists():
            for f in github_dir.rglob("*.yml"):
                files.append(f)
            for f in github_dir.rglob("*.yaml"):
                files.append(f)
        return files

    def _audit_workflow(self, wf_path: Path) -> list[dict]:
        """Audit a single workflow file."""
        try:
            content = wf_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return []
        return self._check_workflow_content(content, str(wf_path))

    def _check_workflow_content(self, content: str, filename: str) -> list[dict]:
        """Check workflow content for all vulnerability patterns."""
        findings = []
        content_lower = content.lower()

        # 1. Script injection
        for pattern, desc in GHA_INJECTION_PATTERNS:
            if re.search(pattern, content, re.IGNORECASE):
                findings.append(_finding(
                    title=f"GitHub Actions Script Injection Risk: {desc}",
                    severity="HIGH",
                    cvss=8.1,
                    cwe="CWE-77",
                    description=(
                        f"Workflow '{filename}' passes untrusted user input directly into "
                        f"a shell script or expression. {desc}. An attacker can craft "
                        "a PR/issue with malicious content to execute arbitrary code."
                    ),
                    evidence=f"File: {filename}\nPattern: {desc}",
                    remediation=(
                        "Store untrusted input in an env variable first:\n"
                        "  env:\n"
                        "    INPUT: ${{ github.event.pull_request.title }}\n"
                        "  run: echo \"$INPUT\"\n"
                        "Never interpolate ${{ }} directly into run: steps."
                    ),
                    target=filename,
                    source="github_actions_auditor",
                ))
                break  # One finding per injection category

        # 2. Dangerous triggers
        for trigger, desc in GHA_DANGEROUS_TRIGGERS:
            if trigger in content:
                sev  = "CRITICAL" if trigger == "pull_request_target" else "HIGH"
                cvss = 9.0 if trigger == "pull_request_target" else 7.5
                findings.append(_finding(
                    title=f"Dangerous Workflow Trigger: {trigger}",
                    severity=sev,
                    cvss=cvss,
                    cwe="CWE-749",
                    description=(
                        f"Workflow uses '{trigger}' trigger. {desc}. "
                        "Fork PRs can trigger this workflow with write access to secrets."
                    ),
                    evidence=f"File: {filename}\nTrigger: on: {trigger}",
                    remediation=(
                        f"Avoid '{trigger}' with write permissions or secret access. "
                        "For pull_request_target: validate PR source, use explicit permissions. "
                        "Consider using pull_request (no write access) instead."
                    ),
                    target=filename,
                    source="github_actions_auditor",
                ))

        # 3. Overly permissive token
        for pattern, desc in GHA_PERM_PATTERNS:
            if re.search(pattern, content, re.IGNORECASE):
                findings.append(_finding(
                    title=f"Overly Permissive GITHUB_TOKEN: {desc}",
                    severity="MEDIUM",
                    cvss=6.1,
                    cwe="CWE-732",
                    description=(
                        f"Workflow grants excessive GITHUB_TOKEN permissions: {desc}. "
                        "If the workflow is compromised, attackers gain broad repository access."
                    ),
                    evidence=f"File: {filename}\nPermission: {desc}",
                    remediation=(
                        "Apply principle of least privilege:\n"
                        "  permissions:\n"
                        "    contents: read\n"
                        "Only grant specific permissions needed for the job."
                    ),
                    target=filename,
                    source="github_actions_auditor",
                ))
                break

        # 4. Unpinned actions
        unpinned = GHA_UNPINNED_PATTERN.findall(content)
        if unpinned:
            examples = [f"{action}@{tag}" for action, tag in unpinned[:3]]
            findings.append(_finding(
                title=f"Unpinned GitHub Actions ({len(unpinned)} found)",
                severity="MEDIUM",
                cvss=6.5,
                cwe="CWE-1357",
                description=(
                    f"Workflow uses {len(unpinned)} action(s) pinned to a floating tag "
                    "(e.g. v1, main, latest) instead of a full commit SHA. "
                    "A compromised action maintainer could push malicious code to that tag."
                ),
                evidence=f"File: {filename}\nUnpinned: {', '.join(examples)}",
                remediation=(
                    "Pin actions to a full commit SHA:\n"
                    "  uses: actions/checkout@v4  # ← vulnerable\n"
                    "  uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # ← safe\n"
                    "Use tools like Dependabot or pin-github-action to automate."
                ),
                target=filename,
                source="github_actions_auditor",
            ))

        # 5. Self-hosted runners
        if "runs-on: self-hosted" in content_lower or "self-hosted" in content_lower:
            if "pull_request" in content and "self-hosted" in content_lower:
                findings.append(_finding(
                    title="Self-Hosted Runner Used with PR Trigger",
                    severity="HIGH",
                    cvss=8.1,
                    cwe="CWE-284",
                    description=(
                        "Workflow runs on self-hosted runner triggered by pull_request. "
                        "Fork PRs can run code on your infrastructure — "
                        "an attacker could exfiltrate secrets or pivot to internal network."
                    ),
                    evidence=f"File: {filename}\nruns-on: self-hosted + on: pull_request",
                    remediation=(
                        "Use GitHub-hosted runners for PR workflows. "
                        "If self-hosted required: add label-based approval gate. "
                        "Use environment protection rules with required reviewers."
                    ),
                    target=filename,
                    source="github_actions_auditor",
                ))

        # 6. Secret exposure
        for pattern, desc in GHA_SECRET_EXPOSURE:
            if re.search(pattern, content, re.IGNORECASE):
                findings.append(_finding(
                    title=f"Potential Secret Exposure in Workflow: {desc}",
                    severity="HIGH",
                    cvss=7.5,
                    cwe="CWE-312",
                    description=(
                        f"Workflow may expose secrets to logs or outputs: {desc}. "
                        "GitHub masks known secret values in logs, but obfuscation can be bypassed."
                    ),
                    evidence=f"File: {filename}\nPattern: {desc}",
                    remediation=(
                        "Never echo secrets directly. "
                        "Use add-mask to mask dynamic values: "
                        "  echo '::add-mask::${{ secrets.MY_SECRET }}'"
                    ),
                    target=filename,
                    source="github_actions_auditor",
                ))
                break

        return findings

    def _save(self, findings: list[dict]) -> Path:
        ts  = datetime.now().strftime("%Y%m%d_%H%M%S")
        out = self.output_dir / f"gha_{ts}.json"
        out.write_text(json.dumps({"findings": findings}, indent=2), encoding="utf-8")
        return out


# ── 2. Dockerfile Auditor ─────────────────────────────────

# Dockerfile security patterns
DOCKERFILE_CHECKS = [
    # Running as root
    (r"^USER\s+root\s*$", "USER root explicitly set", "MEDIUM", 5.5, "CWE-250"),
    # Latest tag (mutable)
    (r"^FROM\s+\S+:latest", "FROM uses :latest tag (mutable)", "MEDIUM", 5.3, "CWE-1357"),
    # ADD vs COPY (ADD can extract archives and fetch URLs)
    (r"^ADD\s+https?://", "ADD fetches from URL (use COPY + curl with checksum)", "MEDIUM", 5.3, "CWE-494"),
    # Curl pipe bash pattern
    (r"curl\s+.*\|\s*(?:bash|sh|python)", "curl | bash supply chain risk", "HIGH", 8.1, "CWE-494"),
    # Secrets in ENV
    (r"^ENV\s+\S*(?:PASSWORD|SECRET|API_KEY|TOKEN|PASSWD)\S*\s*=", "Secret in ENV instruction", "CRITICAL", 9.1, "CWE-312"),
    # Secrets in ARG
    (r"^ARG\s+(?:PASSWORD|SECRET|API_KEY|TOKEN|PASSWD)", "Secret in ARG instruction (appears in image history)", "HIGH", 7.5, "CWE-312"),
    # COPY . . (copies everything including .env, .git)
    (r"^COPY\s+\.\s+\.", "COPY . . may include sensitive files (.env, .git)", "MEDIUM", 5.3, "CWE-200"),
    # Privileged capabilities
    (r"--privileged", "--privileged flag in RUN", "HIGH", 8.1, "CWE-250"),
    # SSH keys baked in
    (r"(?:id_rsa|id_ed25519|\.pem|\.key)", "Private key file referenced", "CRITICAL", 9.8, "CWE-312"),
    # EXPOSE without HEALTHCHECK
    (r"^EXPOSE\s+\d+", "Port exposed", "INFO", 0.0, "CWE-200"),
]

MISSING_DOCKERFILE_CHECKS = [
    ("HEALTHCHECK", "No HEALTHCHECK instruction", "LOW", 3.1, "CWE-778"),
    ("USER", "No USER instruction — runs as root by default", "HIGH", 7.5, "CWE-250"),
]


class DockerfileAuditor:
    """
    Audit Dockerfiles for security misconfigurations.

    Checks:
    - Running as root (missing USER instruction)
    - Mutable :latest tags
    - Secrets in ENV/ARG instructions (appear in image history)
    - curl | bash supply chain attacks
    - COPY . . exposing sensitive files
    - Missing HEALTHCHECK
    - Private key files baked into image
    - Multi-stage build: secrets leaking between stages
    """

    def __init__(
        self,
        dockerfile_path: str = "Dockerfile",
        output_dir: str = "./findings/cicd",
    ):
        self.dockerfile_path = Path(dockerfile_path)
        self.output_dir      = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def run(self) -> list[dict]:
        """Audit the Dockerfile."""
        console.print(f"\n  [bold cyan]Dockerfile Auditor[/bold cyan] → {self.dockerfile_path}")

        if not self.dockerfile_path.exists():
            console.print(f"  [red]Dockerfile not found:[/red] {self.dockerfile_path}")
            return []

        content = self.dockerfile_path.read_text(encoding="utf-8", errors="ignore")
        findings = self.audit_content(content, str(self.dockerfile_path))
        self._save(findings)
        console.print(f"  Findings: [bold]{len(findings)}[/bold]")
        return findings

    def audit_content(self, content: str, filename: str = "Dockerfile") -> list[dict]:
        """Audit Dockerfile content directly (for testing)."""
        findings = []
        lines    = content.splitlines()

        for line in lines:
            line_stripped = line.strip()
            if not line_stripped or line_stripped.startswith("#"):
                continue

            for pattern, desc, severity, cvss, cwe in DOCKERFILE_CHECKS:
                if re.search(pattern, line_stripped, re.IGNORECASE | re.MULTILINE):
                    if severity == "INFO":
                        continue  # Skip INFO-level inline; check globally
                    findings.append(_finding(
                        title=f"Dockerfile Issue: {desc}",
                        severity=severity,
                        cvss=cvss,
                        cwe=cwe,
                        description=f"Dockerfile contains insecure instruction: {desc}",
                        evidence=f"File: {filename}\nLine: {line_stripped[:120]}",
                        remediation=self._remediation(desc),
                        target=filename,
                        source="dockerfile_auditor",
                    ))
                    break  # One finding per line

        # Global checks: missing instructions
        for instruction, desc, severity, cvss, cwe in MISSING_DOCKERFILE_CHECKS:
            if instruction not in content.upper():
                findings.append(_finding(
                    title=f"Dockerfile Missing: {desc}",
                    severity=severity,
                    cvss=cvss,
                    cwe=cwe,
                    description=desc,
                    evidence=f"File: {filename}\nInstruction '{instruction}' not found",
                    remediation=self._remediation(desc),
                    target=filename,
                    source="dockerfile_auditor",
                ))

        # Check for multi-stage secrets leak
        stages = [l for l in lines if re.match(r"^FROM\s+", l.strip(), re.IGNORECASE)]
        if len(stages) >= 2 and re.search(r"^COPY\s+--from=", content, re.IGNORECASE | re.MULTILINE):
            # Multi-stage detected — check if secrets used in non-final stage
            if re.search(r"^ARG\s+\S*(?:SECRET|TOKEN|KEY|PASSWORD)", content, re.IGNORECASE | re.MULTILINE):
                findings.append(_finding(
                    title="Multi-Stage Build: Secret ARG May Persist in Layer History",
                    severity="HIGH",
                    cvss=7.5,
                    cwe="CWE-312",
                    description=(
                        "Multi-stage Dockerfile uses secret ARGs. "
                        "Even if secrets aren't copied to final stage, "
                        "they appear in intermediate layer history and can be extracted."
                    ),
                    evidence=f"File: {filename}\nMulti-stage build with secret ARG detected",
                    remediation=(
                        "Use Docker BuildKit secrets: "
                        "RUN --mount=type=secret,id=mysecret cat /run/secrets/mysecret\n"
                        "Build with: docker build --secret id=mysecret,src=./secret.txt ."
                    ),
                    target=filename,
                    source="dockerfile_auditor",
                ))

        return findings

    def _remediation(self, desc: str) -> str:
        remediations = {
            "USER root explicitly set":      "Never use USER root. Create a non-root user: RUN useradd -r appuser && USER appuser",
            "FROM uses :latest tag":         "Pin to a specific digest: FROM python:3.12.3-slim@sha256:<digest>",
            "ADD fetches from URL":          "Use COPY + RUN curl with checksum verification instead of ADD URL",
            "curl | bash supply chain risk": "Download script, verify checksum, then execute separately",
            "Secret in ENV instruction":     "Use Docker BuildKit secrets or runtime environment injection. Never hardcode in ENV.",
            "Secret in ARG instruction":     "Use BuildKit --secret mount instead of ARG for sensitive values",
            "COPY . . may include":          "Add .dockerignore to exclude .env, .git, credentials. Use explicit COPY paths.",
            "--privileged flag":             "Remove --privileged. Grant only specific capabilities needed.",
            "Private key file referenced":   "Never include private keys in images. Use secrets management (Vault, AWS Secrets Manager).",
            "No HEALTHCHECK instruction":    "Add: HEALTHCHECK --interval=30s CMD curl -f http://localhost/health || exit 1",
            "No USER instruction":           "Add non-root user: RUN useradd -r -u 1001 appuser && USER appuser",
            "Multi-Stage Build":             "Use Docker BuildKit secrets for build-time credentials",
        }
        for key, rem in remediations.items():
            if key.lower() in desc.lower():
                return rem
        return "Review and fix the identified Dockerfile security issue."

    def _save(self, findings: list[dict]) -> Path:
        ts  = datetime.now().strftime("%Y%m%d_%H%M%S")
        out = self.output_dir / f"dockerfile_{ts}.json"
        out.write_text(json.dumps({"findings": findings}, indent=2), encoding="utf-8")
        return out


# ── 3. Kubernetes Auditor ─────────────────────────────────

K8S_CHECKS = {
    "privileged_container": {
        "pattern":  r"privileged:\s*true",
        "title":    "Privileged Kubernetes Container",
        "severity": "CRITICAL",
        "cvss":     9.8,
        "cwe":      "CWE-250",
        "desc":     "Container runs in privileged mode — equivalent to root on host node.",
        "fix":      "Remove privileged: true. Use specific capabilities instead: capabilities.add: [NET_BIND_SERVICE]",
    },
    "host_network": {
        "pattern":  r"hostNetwork:\s*true",
        "title":    "Host Network Access Enabled",
        "severity": "HIGH",
        "cvss":     8.1,
        "cwe":      "CWE-284",
        "desc":     "Container shares host network namespace — can access all host network interfaces.",
        "fix":      "Remove hostNetwork: true. Use Service/NetworkPolicy for required connectivity.",
    },
    "host_pid": {
        "pattern":  r"hostPID:\s*true",
        "title":    "Host PID Namespace Shared",
        "severity": "HIGH",
        "cvss":     8.1,
        "cwe":      "CWE-250",
        "desc":     "Container shares host PID namespace — can see and signal all host processes.",
        "fix":      "Remove hostPID: true.",
    },
    "allow_privilege_escalation": {
        "pattern":  r"allowPrivilegeEscalation:\s*true",
        "title":    "Privilege Escalation Allowed",
        "severity": "HIGH",
        "cvss":     7.5,
        "cwe":      "CWE-250",
        "desc":     "Container allows privilege escalation via setuid/setgid binaries.",
        "fix":      "Set allowPrivilegeEscalation: false in securityContext.",
    },
    "run_as_root": {
        "pattern":  r"runAsUser:\s*0",
        "title":    "Container Runs as Root (UID 0)",
        "severity": "HIGH",
        "cvss":     7.5,
        "cwe":      "CWE-250",
        "desc":     "Container explicitly configured to run as root user.",
        "fix":      "Set runAsUser to a non-zero UID: runAsUser: 1001",
    },
    "wildcard_rbac": {
        "pattern":  r'resources:\s*\[?"?\*"?\]?',
        "title":    "Wildcard RBAC Resources (*)",
        "severity": "HIGH",
        "cvss":     8.1,
        "cwe":      "CWE-732",
        "desc":     "RBAC role grants access to all (*) resources — violates least privilege.",
        "fix":      "Specify exact resource types needed: resources: [pods, services]",
    },
    "wildcard_verbs": {
        "pattern":  r'verbs:\s*\[?"?\*"?\]?',
        "title":    "Wildcard RBAC Verbs (*)",
        "severity": "HIGH",
        "cvss":     8.1,
        "cwe":      "CWE-732",
        "desc":     "RBAC role grants all verbs (*) — effectively full control over matched resources.",
        "fix":      "Specify exact verbs: verbs: [get, list, watch]",
    },
    "default_service_account": {
        "pattern":  r"serviceAccountName:\s*default",
        "title":    "Default Service Account Used",
        "severity": "MEDIUM",
        "cvss":     5.5,
        "cwe":      "CWE-732",
        "desc":     "Pod uses the default service account which often has excessive permissions.",
        "fix":      "Create a dedicated service account with minimal permissions.",
    },
    "secret_in_env": {
        "pattern":  r"(?:PASSWORD|SECRET|TOKEN|API_KEY):\s*['\"]?[A-Za-z0-9+/]{8,}",
        "title":    "Secret Value in K8s Manifest",
        "severity": "CRITICAL",
        "cvss":     9.1,
        "cwe":      "CWE-312",
        "desc":     "Kubernetes manifest contains what appears to be a hardcoded secret value.",
        "fix":      "Use Kubernetes Secrets or external secret manager (Vault, AWS Secrets Manager). Reference via secretKeyRef.",
    },
    "no_resource_limits": {
        "pattern":  None,  # Checked separately
        "title":    "No Resource Limits Defined",
        "severity": "MEDIUM",
        "cvss":     5.3,
        "cwe":      "CWE-400",
        "desc":     "Container has no CPU/memory limits — DoS risk via resource exhaustion.",
        "fix":      "Add resources.limits: {cpu: '500m', memory: '256Mi'}",
    },
}


class KubernetesAuditor:
    """
    Audit Kubernetes YAML manifests for security misconfigurations.

    Checks:
    - Privileged containers
    - Host network/PID namespace sharing
    - Privilege escalation allowed
    - Wildcard RBAC permissions
    - Hardcoded secrets in manifests
    - Missing resource limits
    - Default service account usage
    - No security context
    """

    MANIFEST_EXTENSIONS = {".yml", ".yaml"}

    def __init__(
        self,
        manifests_dir: str = "./k8s",
        output_dir: str = "./findings/cicd",
    ):
        self.manifests_dir = Path(manifests_dir)
        self.output_dir    = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def run(self) -> list[dict]:
        """Audit all K8s manifests in directory."""
        console.print(f"\n  [bold cyan]Kubernetes Auditor[/bold cyan] → {self.manifests_dir}")
        findings = []

        if not self.manifests_dir.exists():
            console.print(f"  [yellow]Directory not found:[/yellow] {self.manifests_dir}")
            return findings

        manifests = list(self.manifests_dir.rglob("*.yml")) + list(self.manifests_dir.rglob("*.yaml"))
        console.print(f"  Manifests found: {len(manifests)}")

        for manifest in manifests:
            try:
                content = manifest.read_text(encoding="utf-8", errors="ignore")
                findings.extend(self.audit_content(content, str(manifest)))
            except Exception:
                continue

        self._save(findings)
        console.print(f"  Findings: [bold]{len(findings)}[/bold]")
        return findings

    def audit_content(self, content: str, filename: str = "manifest.yaml") -> list[dict]:
        """Audit K8s manifest content directly (for testing)."""
        findings = []

        for check_name, check in K8S_CHECKS.items():
            if check["pattern"] is None:
                continue
            if re.search(check["pattern"], content, re.IGNORECASE | re.MULTILINE):
                findings.append(_finding(
                    title=check["title"],
                    severity=check["severity"],
                    cvss=check["cvss"],
                    cwe=check["cwe"],
                    description=check["desc"],
                    evidence=f"File: {filename}\nPattern matched: {check['pattern'][:60]}",
                    remediation=check["fix"],
                    target=filename,
                    source="kubernetes_auditor",
                ))

        # Missing resource limits (heuristic)
        if "resources:" not in content and (
            "kind: Deployment" in content or
            "kind: Pod" in content or
            "kind: DaemonSet" in content
        ):
            check = K8S_CHECKS["no_resource_limits"]
            findings.append(_finding(
                title=check["title"],
                severity=check["severity"],
                cvss=check["cvss"],
                cwe=check["cwe"],
                description=check["desc"],
                evidence=f"File: {filename}\n'resources:' section not found",
                remediation=check["fix"],
                target=filename,
                source="kubernetes_auditor",
            ))

        # Missing securityContext
        if "securityContext:" not in content and (
            "kind: Deployment" in content or "kind: Pod" in content
        ):
            findings.append(_finding(
                title="Missing Kubernetes Security Context",
                severity="MEDIUM",
                cvss=5.5,
                cwe="CWE-250",
                description="Workload has no securityContext defined — default (insecure) settings apply.",
                evidence=f"File: {filename}\nsecurityContext not found",
                remediation=(
                    "Add securityContext:\n"
                    "  runAsNonRoot: true\n"
                    "  runAsUser: 1001\n"
                    "  allowPrivilegeEscalation: false\n"
                    "  readOnlyRootFilesystem: true"
                ),
                target=filename,
                source="kubernetes_auditor",
            ))

        return findings

    def _save(self, findings: list[dict]) -> Path:
        ts  = datetime.now().strftime("%Y%m%d_%H%M%S")
        out = self.output_dir / f"k8s_{ts}.json"
        out.write_text(json.dumps({"findings": findings}, indent=2), encoding="utf-8")
        return out


# ── 4. Secret Scanner ─────────────────────────────────────

SECRET_SCAN_PATTERNS = {
    "AWS Access Key":     r"AKIA[0-9A-Z]{16}",
    "Google API Key":     r"AIza[0-9A-Za-z\-_]{35}",
    "GitHub Token":       r"gh[pousr]_[A-Za-z0-9]{36,}",
    "Firebase URL":       r"https://[a-z0-9\-]+\.firebaseio\.com",
    "JWT Token":          r"eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+",
    "Private RSA Key":    r"-----BEGIN RSA PRIVATE KEY-----",
    "Private EC Key":     r"-----BEGIN EC PRIVATE KEY-----",
    "Generic API Key":    r"(?i)(?:api[_-]?key|apikey)\s*[=:]\s*['\"]?([A-Za-z0-9_\-]{20,50})['\"]?",
    "Generic Password":   r"(?i)(?:password|passwd|pwd)\s*[=:]\s*['\"]([^'\"\s]{8,50})['\"]",
    "Generic Secret":     r"(?i)(?:secret|client_secret)\s*[=:]\s*['\"]?([A-Za-z0-9_\-+/]{16,})['\"]?",
    "Database URL":       r"(?:postgres|mysql|mongodb|redis)://[^\s'\"]+:[^\s'\"]+@[^\s'\"]+",
    "Bearer Token":       r"[Bb]earer\s+[A-Za-z0-9\-_\.]{20,}",
    "Slack Token":        r"xox[baprs]-[A-Za-z0-9]{10,}",
    "SendGrid Key":       r"SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}",
}

# Files to skip during scanning
SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".woff", ".woff2",
    ".ttf", ".eot", ".mp4", ".mp3", ".pdf", ".zip", ".tar", ".gz",
    ".exe", ".dll", ".so", ".dylib", ".bin", ".pyc", ".class",
}

SKIP_DIRS = {
    ".git", ".venv", "venv", "node_modules", "__pycache__",
    "dist", "build", ".tox", ".mypy_cache", ".pytest_cache",
}


@dataclass
class SecretHit:
    """A single secret match found in a file."""
    file:     str
    line:     int
    key_type: str
    snippet:  str  # Truncated, safe-to-log version


class SecretScanner:
    """
    Scan source code files for hardcoded secrets.

    Scans all text files in a directory tree for:
    - AWS access keys
    - API keys and tokens
    - Private RSA/EC keys
    - Database connection strings with credentials
    - GitHub tokens
    - Generic passwords and secrets

    Skips binary files, build artifacts, and vendor directories.
    """

    def __init__(
        self,
        scan_path: str = ".",
        output_dir: str = "./findings/cicd",
        exclude_dirs: list[str] | None = None,
        exclude_files: list[str] | None = None,
        max_file_size_kb: int = 500,
    ):
        self.scan_path       = Path(scan_path)
        self.output_dir      = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.exclude_dirs    = set(exclude_dirs or []) | SKIP_DIRS
        self.exclude_files   = set(exclude_files or [])
        self.max_file_size   = max_file_size_kb * 1024
        self.hits:           list[SecretHit] = []

    def run(self) -> list[dict]:
        """Scan all files and return findings."""
        console.print(f"\n  [bold cyan]Secret Scanner[/bold cyan] → {self.scan_path}")
        self.hits = []
        files_scanned = 0

        for file_path in self._iter_files():
            try:
                new_hits = self._scan_file(file_path)
                self.hits.extend(new_hits)
                files_scanned += 1
            except Exception:
                continue

        console.print(
            f"  Scanned: {files_scanned} files | "
            f"Secrets found: {len(self.hits)}"
        )

        findings = self._build_findings()
        self._save(findings)
        return findings

    def scan_content(self, content: str, filename: str = "file.txt") -> list[SecretHit]:
        """Scan string content directly (for testing)."""
        hits = []
        for line_num, line in enumerate(content.splitlines(), 1):
            for key_type, pattern in SECRET_SCAN_PATTERNS.items():
                if re.search(pattern, line):
                    hits.append(SecretHit(
                        file=filename,
                        line=line_num,
                        key_type=key_type,
                        snippet=self._safe_snippet(line),
                    ))
                    break
        return hits

    def _iter_files(self):
        """Iterate over all scannable files."""
        for path in self.scan_path.rglob("*"):
            if not path.is_file():
                continue
            # Skip excluded dirs
            if any(part in self.exclude_dirs for part in path.parts):
                continue
            # Skip excluded files
            if path.name in self.exclude_files:
                continue
            # Skip binary extensions
            if path.suffix.lower() in SKIP_EXTENSIONS:
                continue
            # Skip large files
            try:
                if path.stat().st_size > self.max_file_size:
                    continue
            except Exception:
                continue
            yield path

    def _scan_file(self, file_path: Path) -> list[SecretHit]:
        """Scan a single file for secrets."""
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return []
        return self.scan_content(content, str(file_path))

    def _safe_snippet(self, line: str) -> str:
        """Return a safe-to-log snippet (truncated, partial masking)."""
        stripped = line.strip()[:120]
        # Mask anything that looks like a long alphanumeric value
        masked = re.sub(r'([A-Za-z0-9+/]{6})[A-Za-z0-9+/=]{10,}', r'\1***', stripped)
        return masked

    def _build_findings(self) -> list[dict]:
        """Convert secret hits into findings, grouped by type."""
        if not self.hits:
            return []

        findings = []
        by_type: dict[str, list[SecretHit]] = {}
        for hit in self.hits:
            by_type.setdefault(hit.key_type, []).append(hit)

        for key_type, hits in by_type.items():
            sev  = "CRITICAL" if any(
                kw in key_type for kw in ["AWS", "Private", "Database"]
            ) else "HIGH"
            cvss = 9.1 if sev == "CRITICAL" else 7.5

            evidence_lines = [
                f"{h.file}:{h.line}  {h.snippet}" for h in hits[:5]
            ]
            findings.append(_finding(
                title=f"Hardcoded Secret: {key_type} ({len(hits)} occurrence(s))",
                severity=sev,
                cvss=cvss,
                cwe="CWE-312",
                description=(
                    f"Found {len(hits)} hardcoded {key_type} value(s) in source code. "
                    "Hardcoded secrets are exposed to anyone with repository access "
                    "and persist in git history even after removal."
                ),
                evidence="\n".join(evidence_lines),
                remediation=(
                    f"Remove {key_type} from source code immediately. "
                    "Rotate/revoke the exposed credential. "
                    "Use environment variables, .env files (gitignored), "
                    "or secrets managers (Vault, AWS Secrets Manager, GitHub Secrets)."
                ),
                target=str(self.scan_path),
                source="secret_scanner",
            ))

        return findings

    def _save(self, findings: list[dict]) -> Path:
        ts  = datetime.now().strftime("%Y%m%d_%H%M%S")
        out = self.output_dir / f"secrets_{ts}.json"
        data = {
            "scan_path": str(self.scan_path),
            "total_hits": len(self.hits),
            "findings":  findings,
        }
        out.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
        return out
