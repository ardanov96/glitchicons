# tests/test_cicd_security.py
"""
Unit tests untuk modules/cicd/cicd_security.py
No network calls — file-based analysis only.
"""

import json
import pytest
from pathlib import Path

from modules.cicd.cicd_security import (
    GitHubActionsAuditor, DockerfileAuditor,
    KubernetesAuditor, SecretScanner,
    SecretHit, _finding,
    GHA_INJECTION_PATTERNS, GHA_DANGEROUS_TRIGGERS,
    SECRET_SCAN_PATTERNS, K8S_CHECKS,
    DOCKERFILE_CHECKS, SKIP_DIRS,
)


# ── Fixtures ──────────────────────────────────────────────

@pytest.fixture
def gha(tmp_path):
    return GitHubActionsAuditor(repo_path=str(tmp_path), output_dir=str(tmp_path))


@pytest.fixture
def dockerfile_auditor(tmp_path):
    return DockerfileAuditor(output_dir=str(tmp_path))


@pytest.fixture
def k8s(tmp_path):
    return KubernetesAuditor(manifests_dir=str(tmp_path / "k8s"), output_dir=str(tmp_path))


@pytest.fixture
def scanner(tmp_path):
    return SecretScanner(scan_path=str(tmp_path), output_dir=str(tmp_path))


# ── Tests: _finding ───────────────────────────────────────

class TestFinding:

    @pytest.mark.unit
    def test_valid_finding(self):
        f = _finding("T", "HIGH", 7.5, "CWE-89", "d", "e", "r", "t")
        assert f["severity"] == "HIGH"

    @pytest.mark.unit
    def test_invalid_severity(self):
        with pytest.raises(AssertionError):
            _finding("T", "EXTREME", 7.5, "CWE-89", "d", "e", "r", "t")

    @pytest.mark.unit
    def test_invalid_cwe(self):
        with pytest.raises(AssertionError):
            _finding("T", "HIGH", 7.5, "89", "d", "e", "r", "t")

    @pytest.mark.unit
    def test_source_tagged(self):
        f = _finding("T", "HIGH", 7.5, "CWE-89", "d", "e", "r", "t", source="gha")
        assert "module:gha" in f["source"]


# ── Tests: GitHubActionsAuditor ───────────────────────────

class TestGitHubActionsAuditor:

    SAFE_WORKFLOW = """
name: CI
on:
  push:
    branches: [main]
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
      - run: pytest tests/
"""

    INJECTION_WORKFLOW = """
name: Dangerous
on:
  pull_request:
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo ${{ github.event.pull_request.title }}
"""

    PULL_REQUEST_TARGET_WORKFLOW = """
name: PR Target
on:
  pull_request_target:
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo hello
"""

    UNPINNED_WORKFLOW = """
name: Unpinned
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
"""

    PERMISSIVE_WORKFLOW = """
name: Permissive
on: push
permissions: write-all
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo hello
"""

    @pytest.mark.unit
    def test_init(self, gha):
        assert gha.output_dir.exists()

    @pytest.mark.unit
    def test_safe_workflow_no_findings(self, gha):
        findings = gha.audit_content(self.SAFE_WORKFLOW, "ci.yml")
        assert findings == []

    @pytest.mark.unit
    def test_injection_detected(self, gha):
        findings = gha.audit_content(self.INJECTION_WORKFLOW, "ci.yml")
        injection = [f for f in findings if "Injection" in f["title"]]
        assert len(injection) >= 1
        assert injection[0]["severity"] == "HIGH"

    @pytest.mark.unit
    def test_pull_request_target_critical(self, gha):
        findings = gha.audit_content(self.PULL_REQUEST_TARGET_WORKFLOW, "ci.yml")
        trigger = [f for f in findings if "pull_request_target" in f["title"]]
        assert len(trigger) >= 1
        assert trigger[0]["severity"] == "CRITICAL"

    @pytest.mark.unit
    def test_unpinned_actions_detected(self, gha):
        findings = gha.audit_content(self.UNPINNED_WORKFLOW, "ci.yml")
        unpinned = [f for f in findings if "Unpinned" in f["title"]]
        assert len(unpinned) >= 1
        assert unpinned[0]["severity"] == "MEDIUM"

    @pytest.mark.unit
    def test_permissive_token_detected(self, gha):
        findings = gha.audit_content(self.PERMISSIVE_WORKFLOW, "ci.yml")
        perm = [f for f in findings if "Permissive" in f["title"]]
        assert len(perm) >= 1

    @pytest.mark.unit
    def test_self_hosted_with_pr(self, gha):
        workflow = """
name: Self-Hosted
on:
  pull_request:
jobs:
  build:
    runs-on: self-hosted
    steps:
      - run: echo hello
"""
        findings = gha.audit_content(workflow, "ci.yml")
        sh = [f for f in findings if "Self-Hosted" in f["title"]]
        assert len(sh) >= 1
        assert sh[0]["severity"] == "HIGH"

    @pytest.mark.unit
    def test_no_workflows_returns_empty(self, gha):
        findings = gha.run()
        assert findings == []

    @pytest.mark.unit
    def test_run_finds_workflow_file(self, tmp_path):
        wf_dir = tmp_path / ".github" / "workflows"
        wf_dir.mkdir(parents=True)
        (wf_dir / "ci.yml").write_text("""
name: CI
on: [pull_request_target]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo ${{ github.event.pull_request.title }}
""")
        auditor = GitHubActionsAuditor(repo_path=str(tmp_path), output_dir=str(tmp_path))
        findings = auditor.run()
        assert len(findings) >= 1

    @pytest.mark.unit
    def test_gha_patterns_not_empty(self):
        assert len(GHA_INJECTION_PATTERNS) >= 5
        assert len(GHA_DANGEROUS_TRIGGERS) >= 2


# ── Tests: DockerfileAuditor ──────────────────────────────

class TestDockerfileAuditor:

    SAFE_DOCKERFILE = """
FROM python:3.12.3-slim@sha256:abc123
RUN useradd -r -u 1001 appuser
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY app/ /app/
USER appuser
HEALTHCHECK --interval=30s CMD curl -f http://localhost/health || exit 1
EXPOSE 8080
CMD ["python", "app.py"]
"""

    INSECURE_DOCKERFILE = """
FROM python:latest
USER root
ENV SECRET_KEY=supersecretvalue123
ARG API_TOKEN
ADD https://example.com/setup.sh /setup.sh
RUN curl https://install.sh | bash
COPY . .
CMD ["python", "app.py"]
"""

    @pytest.mark.unit
    def test_init(self, tmp_path):
        out = tmp_path / "out"
        DockerfileAuditor(output_dir=str(out))
        assert out.exists()

    @pytest.mark.unit
    def test_safe_dockerfile_minimal_findings(self, dockerfile_auditor):
        findings = dockerfile_auditor.audit_content(self.SAFE_DOCKERFILE)
        # Safe dockerfile may have zero or very few findings
        critical = [f for f in findings if f["severity"] == "CRITICAL"]
        assert len(critical) == 0

    @pytest.mark.unit
    def test_latest_tag_detected(self, dockerfile_auditor):
        findings = dockerfile_auditor.audit_content(self.INSECURE_DOCKERFILE)
        latest = [f for f in findings if ":latest" in f["title"]]
        assert len(latest) >= 1
        assert latest[0]["severity"] == "MEDIUM"

    @pytest.mark.unit
    def test_secret_in_env_critical(self, dockerfile_auditor):
        dockerfile = "FROM python:3.12\nENV SECRET_KEY=mysecretvalue123\nCMD python app.py"
        findings = dockerfile_auditor.audit_content(dockerfile)
        secret = [f for f in findings if "Secret in ENV" in f["title"]]
        assert len(secret) >= 1
        assert secret[0]["severity"] == "CRITICAL"

    @pytest.mark.unit
    def test_curl_pipe_bash_high(self, dockerfile_auditor):
        dockerfile = "FROM python:3.12\nRUN curl https://install.sh | bash\nCMD python app.py"
        findings = dockerfile_auditor.audit_content(dockerfile)
        curl = [f for f in findings if "curl" in f["title"].lower()]
        assert len(curl) >= 1
        assert curl[0]["severity"] == "HIGH"

    @pytest.mark.unit
    def test_missing_user_high(self, dockerfile_auditor):
        dockerfile = "FROM python:3.12\nRUN pip install flask\nCMD python app.py"
        findings = dockerfile_auditor.audit_content(dockerfile)
        user = [f for f in findings if "USER" in f["title"]]
        assert len(user) >= 1
        assert user[0]["severity"] == "HIGH"

    @pytest.mark.unit
    def test_missing_healthcheck_low(self, dockerfile_auditor):
        dockerfile = "FROM python:3.12\nUSER appuser\nCMD python app.py"
        findings = dockerfile_auditor.audit_content(dockerfile)
        hc = [f for f in findings if "HEALTHCHECK" in f["title"]]
        assert len(hc) >= 1
        assert hc[0]["severity"] == "LOW"

    @pytest.mark.unit
    def test_nonexistent_file_returns_empty(self, tmp_path):
        a = DockerfileAuditor(
            dockerfile_path=str(tmp_path / "Dockerfile"),
            output_dir=str(tmp_path),
        )
        findings = a.run()
        assert findings == []

    @pytest.mark.unit
    def test_dockerfile_checks_not_empty(self):
        assert len(DOCKERFILE_CHECKS) >= 8


# ── Tests: KubernetesAuditor ──────────────────────────────

class TestKubernetesAuditor:

    SECURE_DEPLOYMENT = """
apiVersion: apps/v1
kind: Deployment
metadata:
  name: myapp
spec:
  template:
    spec:
      serviceAccountName: myapp-sa
      securityContext:
        runAsNonRoot: true
        runAsUser: 1001
      containers:
        - name: myapp
          image: myapp:1.0.0
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
          resources:
            limits:
              cpu: "500m"
              memory: "256Mi"
"""

    INSECURE_DEPLOYMENT = """
apiVersion: apps/v1
kind: Deployment
metadata:
  name: vulnerable
spec:
  template:
    spec:
      hostNetwork: true
      hostPID: true
      containers:
        - name: app
          image: app:latest
          securityContext:
            privileged: true
            allowPrivilegeEscalation: true
            runAsUser: 0
"""

    WILDCARD_RBAC = """
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
rules:
  - apiGroups: ["*"]
    resources: ["*"]
    verbs: ["*"]
"""

    @pytest.mark.unit
    def test_init(self, tmp_path):
        out = tmp_path / "out"
        KubernetesAuditor(output_dir=str(out))
        assert out.exists()

    @pytest.mark.unit
    def test_secure_deployment_no_critical(self, k8s):
        findings = k8s.audit_content(self.SECURE_DEPLOYMENT)
        critical = [f for f in findings if f["severity"] == "CRITICAL"]
        assert len(critical) == 0

    @pytest.mark.unit
    def test_privileged_critical(self, k8s):
        findings = k8s.audit_content(self.INSECURE_DEPLOYMENT)
        priv = [f for f in findings if "Privileged" in f["title"]]
        assert len(priv) >= 1
        assert priv[0]["severity"] == "CRITICAL"

    @pytest.mark.unit
    def test_host_network_high(self, k8s):
        findings = k8s.audit_content(self.INSECURE_DEPLOYMENT)
        hn = [f for f in findings if "Host Network" in f["title"]]
        assert len(hn) >= 1
        assert hn[0]["severity"] == "HIGH"

    @pytest.mark.unit
    def test_wildcard_rbac_high(self, k8s):
        findings = k8s.audit_content(self.WILDCARD_RBAC)
        rbac = [f for f in findings if "Wildcard" in f["title"]]
        assert len(rbac) >= 1
        assert rbac[0]["severity"] == "HIGH"

    @pytest.mark.unit
    def test_missing_security_context_medium(self, k8s):
        minimal = "apiVersion: apps/v1\nkind: Deployment\nspec:\n  template:\n    spec:\n      containers:\n        - name: app\n"
        findings = k8s.audit_content(minimal)
        sc = [f for f in findings if "Security Context" in f["title"]]
        assert len(sc) >= 1

    @pytest.mark.unit
    def test_missing_resource_limits(self, k8s):
        no_limits = "apiVersion: apps/v1\nkind: Deployment\nspec:\n  template:\n    spec:\n      containers: []\n"
        findings = k8s.audit_content(no_limits)
        rl = [f for f in findings if "Resource Limits" in f["title"]]
        assert len(rl) >= 1

    @pytest.mark.unit
    def test_secret_in_manifest_critical(self, k8s):
        manifest = "apiVersion: v1\nkind: ConfigMap\ndata:\n  PASSWORD: supersecretvalue123\n"
        findings = k8s.audit_content(manifest)
        sec = [f for f in findings if "Secret" in f["title"]]
        assert len(sec) >= 1

    @pytest.mark.unit
    def test_empty_dir_returns_empty(self, tmp_path):
        empty_dir = tmp_path / "empty_k8s"
        empty_dir.mkdir()
        auditor = KubernetesAuditor(
            manifests_dir=str(empty_dir),
            output_dir=str(tmp_path),
        )
        findings = auditor.run()
        assert findings == []

    @pytest.mark.unit
    def test_k8s_checks_not_empty(self):
        assert len(K8S_CHECKS) >= 8


# ── Tests: SecretScanner ──────────────────────────────────

class TestSecretScanner:

    @pytest.mark.unit
    def test_init(self, scanner):
        assert scanner.output_dir.exists()

    @pytest.mark.unit
    def test_aws_key_detected(self, scanner):
        hits = scanner.scan_content("key = AKIAIOSFODNN7EXAMPLE12\n", "config.py")
        aws = [h for h in hits if "AWS" in h.key_type]
        assert len(aws) >= 1

    @pytest.mark.unit
    def test_google_key_detected(self, scanner):
        hits = scanner.scan_content(
            'AIzaSyAbcdefghijklmnopqrstuvwxyz1234567\n', "config.py"
        )
        goog = [h for h in hits if "Google" in h.key_type]
        assert len(goog) >= 1

    @pytest.mark.unit
    def test_private_key_detected(self, scanner):
        hits = scanner.scan_content("-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n", "key.pem")
        pk = [h for h in hits if "Private" in h.key_type]
        assert len(pk) >= 1

    @pytest.mark.unit
    def test_database_url_detected(self, scanner):
        hits = scanner.scan_content(
            'DB_URL = "postgres://admin:password123@db.prod.com:5432/mydb"\n', "settings.py"
        )
        db = [h for h in hits if "Database" in h.key_type]
        assert len(db) >= 1

    @pytest.mark.unit
    def test_clean_content_no_hits(self, scanner):
        hits = scanner.scan_content("print('hello world')\nx = 1 + 2\n", "main.py")
        assert hits == []

    @pytest.mark.unit
    def test_safe_snippet_masks_secret(self, scanner):
        snippet = scanner._safe_snippet("  API_KEY = 'AKIAIOSFODNN7EXAMPLEABCDEF'")
        assert "***" in snippet

    @pytest.mark.unit
    def test_build_findings_groups_by_type(self, scanner):
        scanner.hits = [
            SecretHit("a.py", 1, "AWS Access Key", "key=AKIA***"),
            SecretHit("b.py", 5, "AWS Access Key", "key=AKIA***"),
            SecretHit("c.py", 3, "Google API Key", "key=AIza***"),
        ]
        findings = scanner._build_findings()
        assert len(findings) == 2  # Grouped by type
        aws = next(f for f in findings if "AWS" in f["title"])
        assert "(2 occurrence" in aws["title"]

    @pytest.mark.unit
    def test_aws_finding_critical(self, scanner):
        scanner.hits = [SecretHit("f.py", 1, "AWS Access Key", "AKIA***")]
        findings = scanner._build_findings()
        assert findings[0]["severity"] == "CRITICAL"

    @pytest.mark.unit
    def test_run_scans_files(self, tmp_path):
        # Write a file with a secret
        (tmp_path / "config.py").write_text(
            "API_KEY = 'AIzaSyAbcdefghijklmnopqrstuvwxyz12345'\n"
        )
        scanner = SecretScanner(scan_path=str(tmp_path), output_dir=str(tmp_path))
        findings = scanner.run()
        assert isinstance(findings, list)

    @pytest.mark.unit
    def test_skips_excluded_dirs(self, tmp_path):
        venv_dir = tmp_path / ".venv" / "lib"
        venv_dir.mkdir(parents=True)
        (venv_dir / "secret.py").write_text(
            "AWS_KEY = 'AKIAIOSFODNN7EXAMPLE12'\n"
        )
        scanner = SecretScanner(scan_path=str(tmp_path), output_dir=str(tmp_path))
        findings = scanner.run()
        assert findings == []

    @pytest.mark.unit
    def test_secret_patterns_not_empty(self):
        assert len(SECRET_SCAN_PATTERNS) >= 10

    @pytest.mark.unit
    def test_skip_dirs_not_empty(self):
        assert ".git" in SKIP_DIRS
        assert "node_modules" in SKIP_DIRS
        assert ".venv" in SKIP_DIRS

    @pytest.mark.unit
    def test_empty_findings_returns_empty_list(self, scanner):
        assert scanner._build_findings() == []
