# tests/test_cloud_native_v2.py
"""
Unit tests untuk modules/cloud/cloud_native_v2.py
No network calls — all analysis is offline/file-based.
"""

import json
import pytest
from pathlib import Path

from modules.cloud.cloud_native_v2 import (
    AWSIAMAnalyzer, TerraformScanner,
    AzureADScanner, GCPIAMAnalyzer,
    PrivEscPath, IAM_PRIVESC_PERMISSIONS,
    TERRAFORM_CHECKS, AZURE_CHECKS,
    DANGEROUS_GCP_ROLES, DANGEROUS_GCP_MEMBERS,
    GCP_PRIMITIVE_ROLES, _finding,
)


# ── Sample data ───────────────────────────────────────────

def admin_policy():
    return {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect":   "Allow",
            "Action":   "*",
            "Resource": "*",
        }]
    }


def safe_policy():
    return {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect":   "Allow",
            "Action":   ["s3:GetObject", "s3:PutObject"],
            "Resource": "arn:aws:s3:::my-bucket/*",
        }]
    }


def privesc_policy():
    return {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect":   "Allow",
            "Action":   ["iam:CreatePolicyVersion", "iam:AttachUserPolicy"],
            "Resource": "*",
        }]
    }


def trust_policy_wildcard():
    return {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect":    "Allow",
            "Principal": "*",
            "Action":    "sts:AssumeRole",
        }]
    }


def trust_policy_cross_account():
    return {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect":    "Allow",
            "Principal": {"AWS": "arn:aws:iam::999999999999:root"},
            "Action":    "sts:AssumeRole",
        }]
    }


SAFE_TF = """
resource "aws_s3_bucket" "private" {
  bucket = "my-private-bucket"
}

resource "aws_s3_bucket_acl" "private_acl" {
  bucket = aws_s3_bucket.private.id
  acl    = "private"
}
"""

INSECURE_TF = """
resource "aws_s3_bucket_acl" "public" {
  acl = "public-read"
}

resource "aws_security_group_rule" "all_inbound" {
  cidr_blocks = ["0.0.0.0/0"]
  type        = "ingress"
}

resource "aws_db_instance" "exposed" {
  publicly_accessible = true
  storage_encrypted   = false
}

resource "aws_iam_policy" "admin" {
  policy = <<-EOF
    {"Statement":[{"Action":"*","Effect":"Allow","Resource":"*"}]}
  EOF
}
"""

AZURE_CONFIG_SECURE = {
    "security_defaults_enabled": True,
    "mfa_conditional_access":    True,
    "legacy_auth_blocked":       True,
    "pim_enabled":               True,
    "sspr_enabled":              True,
    "guest_access_level":        "restricted",
    "user_consent_policy":       "disabled",
}

AZURE_CONFIG_INSECURE = {
    "security_defaults_enabled": False,
    "mfa_conditional_access":    False,
    "legacy_auth_blocked":       False,
    "pim_enabled":               False,
    "sspr_enabled":              False,
    "guest_access_level":        "unrestricted",
    "user_consent_policy":       "enabled",
}

GCP_POLICY_SAFE = {
    "bindings": [{
        "role":    "roles/storage.objectViewer",
        "members": ["serviceAccount:app@project.iam.gserviceaccount.com"],
    }]
}

GCP_POLICY_DANGEROUS = {
    "bindings": [
        {
            "role":    "roles/owner",
            "members": ["user:attacker@example.com"],
        },
        {
            "role":    "roles/storage.admin",
            "members": ["allUsers"],
        },
        {
            "role":    "roles/editor",
            "members": ["user:bob@example.com"],
        },
    ]
}


# ── Fixtures ──────────────────────────────────────────────

@pytest.fixture
def iam_analyzer(tmp_path):
    return AWSIAMAnalyzer(output_dir=str(tmp_path))


@pytest.fixture
def tf_scanner(tmp_path):
    return TerraformScanner(output_dir=str(tmp_path))


@pytest.fixture
def azure_scanner(tmp_path):
    return AzureADScanner(
        tenant_id="test-tenant-id",
        output_dir=str(tmp_path),
    )


@pytest.fixture
def gcp_analyzer(tmp_path):
    return GCPIAMAnalyzer(output_dir=str(tmp_path))


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


# ── Tests: AWSIAMAnalyzer ─────────────────────────────────

class TestAWSIAMAnalyzer:

    @pytest.mark.unit
    def test_init(self, iam_analyzer):
        assert iam_analyzer.output_dir.exists()

    @pytest.mark.unit
    def test_wildcard_action_critical(self, iam_analyzer):
        findings = iam_analyzer.analyze_policy_document(admin_policy(), "arn:aws:iam::123:user/test")
        critical = [f for f in findings if f["severity"] == "CRITICAL"]
        assert len(critical) >= 1

    @pytest.mark.unit
    def test_safe_policy_no_critical(self, iam_analyzer):
        findings = iam_analyzer.analyze_policy_document(safe_policy(), "user/safe")
        critical = [f for f in findings if f["severity"] == "CRITICAL"]
        assert len(critical) == 0

    @pytest.mark.unit
    def test_privesc_permission_detected(self, iam_analyzer):
        findings = iam_analyzer.analyze_policy_document(privesc_policy(), "user/test")
        privesc  = [f for f in findings if "Privilege Escalation" in f["title"]]
        assert len(privesc) >= 1

    @pytest.mark.unit
    def test_privesc_requires_wildcard_resource(self, iam_analyzer):
        policy = {
            "Statement": [{
                "Effect":   "Allow",
                "Action":   ["iam:CreatePolicyVersion"],
                "Resource": "arn:aws:iam::123:policy/specific-policy",
            }]
        }
        findings = iam_analyzer.analyze_policy_document(policy, "user/test")
        privesc = [f for f in findings if "Privilege Escalation" in f["title"]]
        assert len(privesc) == 0  # No wildcard resource = no escalation

    @pytest.mark.unit
    def test_deny_statements_ignored(self, iam_analyzer):
        policy = {
            "Statement": [{
                "Effect":   "Deny",
                "Action":   "*",
                "Resource": "*",
            }]
        }
        findings = iam_analyzer.analyze_policy_document(policy, "user/test")
        assert findings == []

    @pytest.mark.unit
    def test_find_privesc_paths_admin_policy(self, iam_analyzer):
        iam_data = {
            "users": [{
                "Arn": "arn:aws:iam::123:user/admin-user",
                "AttachedPolicies": [{
                    "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess"
                }],
            }]
        }
        paths = iam_analyzer.find_privesc_paths(iam_data)
        admin = [p for p in paths if p.method == "admin_policy"]
        assert len(admin) >= 1
        assert admin[0].severity == "CRITICAL"

    @pytest.mark.unit
    def test_trust_policy_wildcard_critical(self, iam_analyzer):
        findings = iam_analyzer.check_trust_policy("PrivilegedRole", trust_policy_wildcard())
        wildcard = [f for f in findings if "Wildcard" in f["title"]]
        assert len(wildcard) >= 1
        assert wildcard[0]["severity"] == "CRITICAL"

    @pytest.mark.unit
    def test_trust_policy_cross_account_no_condition(self, iam_analyzer):
        findings = iam_analyzer.check_trust_policy("CrossAccountRole", trust_policy_cross_account())
        cross = [f for f in findings if "Cross-Account" in f["title"]]
        assert len(cross) >= 1
        assert cross[0]["severity"] == "MEDIUM"

    @pytest.mark.unit
    def test_save_creates_file(self, iam_analyzer, tmp_path):
        path = iam_analyzer._save([])
        assert path.exists()

    @pytest.mark.unit
    def test_privesc_permissions_not_empty(self):
        assert len(IAM_PRIVESC_PERMISSIONS) >= 15
        perms = [p[0] for p in IAM_PRIVESC_PERMISSIONS]
        assert "iam:CreatePolicyVersion" in perms
        assert "iam:AttachUserPolicy"    in perms


# ── Tests: TerraformScanner ───────────────────────────────

class TestTerraformScanner:

    @pytest.mark.unit
    def test_init(self, tf_scanner):
        assert tf_scanner.output_dir.exists()

    @pytest.mark.unit
    def test_safe_tf_no_high_findings(self, tf_scanner):
        findings = tf_scanner.scan_content(SAFE_TF, "main.tf")
        high_or_critical = [f for f in findings if f["severity"] in ("CRITICAL", "HIGH")]
        assert len(high_or_critical) == 0

    @pytest.mark.unit
    def test_public_acl_critical(self, tf_scanner):
        findings = tf_scanner.scan_content(INSECURE_TF, "main.tf")
        acl = [f for f in findings if "Public ACL" in f["title"]]
        assert len(acl) >= 1
        assert acl[0]["severity"] == "CRITICAL"

    @pytest.mark.unit
    def test_open_security_group_detected(self, tf_scanner):
        findings = tf_scanner.scan_content(INSECURE_TF, "main.tf")
        sg = [f for f in findings if "0.0.0.0/0" in f["title"] or "Internet" in f["title"]]
        assert len(sg) >= 1

    @pytest.mark.unit
    def test_rds_public_critical(self, tf_scanner):
        findings = tf_scanner.scan_content(INSECURE_TF, "main.tf")
        rds = [f for f in findings if "RDS" in f["title"] and "Accessible" in f["title"]]
        assert len(rds) >= 1
        assert rds[0]["severity"] == "CRITICAL"

    @pytest.mark.unit
    def test_rds_unencrypted_detected(self, tf_scanner):
        findings = tf_scanner.scan_content(INSECURE_TF, "main.tf")
        enc = [f for f in findings if "Encrypted" in f["title"] or "encrypted" in f["title"].lower()]
        assert len(enc) >= 1

    @pytest.mark.unit
    def test_iam_wildcard_action_detected(self, tf_scanner):
        findings = tf_scanner.scan_content(INSECURE_TF, "main.tf")
        iam = [f for f in findings if "Wildcard Action" in f["title"] or "Wildcard" in f["title"]]
        assert len(iam) >= 1

    @pytest.mark.unit
    def test_hardcoded_aws_key(self, tf_scanner):
        tf = 'access_key = "AKIAIOSFODNN7EXAMPLEKEY"\n'
        findings = tf_scanner._check_secrets(tf, "main.tf")
        assert len(findings) >= 1
        assert findings[0]["severity"] == "CRITICAL"

    @pytest.mark.unit
    def test_hardcoded_password(self, tf_scanner):
        tf = 'password = "mysupersecretpassword"\n'
        findings = tf_scanner._check_secrets(tf, "main.tf")
        assert len(findings) >= 1

    @pytest.mark.unit
    def test_scan_directory_not_found(self, tf_scanner):
        findings = tf_scanner.scan_directory("/nonexistent/path")
        assert findings == []

    @pytest.mark.unit
    def test_scan_directory_with_files(self, tf_scanner, tmp_path):
        tf_file = tmp_path / "main.tf"
        tf_file.write_text(INSECURE_TF)
        findings = tf_scanner.scan_directory(str(tmp_path))
        assert len(findings) >= 1

    @pytest.mark.unit
    def test_terraform_checks_not_empty(self):
        assert len(TERRAFORM_CHECKS) >= 10
        resource_types = [c[0] for c in TERRAFORM_CHECKS]
        assert "aws_s3_bucket_acl"    in resource_types
        assert "aws_security_group_rule" in resource_types
        assert "aws_db_instance"      in resource_types


# ── Tests: AzureADScanner ────────────────────────────────

class TestAzureADScanner:

    @pytest.mark.unit
    def test_init(self, azure_scanner):
        assert azure_scanner.tenant_id == "test-tenant-id"
        assert azure_scanner.output_dir.exists()

    @pytest.mark.unit
    def test_secure_config_no_critical(self, azure_scanner):
        findings = azure_scanner.analyze_config(AZURE_CONFIG_SECURE)
        critical = [f for f in findings if f["severity"] == "CRITICAL"]
        assert len(critical) == 0

    @pytest.mark.unit
    def test_mfa_not_required_critical(self, azure_scanner):
        config   = {"mfa_conditional_access": False}
        findings = azure_scanner.analyze_config(config)
        mfa      = [f for f in findings if "MFA" in f["title"]]
        assert len(mfa) >= 1
        assert mfa[0]["severity"] == "CRITICAL"

    @pytest.mark.unit
    def test_legacy_auth_high(self, azure_scanner):
        config   = {"legacy_auth_blocked": False}
        findings = azure_scanner.analyze_config(config)
        legacy   = [f for f in findings if "Legacy" in f["title"]]
        assert len(legacy) >= 1
        assert legacy[0]["severity"] == "HIGH"

    @pytest.mark.unit
    def test_security_defaults_disabled(self, azure_scanner):
        config   = {"security_defaults_enabled": False}
        findings = azure_scanner.analyze_config(config)
        sd       = [f for f in findings if "Security Defaults" in f["title"]]
        assert len(sd) >= 1

    @pytest.mark.unit
    def test_guest_unrestricted_detected(self, azure_scanner):
        config   = {"guest_access_level": "unrestricted"}
        findings = azure_scanner.analyze_config(config)
        guest    = [f for f in findings if "Guest" in f["title"]]
        assert len(guest) >= 1

    @pytest.mark.unit
    def test_app_consent_unrestricted(self, azure_scanner):
        config   = {"user_consent_policy": "enabled"}
        findings = azure_scanner.analyze_config(config)
        consent  = [f for f in findings if "Consent" in f["title"]]
        assert len(consent) >= 1
        assert consent[0]["severity"] == "HIGH"

    @pytest.mark.unit
    def test_insecure_config_many_findings(self, azure_scanner):
        findings = azure_scanner.analyze_config(AZURE_CONFIG_INSECURE)
        assert len(findings) >= 5

    @pytest.mark.unit
    def test_no_token_run_returns_empty(self, azure_scanner):
        result = azure_scanner.run()
        assert result == []

    @pytest.mark.unit
    def test_azure_checks_not_empty(self):
        assert len(AZURE_CHECKS) >= 6
        assert "mfa_not_required"       in AZURE_CHECKS
        assert "legacy_auth_enabled"    in AZURE_CHECKS
        assert "guest_user_access"      in AZURE_CHECKS


# ── Tests: GCPIAMAnalyzer ────────────────────────────────

class TestGCPIAMAnalyzer:

    @pytest.mark.unit
    def test_init(self, gcp_analyzer):
        assert gcp_analyzer.output_dir.exists()

    @pytest.mark.unit
    def test_safe_policy_no_critical(self, gcp_analyzer):
        findings = gcp_analyzer.analyze_policy(GCP_POLICY_SAFE, "my-project")
        critical = [f for f in findings if f["severity"] == "CRITICAL"]
        assert len(critical) == 0

    @pytest.mark.unit
    def test_allusers_critical(self, gcp_analyzer):
        policy   = {"bindings": [{"role": "roles/storage.admin", "members": ["allUsers"]}]}
        findings = gcp_analyzer.analyze_policy(policy, "my-project")
        public   = [f for f in findings if "Public Access" in f["title"]]
        assert len(public) >= 1
        assert public[0]["severity"] == "CRITICAL"

    @pytest.mark.unit
    def test_allauthenticatedusers_high(self, gcp_analyzer):
        policy   = {"bindings": [{"role": "roles/viewer", "members": ["allAuthenticatedUsers"]}]}
        findings = gcp_analyzer.analyze_policy(policy, "my-project")
        auth     = [f for f in findings if "allAuthenticatedUsers" in f["evidence"]]
        assert len(auth) >= 1
        assert auth[0]["severity"] == "HIGH"

    @pytest.mark.unit
    def test_owner_role_critical(self, gcp_analyzer):
        policy   = {"bindings": [{"role": "roles/owner", "members": ["user:admin@corp.com"]}]}
        findings = gcp_analyzer.analyze_policy(policy, "my-project")
        owner    = [f for f in findings if "roles/owner" in f["title"] or "Primitive" in f["title"]]
        assert len(owner) >= 1

    @pytest.mark.unit
    def test_editor_role_high(self, gcp_analyzer):
        policy   = {"bindings": [{"role": "roles/editor", "members": ["user:bob@corp.com"]}]}
        findings = gcp_analyzer.analyze_policy(policy, "my-project")
        editor   = [f for f in findings if "editor" in f["title"].lower() or "Primitive" in f["title"]]
        assert len(editor) >= 1

    @pytest.mark.unit
    def test_service_account_key_admin(self, gcp_analyzer):
        policy = {"bindings": [{
            "role":    "roles/iam.serviceAccountKeyAdmin",
            "members": ["serviceAccount:app@project.iam.gserviceaccount.com"],
        }]}
        findings = gcp_analyzer.analyze_policy(policy, "my-project")
        sa_key   = [f for f in findings if "Service Account Key" in f["title"]]
        assert len(sa_key) >= 1

    @pytest.mark.unit
    def test_dangerous_policy_multiple_findings(self, gcp_analyzer):
        findings = gcp_analyzer.analyze_policy(GCP_POLICY_DANGEROUS, "my-project")
        assert len(findings) >= 3

    @pytest.mark.unit
    def test_analyze_org_policy_missing_constraints(self, gcp_analyzer):
        findings = gcp_analyzer.analyze_org_policy([], "123456789")
        assert len(findings) >= 3  # Multiple missing constraints

    @pytest.mark.unit
    def test_analyze_org_policy_with_constraint(self, gcp_analyzer):
        policies = [{"name": "constraints/iam.disableServiceAccountKeyCreation"}]
        findings = gcp_analyzer.analyze_org_policy(policies, "123456789")
        # One constraint present = fewer findings
        all_findings = gcp_analyzer.analyze_org_policy([], "123456789")
        assert len(findings) < len(all_findings)

    @pytest.mark.unit
    def test_service_accounts_not_flagged_for_primitive_roles(self, gcp_analyzer):
        # Service accounts assigned owner is less severe than users
        policy = {"bindings": [{
            "role": "roles/owner",
            "members": ["serviceAccount:deploy@project.iam.gserviceaccount.com"],
        }]}
        findings = gcp_analyzer.analyze_policy(policy, "my-project")
        # SA-only members should not trigger the "human members" check
        human_owner = [f for f in findings
                       if "Overprivileged" in f["title"] and "roles/owner" in f["title"]]
        assert len(human_owner) == 0

    @pytest.mark.unit
    def test_dangerous_gcp_roles_not_empty(self):
        assert len(DANGEROUS_GCP_ROLES) >= 8
        assert "roles/owner"    in DANGEROUS_GCP_ROLES
        assert "roles/editor"   in DANGEROUS_GCP_ROLES
        assert "roles/iam.admin" in DANGEROUS_GCP_ROLES

    @pytest.mark.unit
    def test_dangerous_members_not_empty(self):
        assert "allUsers"              in DANGEROUS_GCP_MEMBERS
        assert "allAuthenticatedUsers" in DANGEROUS_GCP_MEMBERS

    @pytest.mark.unit
    def test_primitive_roles_set(self):
        assert "roles/owner"  in GCP_PRIMITIVE_ROLES
        assert "roles/editor" in GCP_PRIMITIVE_ROLES
        assert "roles/viewer" in GCP_PRIMITIVE_ROLES
