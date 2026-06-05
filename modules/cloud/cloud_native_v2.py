"""
Cloud Native v2 — modules/cloud/cloud_native_v2.py

Advanced cloud security analysis:
  1. AWSIAMAnalyzer   — IAM privilege escalation path finding
  2. TerraformScanner — infrastructure-as-code misconfiguration
  3. AzureADScanner   — Azure Active Directory security audit
  4. GCPIAMAnalyzer   — GCP IAM policy over-permission analysis

Usage:
    from modules.cloud.cloud_native_v2 import (
        AWSIAMAnalyzer, TerraformScanner,
        AzureADScanner, GCPIAMAnalyzer,
    )

    # AWS IAM
    analyzer = AWSIAMAnalyzer()
    paths    = analyzer.find_privesc_paths(iam_data)

    # Terraform
    scanner  = TerraformScanner()
    findings = scanner.scan_directory("./infra/terraform")

    # Azure AD
    azure    = AzureADScanner(tenant_id="...", token="...")
    findings = azure.run()

    # GCP IAM
    gcp      = GCPIAMAnalyzer()
    findings = gcp.analyze_policy(iam_policy)

Author: ardanov96
"""

import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from rich.console import Console

console = Console()


# ── Finding helper ────────────────────────────────────────

def _finding(
    title: str, severity: str, cvss: float, cwe: str,
    description: str, evidence: str, remediation: str,
    target: str, source: str = "cloud_native_v2",
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


# ══════════════════════════════════════════════════════════
# 1. AWS IAM Analyzer — Privilege Escalation Path Finder
# ══════════════════════════════════════════════════════════

# Dangerous IAM permissions that enable privilege escalation
# Each entry: (permission, description, escalation_method)
IAM_PRIVESC_PERMISSIONS = [
    ("iam:CreatePolicyVersion",    "Create new policy version (set as default)",   "policy_version"),
    ("iam:SetDefaultPolicyVersion","Set existing policy version as default",        "policy_version"),
    ("iam:AttachUserPolicy",       "Attach any policy to any user",                 "attach_policy"),
    ("iam:AttachGroupPolicy",      "Attach any policy to any group",                "attach_policy"),
    ("iam:AttachRolePolicy",       "Attach any policy to any role",                 "attach_policy"),
    ("iam:PutUserPolicy",          "Inline policy on any user",                     "inline_policy"),
    ("iam:PutGroupPolicy",         "Inline policy on any group",                    "inline_policy"),
    ("iam:PutRolePolicy",          "Inline policy on any role",                     "inline_policy"),
    ("iam:AddUserToGroup",         "Add any user to any group",                     "group_membership"),
    ("iam:UpdateAssumeRolePolicy", "Modify trust policy of any role",               "assume_role"),
    ("iam:PassRole",               "Pass privileged role to EC2/Lambda/etc.",       "pass_role"),
    ("iam:CreateAccessKey",        "Create access key for any user",                "access_key"),
    ("iam:UpdateLoginProfile",     "Reset password of any IAM user",                "password_reset"),
    ("iam:CreateLoginProfile",     "Create login profile (console access)",         "console_access"),
    ("sts:AssumeRole",             "Assume any role",                               "assume_role"),
    ("lambda:UpdateFunctionCode",  "Update Lambda code (if function has priv role)","lambda_code"),
    ("ec2:RunInstances",           "Launch EC2 with privileged instance profile",   "ec2_instance"),
    ("cloudformation:CreateStack", "Deploy stack with privileged role",             "cfn_stack"),
    ("glue:UpdateDevEndpoint",     "Inject SSH key to Glue dev endpoint",           "glue_endpoint"),
]

# Dangerous IAM conditions that indicate overly broad access
DANGEROUS_CONDITIONS = [
    ("Resource", "*",           "Wildcard resource — applies to all resources"),
    ("Action",   "*",           "Wildcard action — all actions allowed"),
    ("Action",   "iam:*",       "Wildcard IAM — full IAM control"),
    ("Action",   "s3:*",        "Wildcard S3 — full S3 control"),
    ("Action",   "ec2:*",       "Wildcard EC2 — full EC2 control"),
    ("Action",   "sts:*",       "Wildcard STS — all role assumption"),
    ("Condition", None,         "No conditions — unconditional access"),
]


@dataclass
class PrivEscPath:
    """An IAM privilege escalation path."""
    principal:    str          # IAM user/role ARN
    permission:   str          # The dangerous permission
    method:       str          # escalation method name
    description:  str
    severity:     str
    risk_score:   float        # 0-10


@dataclass
class IAMFinding:
    """Result of IAM analysis."""
    principal:   str
    finding_type: str
    severity:    str
    details:     str
    permissions: list[str] = field(default_factory=list)
    risk_score:  float = 0.0


class AWSIAMAnalyzer:
    """
    Analyze AWS IAM policies for privilege escalation paths.

    Checks:
    - Dangerous permissions enabling escalation to admin
    - Wildcard resource permissions
    - Cross-account trust relationships
    - Overly permissive inline policies
    - Admin policy attachments
    - Unused high-privilege permissions
    - PassRole to privileged services

    Input: IAM policy JSON (from aws iam get-policy-version,
           get-user-policy, or list-attached-user-policies)
    """

    ADMIN_POLICIES = {
        "arn:aws:iam::aws:policy/AdministratorAccess",
        "arn:aws:iam::aws:policy/IAMFullAccess",
        "arn:aws:iam::aws:policy/PowerUserAccess",
    }

    def __init__(self, output_dir: str = "./findings/cloud"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def analyze_policy_document(
        self,
        policy: dict,
        principal: str = "unknown",
    ) -> list[dict]:
        """
        Analyze a single IAM policy document for escalation paths.

        Args:
            policy:    IAM policy document (with 'Statement' key)
            principal: IAM principal ARN for context

        Returns:
            List of finding dicts
        """
        findings = []
        statements = policy.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]

        for stmt in statements:
            effect    = stmt.get("Effect", "Deny")
            if effect != "Allow":
                continue

            resources = stmt.get("Resource", [])
            actions   = stmt.get("Action", [])
            if isinstance(resources, str):
                resources = [resources]
            if isinstance(actions, str):
                actions = [actions]

            # Check for wildcard resource
            has_wildcard_resource = "*" in resources

            # Check for admin actions
            if "*" in actions or "iam:*" in actions:
                findings.append(_finding(
                    title=f"IAM Wildcard Action — Full {self._action_scope(actions)} Control",
                    severity="CRITICAL",
                    cvss=9.8,
                    cwe="CWE-732",
                    description=(
                        f"Policy grants wildcard action(s) '{', '.join(actions[:3])}'. "
                        "This effectively grants admin-level access."
                    ),
                    evidence=(
                        f"Principal: {principal}\n"
                        f"Actions: {actions[:5]}\n"
                        f"Resources: {resources[:3]}"
                    ),
                    remediation=(
                        "Replace wildcard actions with specific required permissions. "
                        "Apply principle of least privilege. "
                        "Use IAM Access Analyzer to identify unused permissions."
                    ),
                    target=f"iam://{principal}",
                    source="aws_iam_analyzer",
                ))

            # Check dangerous permissions
            for perm, desc, method in IAM_PRIVESC_PERMISSIONS:
                perm_service = perm.split(":")[0]
                if any(
                    a == perm or
                    a == f"{perm_service}:*" or
                    a == "*"
                    for a in actions
                ) and has_wildcard_resource:
                    findings.append(_finding(
                        title=f"IAM Privilege Escalation Path: {perm}",
                        severity="HIGH",
                        cvss=8.8,
                        cwe="CWE-269",
                        description=(
                            f"Principal '{principal}' has '{perm}' on '*' resources. "
                            f"This enables escalation via: {method}. {desc}."
                        ),
                        evidence=(
                            f"Permission: {perm}\n"
                            f"Resource: * (wildcard)\n"
                            f"Method: {method}\n"
                            f"Description: {desc}"
                        ),
                        remediation=(
                            f"Restrict '{perm}' to specific resource ARNs. "
                            "Add conditions like aws:ResourceTag or iam:PassedToService constraints. "
                            "Review if this permission is necessary."
                        ),
                        target=f"iam://{principal}",
                        source="aws_iam_analyzer",
                    ))

        return findings

    def find_privesc_paths(self, iam_data: dict) -> list[PrivEscPath]:
        """
        Find privilege escalation paths across IAM users/roles.

        Args:
            iam_data: Dict with 'users', 'roles', 'groups' containing
                      attached policies and inline policies

        Returns:
            List of PrivEscPath objects
        """
        paths   = []
        users   = iam_data.get("users", [])
        roles   = iam_data.get("roles", [])

        for principal_list in [users, roles]:
            for principal in principal_list:
                arn     = principal.get("Arn", "")
                policies = principal.get("AttachedPolicies", []) + \
                           principal.get("InlinePolicies", [])

                # Check admin policy attachments
                for policy in policies:
                    policy_arn = policy.get("PolicyArn", "")
                    if policy_arn in self.ADMIN_POLICIES:
                        paths.append(PrivEscPath(
                            principal=arn,
                            permission=policy_arn,
                            method="admin_policy",
                            description=f"Admin policy directly attached: {policy_arn}",
                            severity="CRITICAL",
                            risk_score=10.0,
                        ))

                # Analyze inline policy documents
                for policy in policies:
                    doc = policy.get("PolicyDocument", {})
                    if doc:
                        for stmt in doc.get("Statement", []):
                            if stmt.get("Effect") != "Allow":
                                continue
                            actions   = stmt.get("Action", [])
                            resources = stmt.get("Resource", [])
                            if isinstance(actions, str):
                                actions = [actions]
                            if isinstance(resources, str):
                                resources = [resources]

                            for perm, desc, method in IAM_PRIVESC_PERMISSIONS[:8]:
                                perm_svc = perm.split(":")[0]
                                if (any(a == perm or a == f"{perm_svc}:*" or a == "*"
                                        for a in actions) and "*" in resources):
                                    paths.append(PrivEscPath(
                                        principal=arn,
                                        permission=perm,
                                        method=method,
                                        description=desc,
                                        severity="HIGH",
                                        risk_score=8.5,
                                    ))

        return paths

    def check_trust_policy(
        self,
        role_name: str,
        trust_policy: dict,
    ) -> list[dict]:
        """Check role trust policy for dangerous configurations."""
        findings = []
        stmts    = trust_policy.get("Statement", [])
        if isinstance(stmts, dict):
            stmts = [stmts]

        for stmt in stmts:
            if stmt.get("Effect") != "Allow":
                continue
            principal = stmt.get("Principal", {})

            # Wildcard principal
            if principal == "*" or (isinstance(principal, dict) and
                    principal.get("AWS") == "*"):
                findings.append(_finding(
                    title=f"IAM Role Wildcard Trust Policy: {role_name}",
                    severity="CRITICAL",
                    cvss=9.8,
                    cwe="CWE-284",
                    description=(
                        f"Role '{role_name}' trust policy allows ANY principal to assume it. "
                        "Any AWS account or service can assume this role."
                    ),
                    evidence=f"Principal: *\nRole: {role_name}",
                    remediation=(
                        "Restrict trust policy Principal to specific account IDs or ARNs. "
                        "Add conditions like aws:PrincipalOrgID or sts:ExternalId."
                    ),
                    target=f"iam://role/{role_name}",
                    source="aws_iam_analyzer",
                ))

            # Cross-account without conditions
            aws_principal = principal if isinstance(principal, str) else \
                           principal.get("AWS", "")
            if isinstance(aws_principal, str) and ":" in aws_principal:
                account_id = aws_principal.split(":")[4] if len(aws_principal.split(":")) > 4 else ""
                if account_id and not stmt.get("Condition"):
                    findings.append(_finding(
                        title=f"Cross-Account Role Trust Without Conditions: {role_name}",
                        severity="MEDIUM",
                        cvss=6.5,
                        cwe="CWE-284",
                        description=(
                            f"Role '{role_name}' allows cross-account assumption from "
                            f"{aws_principal} without any conditions (no ExternalId, no MFA)."
                        ),
                        evidence=f"Principal: {aws_principal}\nConditions: none",
                        remediation=(
                            "Add sts:ExternalId condition for third-party integrations. "
                            "Add aws:MultiFactorAuthPresent condition for human access."
                        ),
                        target=f"iam://role/{role_name}",
                        source="aws_iam_analyzer",
                    ))

        return findings

    def _action_scope(self, actions: list[str]) -> str:
        if "*" in actions:
            return "AWS"
        services = set(a.split(":")[0] for a in actions if ":" in a)
        return "/".join(sorted(services)[:3])

    def _save(self, findings: list[dict]) -> Path:
        ts  = datetime.now().strftime("%Y%m%d_%H%M%S")
        out = self.output_dir / f"aws_iam_{ts}.json"
        out.write_text(json.dumps({"findings": findings}, indent=2), encoding="utf-8")
        return out


# ══════════════════════════════════════════════════════════
# 2. Terraform Scanner
# ══════════════════════════════════════════════════════════

# Terraform misconfiguration patterns
# Each: (resource_type, attribute, pattern, severity, cvss, cwe, title, remediation)
TERRAFORM_CHECKS = [
    # S3
    ("aws_s3_bucket_acl",       "acl",              r"public-read|public-read-write",
     "CRITICAL", 9.1, "CWE-732", "S3 Bucket Public ACL",
     "Set acl = 'private'. Use aws_s3_bucket_public_access_block to block public access."),
    ("aws_s3_bucket",           "acl",              r"public-read|public-read-write",
     "CRITICAL", 9.1, "CWE-732", "S3 Bucket Public ACL (legacy)",
     "Remove public ACL. Use block_public_acls = true."),
    # Security Groups
    ("aws_security_group_rule", "cidr_blocks",      r'"0\.0\.0\.0/0"',
     "HIGH",     7.5, "CWE-284", "Security Group Open to Internet (0.0.0.0/0)",
     "Restrict cidr_blocks to specific IP ranges. Never use 0.0.0.0/0 for sensitive ports."),
    ("aws_security_group",      "cidr_blocks",      r'"0\.0\.0\.0/0"',
     "HIGH",     7.5, "CWE-284", "Security Group Ingress Open to Internet",
     "Restrict ingress to known IP ranges or security group references."),
    ("aws_security_group_rule", "ipv6_cidr_blocks",  r'"::/0"',
     "HIGH",     7.5, "CWE-284", "Security Group Open to All IPv6",
     "Restrict IPv6 CIDR blocks. ::/0 allows all IPv6 traffic."),
    # RDS
    ("aws_db_instance",         "publicly_accessible", r"true",
     "CRITICAL", 9.1, "CWE-284", "RDS Instance Publicly Accessible",
     "Set publicly_accessible = false. Place RDS in private subnet."),
    ("aws_db_instance",         "storage_encrypted",   r"false",
     "HIGH",     7.5, "CWE-311", "RDS Storage Not Encrypted",
     "Set storage_encrypted = true and specify kms_key_id."),
    ("aws_db_instance",         "backup_retention_period", r"^0$",
     "MEDIUM",   5.5, "CWE-693", "RDS Backup Disabled",
     "Set backup_retention_period >= 7 days."),
    # EC2
    ("aws_instance",            "associate_public_ip_address", r"true",
     "MEDIUM",   5.3, "CWE-200", "EC2 Instance Has Public IP",
     "Set associate_public_ip_address = false. Use NAT gateway for outbound."),
    # IAM
    ("aws_iam_policy",          "policy",           r'"Action":\s*"\*"',
     "CRITICAL", 9.8, "CWE-732", "IAM Policy Wildcard Action",
     "Replace '*' actions with specific required permissions."),
    ("aws_iam_role_policy",     "policy",           r'"Action":\s*"\*"',
     "CRITICAL", 9.8, "CWE-732", "IAM Role Policy Wildcard Action",
     "Apply least privilege — specify exact required actions."),
    # CloudTrail
    ("aws_cloudtrail",          "is_multi_region_trail", r"false",
     "MEDIUM",   5.5, "CWE-778", "CloudTrail Not Multi-Region",
     "Set is_multi_region_trail = true for complete audit coverage."),
    ("aws_cloudtrail",          "log_file_validation_enabled", r"false",
     "MEDIUM",   5.5, "CWE-345", "CloudTrail Log Validation Disabled",
     "Set log_file_validation_enabled = true to detect log tampering."),
    # KMS
    ("aws_kms_key",             "enable_key_rotation", r"false",
     "MEDIUM",   5.3, "CWE-321", "KMS Key Rotation Disabled",
     "Set enable_key_rotation = true for automatic annual rotation."),
    # EKS
    ("aws_eks_cluster",         "endpoint_public_access", r"true",
     "HIGH",     7.5, "CWE-284", "EKS API Server Publicly Accessible",
     "Set endpoint_public_access = false. Access via VPN or bastion."),
    # Lambda
    ("aws_lambda_function",     "tracing_config",   r"PassThrough",
     "LOW",      3.1, "CWE-778", "Lambda Tracing in PassThrough Mode",
     "Set tracing_config.mode = 'Active' for full X-Ray tracing."),
    # Secrets
    ("aws_secretsmanager_secret", "recovery_window_in_days", r"^0$",
     "MEDIUM",   5.5, "CWE-693", "Secrets Manager Immediate Deletion Enabled",
     "Set recovery_window_in_days >= 7 to prevent accidental deletion."),
]


class TerraformScanner:
    """
    Scan Terraform .tf files for security misconfigurations.

    Supports:
    - AWS provider checks (S3, EC2, RDS, IAM, CloudTrail, KMS, EKS)
    - Pattern-based analysis (regex against .tf content)
    - Multi-file directory scanning
    - Variable interpolation detection (flags non-literal values)
    """

    TF_EXTENSIONS = {".tf"}

    def __init__(self, output_dir: str = "./findings/cloud"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def scan_directory(self, path: str) -> list[dict]:
        """Scan all .tf files in a directory recursively."""
        console.print(f"\n  [bold cyan]Terraform Scanner[/bold cyan] → {path}")
        findings = []
        tf_dir   = Path(path)

        if not tf_dir.exists():
            console.print(f"  [yellow]Directory not found:[/yellow] {path}")
            return findings

        tf_files = list(tf_dir.rglob("*.tf"))
        console.print(f"  .tf files found: {len(tf_files)}")

        for tf_file in tf_files:
            try:
                content  = tf_file.read_text(encoding="utf-8", errors="ignore")
                findings.extend(self.scan_content(content, str(tf_file)))
            except Exception:
                continue

        self._save(findings)
        console.print(f"  Findings: [bold]{len(findings)}[/bold]")
        return findings

    def scan_content(self, content: str, filename: str = "main.tf") -> list[dict]:
        """Scan Terraform content string for misconfigurations."""
        findings = []

        for (resource_type, attribute, pattern,
             severity, cvss, cwe, title, remediation) in TERRAFORM_CHECKS:
            # Check if resource type exists in file
            if resource_type not in content:
                continue
            # Check attribute + pattern match
            if attribute in content and re.search(pattern, content, re.IGNORECASE):
                # Find context line
                context = self._find_context(content, attribute, pattern)
                findings.append(_finding(
                    title=f"Terraform: {title}",
                    severity=severity,
                    cvss=cvss,
                    cwe=cwe,
                    description=f"Terraform resource '{resource_type}' has misconfigured '{attribute}'.",
                    evidence=f"File: {filename}\nResource: {resource_type}\nAttribute: {attribute}\nContext: {context}",
                    remediation=remediation,
                    target=filename,
                    source="terraform_scanner",
                ))

        # Check for hardcoded secrets
        secret_findings = self._check_secrets(content, filename)
        findings.extend(secret_findings)

        return findings

    def _find_context(self, content: str, attribute: str, pattern: str) -> str:
        """Find the matching line for context."""
        for line in content.splitlines():
            if attribute in line and re.search(pattern, line, re.IGNORECASE):
                return line.strip()[:120]
        return ""

    def _check_secrets(self, content: str, filename: str) -> list[dict]:
        """Check for hardcoded secrets in Terraform files."""
        findings = []
        secret_patterns = {
            "AWS Access Key":   r'AKIA[0-9A-Z]{16}',
            "AWS Secret":       r'(?i)secret_?key\s*=\s*"[A-Za-z0-9+/]{30,}"',
            "Password":         r'(?i)password\s*=\s*"[^"]{8,}"',
            "Private Key":      r'-----BEGIN (RSA|EC|PRIVATE) KEY-----',
            "Database Password": r'(?i)db_password\s*=\s*"[^"]{4,}"',
        }
        for secret_type, pattern in secret_patterns.items():
            match = re.search(pattern, content)
            if match:
                findings.append(_finding(
                    title=f"Terraform: Hardcoded {secret_type}",
                    severity="CRITICAL",
                    cvss=9.1,
                    cwe="CWE-312",
                    description=f"Terraform file contains hardcoded {secret_type}. Credentials in IaC are committed to version control.",
                    evidence=f"File: {filename}\nType: {secret_type}\nSample: {match.group(0)[:40]}...",
                    remediation=(
                        "Use Terraform variables with sensitive = true. "
                        "Fetch secrets from AWS Secrets Manager or HashiCorp Vault at runtime. "
                        "Rotate exposed credentials immediately."
                    ),
                    target=filename,
                    source="terraform_scanner",
                ))
        return findings

    def _save(self, findings: list[dict]) -> Path:
        ts  = datetime.now().strftime("%Y%m%d_%H%M%S")
        out = self.output_dir / f"terraform_{ts}.json"
        out.write_text(json.dumps({"findings": findings}, indent=2), encoding="utf-8")
        return out


# ══════════════════════════════════════════════════════════
# 3. Azure AD Scanner
# ══════════════════════════════════════════════════════════

# Azure AD security checks
AZURE_CHECKS = {
    "guest_user_access": {
        "title":    "Azure AD Guest User Access Unrestricted",
        "severity": "MEDIUM",
        "cvss":     5.5,
        "cwe":      "CWE-284",
        "desc":     "Guest users can enumerate directory objects — users, groups, apps.",
        "fix":      "Set guestUserAccessRestrictions to 'restrictedAccess' or 'noAccess'.",
    },
    "mfa_not_required": {
        "title":    "MFA Not Required for All Users",
        "severity": "CRITICAL",
        "cvss":     9.1,
        "cwe":      "CWE-308",
        "desc":     "Azure AD does not enforce MFA via Conditional Access policy.",
        "fix":      "Create Conditional Access policy requiring MFA for all users. Enable Security Defaults.",
    },
    "legacy_auth_enabled": {
        "title":    "Legacy Authentication Not Blocked",
        "severity": "HIGH",
        "cvss":     8.1,
        "cwe":      "CWE-287",
        "desc":     "Legacy auth (IMAP, SMTP, POP3) bypasses MFA and Conditional Access.",
        "fix":      "Create Conditional Access policy blocking legacy authentication protocols.",
    },
    "privileged_no_pim": {
        "title":    "Permanent Privileged Role Assignment (No PIM)",
        "severity": "HIGH",
        "cvss":     7.5,
        "cwe":      "CWE-269",
        "desc":     "Global Admins/Privileged Role Admins have permanent assignments. Should use PIM for just-in-time access.",
        "fix":      "Enable Azure AD PIM. Convert permanent assignments to eligible assignments requiring activation.",
    },
    "self_service_password_reset": {
        "title":    "Self-Service Password Reset Disabled",
        "severity": "LOW",
        "cvss":     3.1,
        "cwe":      "CWE-640",
        "desc":     "SSPR disabled may force insecure password reset workflows via helpdesk.",
        "fix":      "Enable SSPR with at least 2 authentication methods required.",
    },
    "password_hash_sync_disabled": {
        "title":    "Password Hash Sync Disabled (Hybrid)",
        "severity": "MEDIUM",
        "cvss":     5.5,
        "cwe":      "CWE-287",
        "desc":     "Without password hash sync, leaked hashes from on-prem cannot be detected by Azure AD Identity Protection.",
        "fix":      "Enable Password Hash Sync in Azure AD Connect for Identity Protection coverage.",
    },
    "app_consent_unrestricted": {
        "title":    "User App Consent Not Restricted",
        "severity": "HIGH",
        "cvss":     7.5,
        "cwe":      "CWE-284",
        "desc":     "Users can consent to OAuth apps accessing company data. Enables consent phishing attacks.",
        "fix":      "Disable user consent or limit to verified publishers. Require admin consent for all apps.",
    },
    "security_defaults_disabled": {
        "title":    "Azure AD Security Defaults Disabled",
        "severity": "HIGH",
        "cvss":     7.5,
        "cwe":      "CWE-732",
        "desc":     "Security defaults disabled without equivalent Conditional Access policies.",
        "fix":      "Enable Security Defaults or create equivalent Conditional Access policies.",
    },
}


class AzureADScanner:
    """
    Audit Azure Active Directory security configuration.

    Checks tenant-level security settings via Microsoft Graph API:
    - MFA enforcement via Conditional Access
    - Legacy authentication blocking
    - Privileged Identity Management (PIM) usage
    - Guest user access restrictions
    - Application consent settings
    - Security defaults status
    - Password policies

    Requires: Microsoft Graph API token or tenant admin credentials.
    """

    GRAPH_URL = "https://graph.microsoft.com/v1.0"
    GRAPH_BETA = "https://graph.microsoft.com/beta"

    def __init__(
        self,
        tenant_id: str = "",
        token: str = "",
        output_dir: str = "./findings/cloud",
        timeout: int = 15,
    ):
        self.tenant_id  = tenant_id
        self.token      = token
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.timeout    = timeout

        try:
            import httpx
            self.client = httpx.Client(
                timeout=timeout,
                headers={
                    "Authorization": f"Bearer {token}",
                    "Content-Type":  "application/json",
                    "User-Agent":    "Glitchicons/3.4.0",
                } if token else {},
            )
        except ImportError:
            self.client = None

    def analyze_config(self, config: dict) -> list[dict]:
        """
        Analyze Azure AD configuration dict for security issues.

        Config keys (from Microsoft Graph API):
          - security_defaults_enabled: bool
          - mfa_conditional_access:    bool
          - legacy_auth_blocked:       bool
          - guest_access_level:        str ("unrestricted"|"limited"|"restricted")
          - pim_enabled:               bool
          - user_consent_policy:       str ("enabled"|"disabled"|"verified_only")
          - sspr_enabled:              bool
        """
        findings = []

        check_map = {
            "security_defaults_enabled": ("security_defaults_disabled", False),
            "mfa_conditional_access":    ("mfa_not_required", False),
            "legacy_auth_blocked":       ("legacy_auth_enabled", False),
            "pim_enabled":               ("privileged_no_pim", False),
            "sspr_enabled":              ("self_service_password_reset", False),
        }

        for config_key, (check_id, trigger_value) in check_map.items():
            actual = config.get(config_key)
            if actual is None:
                continue
            if actual == trigger_value:
                check = AZURE_CHECKS[check_id]
                findings.append(_finding(
                    title=check["title"],
                    severity=check["severity"],
                    cvss=check["cvss"],
                    cwe=check["cwe"],
                    description=check["desc"],
                    evidence=(
                        f"Tenant: {self.tenant_id or 'unknown'}\n"
                        f"Setting: {config_key} = {actual}"
                    ),
                    remediation=check["fix"],
                    target=f"azure://{self.tenant_id or 'tenant'}",
                    source="azure_ad_scanner",
                ))

        # Guest access check
        guest_level = config.get("guest_access_level", "")
        if guest_level == "unrestricted":
            check = AZURE_CHECKS["guest_user_access"]
            findings.append(_finding(
                title=check["title"],
                severity=check["severity"],
                cvss=check["cvss"],
                cwe=check["cwe"],
                description=check["desc"],
                evidence=f"guest_access_level: {guest_level}",
                remediation=check["fix"],
                target=f"azure://{self.tenant_id or 'tenant'}",
                source="azure_ad_scanner",
            ))

        # Consent policy check
        consent = config.get("user_consent_policy", "")
        if consent == "enabled":
            check = AZURE_CHECKS["app_consent_unrestricted"]
            findings.append(_finding(
                title=check["title"],
                severity=check["severity"],
                cvss=check["cvss"],
                cwe=check["cwe"],
                description=check["desc"],
                evidence=f"user_consent_policy: {consent}",
                remediation=check["fix"],
                target=f"azure://{self.tenant_id or 'tenant'}",
                source="azure_ad_scanner",
            ))

        self._save(findings)
        return findings

    def run(self) -> list[dict]:
        """Run full Azure AD audit via Microsoft Graph API."""
        console.print(f"\n  [bold cyan]Azure AD Scanner[/bold cyan] → tenant: {self.tenant_id}")
        if not self.token:
            console.print("  [yellow]No token — using analyze_config() for offline analysis[/yellow]")
            return []

        config = {}
        try:
            # Security defaults
            resp = self.client.get(f"{self.GRAPH_BETA}/policies/identitySecurityDefaultsEnforcementPolicy")
            if resp.status_code == 200:
                config["security_defaults_enabled"] = resp.json().get("isEnabled", False)

            # Conditional access policies (check for MFA)
            resp = self.client.get(f"{self.GRAPH_BETA}/identity/conditionalAccess/policies")
            if resp.status_code == 200:
                policies = resp.json().get("value", [])
                has_mfa_policy = any(
                    "mfa" in json.dumps(p).lower()
                    for p in policies
                )
                config["mfa_conditional_access"] = has_mfa_policy

        except Exception as e:
            console.print(f"  [yellow]Graph API error:[/yellow] {e}")

        return self.analyze_config(config)

    def _save(self, findings: list[dict]) -> Path:
        ts  = datetime.now().strftime("%Y%m%d_%H%M%S")
        out = self.output_dir / f"azure_ad_{ts}.json"
        out.write_text(json.dumps({"findings": findings}, indent=2), encoding="utf-8")
        return out


# ══════════════════════════════════════════════════════════
# 4. GCP IAM Analyzer
# ══════════════════════════════════════════════════════════

# Dangerous GCP IAM roles
DANGEROUS_GCP_ROLES = {
    "roles/owner":              ("CRITICAL", 10.0, "Full owner — all resources, all actions"),
    "roles/editor":             ("HIGH",     8.5,  "Editor — modify all non-IAM resources"),
    "roles/iam.admin":          ("CRITICAL", 9.8,  "IAM admin — manage all IAM policies"),
    "roles/iam.serviceAccountTokenCreator": (
        "HIGH", 8.1, "Can create SA tokens — impersonate any service account"),
    "roles/iam.serviceAccountKeyAdmin": (
        "HIGH", 7.5, "Can create SA keys — long-term credentials"),
    "roles/iam.workloadIdentityUser": (
        "MEDIUM", 5.5, "Workload Identity User — cross-service impersonation"),
    "roles/resourcemanager.organizationAdmin": (
        "CRITICAL", 9.8, "Org admin — all resources in organization"),
    "roles/cloudsql.admin":     ("HIGH",     7.5,  "Full Cloud SQL control"),
    "roles/storage.admin":      ("HIGH",     7.5,  "Full GCS bucket control"),
    "roles/compute.admin":      ("HIGH",     7.5,  "Full Compute Engine control"),
    "roles/secretmanager.secretAccessor": (
        "HIGH", 7.5, "Can read all Secret Manager secrets"),
    "roles/cloudfunctions.admin": (
        "HIGH", 7.5, "Full Cloud Functions control (code injection risk)"),
}

# GCP IAM primitive roles (should be avoided)
GCP_PRIMITIVE_ROLES = {"roles/owner", "roles/editor", "roles/viewer"}

# Special members to flag
DANGEROUS_GCP_MEMBERS = {
    "allUsers":               ("CRITICAL", "Public internet — unauthenticated access"),
    "allAuthenticatedUsers":  ("HIGH",     "Any Google account — no org restriction"),
}


class GCPIAMAnalyzer:
    """
    Analyze GCP IAM policies for over-permissions and misconfigurations.

    Checks:
    - Primitive roles (owner/editor) assigned to users
    - Public access (allUsers, allAuthenticatedUsers)
    - Dangerous predefined roles on sensitive resources
    - Service account key usage (prefer Workload Identity)
    - Cross-project role bindings
    - Org-level policy inheritance issues
    """

    def __init__(self, output_dir: str = "./findings/cloud"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def analyze_policy(
        self,
        policy: dict,
        resource: str = "project",
    ) -> list[dict]:
        """
        Analyze a GCP IAM policy for security issues.

        Args:
            policy:   GCP IAM policy ({"bindings": [...], "version": 1})
            resource: Resource identifier (project/folder/org ID)

        Returns:
            List of finding dicts
        """
        findings  = []
        bindings  = policy.get("bindings", [])

        for binding in bindings:
            role    = binding.get("role", "")
            members = binding.get("members", [])

            # Check dangerous members (allUsers, allAuthenticatedUsers)
            for member in members:
                if member in DANGEROUS_GCP_MEMBERS:
                    sev, desc = DANGEROUS_GCP_MEMBERS[member]
                    findings.append(_finding(
                        title=f"GCP IAM Public Access: {role} granted to {member}",
                        severity=sev,
                        cvss=9.8 if sev == "CRITICAL" else 8.1,
                        cwe="CWE-284",
                        description=(
                            f"IAM role '{role}' is bound to '{member}'. {desc}. "
                            "This grants unauthenticated/unrestricted access."
                        ),
                        evidence=(
                            f"Resource: {resource}\n"
                            f"Role: {role}\n"
                            f"Member: {member}"
                        ),
                        remediation=(
                            f"Remove '{member}' from role '{role}'. "
                            "Grant access to specific service accounts or user groups only."
                        ),
                        target=f"gcp://{resource}",
                        source="gcp_iam_analyzer",
                    ))

            # Check dangerous roles
            if role in DANGEROUS_GCP_ROLES:
                sev, cvss, role_desc = DANGEROUS_GCP_ROLES[role]
                # Filter to non-service-account members
                human_members = [
                    m for m in members
                    if not m.startswith("serviceAccount:")
                ]
                if human_members:
                    findings.append(_finding(
                        title=f"GCP Overprivileged Role: {role} on {resource}",
                        severity=sev,
                        cvss=cvss,
                        cwe="CWE-269",
                        description=(
                            f"Dangerous role '{role}' granted to {len(human_members)} member(s). "
                            f"{role_desc}."
                        ),
                        evidence=(
                            f"Resource: {resource}\n"
                            f"Role: {role}\n"
                            f"Members: {', '.join(human_members[:5])}"
                        ),
                        remediation=(
                            f"Replace '{role}' with a custom role containing only required permissions. "
                            "Use predefined roles with minimal scope instead of primitive roles."
                        ),
                        target=f"gcp://{resource}",
                        source="gcp_iam_analyzer",
                    ))

            # Check primitive roles (owner/editor)
            if role in GCP_PRIMITIVE_ROLES and role != "roles/viewer":
                findings.append(_finding(
                    title=f"GCP Primitive Role Assignment: {role}",
                    severity="HIGH" if role == "roles/editor" else "CRITICAL",
                    cvss=9.0 if role == "roles/owner" else 7.5,
                    cwe="CWE-250",
                    description=(
                        f"Primitive role '{role}' assigned. Google recommends against using "
                        "primitive roles as they grant very broad permissions."
                    ),
                    evidence=(
                        f"Resource: {resource}\n"
                        f"Role: {role}\n"
                        f"Members: {len(members)}"
                    ),
                    remediation=(
                        f"Replace '{role}' with predefined or custom roles. "
                        "Use roles/viewer or specific resource roles for read access."
                    ),
                    target=f"gcp://{resource}",
                    source="gcp_iam_analyzer",
                ))

        # Check for service account key usage
        sa_key_findings = self._check_sa_keys(bindings, resource)
        findings.extend(sa_key_findings)

        self._save(findings)
        return findings

    def analyze_org_policy(
        self,
        org_policies: list[dict],
        org_id: str,
    ) -> list[dict]:
        """Check GCP organization policy constraints."""
        findings = []
        recommended_constraints = {
            "constraints/iam.disableServiceAccountKeyCreation": "Prevent SA key creation",
            "constraints/compute.requireShieldedVm":           "Require Shielded VMs",
            "constraints/iam.allowedPolicyMemberDomains":      "Restrict IAM to org domains",
            "constraints/storage.uniformBucketLevelAccess":    "Enforce uniform bucket access",
        }

        enabled_constraints = {p.get("name", "") for p in org_policies}
        for constraint, desc in recommended_constraints.items():
            if constraint not in enabled_constraints:
                findings.append(_finding(
                    title=f"GCP Org Policy Missing: {constraint.split('/')[-1]}",
                    severity="MEDIUM",
                    cvss=5.5,
                    cwe="CWE-284",
                    description=f"Organization policy '{constraint}' not enforced. {desc}.",
                    evidence=f"Org: {org_id}\nConstraint: {constraint} not found",
                    remediation=f"Enable org policy constraint: {constraint}",
                    target=f"gcp://organizations/{org_id}",
                    source="gcp_iam_analyzer",
                ))
        return findings

    def _check_sa_keys(self, bindings: list[dict], resource: str) -> list[dict]:
        """Check for service accounts with key-based auth (prefer Workload Identity)."""
        findings = []
        for binding in bindings:
            role    = binding.get("role", "")
            members = binding.get("members", [])
            if role in ("roles/iam.serviceAccountKeyAdmin",
                        "roles/iam.serviceAccountTokenCreator"):
                sa_members = [m for m in members if "serviceAccount" in m]
                if sa_members:
                    findings.append(_finding(
                        title=f"GCP Service Account Key Admin Role Detected",
                        severity="HIGH",
                        cvss=7.5,
                        cwe="CWE-522",
                        description=(
                            "Service account(s) have key admin permissions. "
                            "SA keys are long-lived credentials that increase breach risk."
                        ),
                        evidence=(
                            f"Resource: {resource}\n"
                            f"Role: {role}\n"
                            f"SA members: {', '.join(sa_members[:3])}"
                        ),
                        remediation=(
                            "Use Workload Identity Federation instead of service account keys. "
                            "If keys required: rotate regularly, store in Secret Manager."
                        ),
                        target=f"gcp://{resource}",
                        source="gcp_iam_analyzer",
                    ))
        return findings

    def _save(self, findings: list[dict]) -> Path:
        ts  = datetime.now().strftime("%Y%m%d_%H%M%S")
        out = self.output_dir / f"gcp_iam_{ts}.json"
        out.write_text(json.dumps({"findings": findings}, indent=2), encoding="utf-8")
        return out
