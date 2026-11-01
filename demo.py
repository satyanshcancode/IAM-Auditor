"""Deterministic IAM Auditor Portfolio Demonstration Script.

Runs end-to-end audit pipeline completely offline using sanitized fixtures.
Generates demo_audit_report.json, demo_findings.sarif, and demo_remediation.sh.
"""

import os
import sys
from pathlib import Path

# Ensure repository root is on sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from aws.policy_evaluator import PolicyEvaluator
from aws.remediation import generate_remediation_script_for_finding
from iam_audit.core.models import AuditReport, SecurityFinding
from iam_audit.exporters.base import export_json, export_sarif


def run_portfolio_demo() -> AuditReport:
    print("======================================================================")
    print("      AWS IAM Auditor & Permission Analyzer - Portfolio Demo          ")
    print("======================================================================\n")

    # Step 1: Discover Inventory (Sanitized Fixtures)
    print("[+] Step 1: Discovering IAM Inventory (Sanitized Offline Fixtures)...")
    users = ["alice", "bob", "developer-service-user"]
    roles = ["CrossAccountAdminRole", "AppDeployerRole"]
    print(f"    Discovered Users : {users}")
    print(f"    Discovered Roles : {roles}\n")

    # Step 2: Policy Authorization Semantics & Indeterminate Decision Check
    print("[+] Step 2: Evaluating Policy Authorization Semantics...")
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::corporate-bucket/home/${aws:username}/*",
            }
        ],
    }
    evaluator = PolicyEvaluator([{"name": "HomeDirPolicy", "document": policy_doc}])

    # Context provided (Resolved)
    res_resolved = evaluator.evaluate_action(
        "s3:GetObject",
        "arn:aws:s3:::corporate-bucket/home/alice/file.pdf",
        context={"aws:username": "alice"},
    )
    print(f"    [Resolved Variable Context] Action: s3:GetObject -> Allowed: {res_resolved.allowed}, Decision: '{res_resolved.decision}'")

    # Context missing (Indeterminate)
    res_indet = evaluator.evaluate_action(
        "s3:GetObject",
        "arn:aws:s3:::corporate-bucket/home/alice/file.pdf",
    )
    print(f"    [Missing Variable Context] Action: s3:GetObject -> Allowed: {res_indet.allowed}, Decision: '{res_indet.decision}'")
    print(f"    Limitation Note: {res_indet.limitation_note}\n")

    # Step 3: Security Finding Generation
    print("[+] Step 3: Generating Evidence-Backed Security Findings...")
    findings = [
        SecurityFinding(
            id="IAM_ACCESS_KEY_OLD-alice-AKIA111122223333",
            rule_id="IAM_ACCESS_KEY_OLD",
            category="HYGIENE",
            severity="HIGH",
            confidence="CONFIRMED",
            resource="alice AKIA111122223333",
            resource_type="AccessKey",
            entity_name="alice",
            access_key_id="AKIA111122223333",
            issue="User 'alice' access key AKIA111122223333 has not been rotated for 120 days.",
            impact="Long-lived inactive credentials increase risk of credential leakage.",
            recommendation="Inactivate and rotate access keys older than 90 days.",
            evidence={"user_name": "alice", "access_key_id": "AKIA111122223333", "age_days": 120},
            detection_source="IAM Access Key Auditor",
        ),
        SecurityFinding(
            id="IAM_ROLE_PUBLIC_TRUST_RISK-CrossAccountAdminRole",
            rule_id="IAM_ROLE_PUBLIC_TRUST_RISK",
            category="ROLE_TRUST",
            severity="CRITICAL",
            confidence="CONFIRMED",
            resource="CrossAccountAdminRole (IAM Role)",
            resource_type="IAM Role",
            entity_name="CrossAccountAdminRole",
            issue="Role 'CrossAccountAdminRole' has a trust policy allowing wildcard principal '*' without conditions.",
            impact="Anyone in any AWS account can assume this IAM role and acquire its permissions.",
            recommendation="Restrict role trust policy to specific trusted AWS account IDs.",
            evidence={"role_name": "CrossAccountAdminRole", "principal": "*"},
            detection_source="IAM Role Trust Auditor",
        ),
    ]

    for f in findings:
        print(f"    - [{f.severity}] {f.rule_id}: {f.issue}")
    print()

    # Step 4: Export Reports (JSON and SARIF)
    print("[+] Step 4: Exporting Security Findings (JSON & SARIF)...")
    json_path = Path("demo_audit_report.json")
    sarif_path = Path("demo_findings.sarif")

    report = AuditReport(
        generated_at="2026-10-02T21:58:00Z",
        total_users=3,
        total_groups=1,
        total_roles=2,
        findings=findings,
        overall_status="ACTION_REQUIRED",
    )

    export_json(report, json_path)
    export_sarif(report, sarif_path)

    print(f"    Exported JSON report to: {json_path}")
    print(f"    Exported SARIF report to: {sarif_path}\n")

    # Step 5: Generate Remediation Artifact (Dry-Run Mode)
    print("[+] Step 5: Generating Safe Remediation Script (Dry-Run Supported)...")
    remediation_artifact = generate_remediation_script_for_finding(
        finding=findings[0].model_dump(),
        account_id="123456789012",
    )
    script_path = Path("demo_remediation.sh")
    script_path.write_text(remediation_artifact["script_content"], encoding="utf-8")

    print(f"    Generated Remediation Script: {script_path}")
    print("    Script Safeguards: Target Account ID Guard, Backup Snapshot Policy, Dry-Run Flag, Approval Gate")
    print(f"    Rollback Instructions:\n{remediation_artifact['rollback_instructions']}\n")

    print("======================================================================")
    print("                IAM Auditor Portfolio Demo Completed!                 ")
    print("======================================================================\n")
    return report


if __name__ == "__main__":
    run_portfolio_demo()
