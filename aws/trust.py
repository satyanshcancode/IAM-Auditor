"""AWS IAM Role Trust Policy Auditor (Phase 2).

Audits AssumeRolePolicyDocument for public wildcard principals, cross-account trusts,
missing ExternalId/Organization conditions, and correlation with role permissions.
"""

from typing import Any

from aws.policy_evaluator import normalize_to_list
from iam_audit.core.models import SecurityFinding


def parse_trust_principals(principal_block: Any) -> list[dict[str, str]]:
    """Parse Principal block into structured list of type and value."""
    result: list[dict[str, str]] = []

    if principal_block == "*":
        return [{"type": "Wildcard", "value": "*"}]

    if isinstance(principal_block, str):
        return [{"type": "Principal", "value": principal_block}]

    if isinstance(principal_block, dict):
        for p_type, p_val in principal_block.items():
            for item in normalize_to_list(p_val):
                result.append({"type": p_type, "value": item})

    return result


def is_wildcard_principal(principal_val: str) -> bool:
    """Return True if principal value represents a wildcard."""
    val = principal_val.strip()
    return val == "*" or val.endswith(":root") and val.startswith("*") or val == "arn:aws:iam::*:root"


def audit_role_trust_policies(
    roles: list[dict[str, Any]],
    current_account_id: str | None = None,
    role_analyses: dict[str, dict[str, Any]] | None = None,
) -> tuple[list[SecurityFinding], list[dict[str, Any]]]:
    """Audit IAM roles for trust policy vulnerabilities and cross-account risks."""
    findings: list[SecurityFinding] = []
    errors: list[dict[str, Any]] = []
    role_analyses = role_analyses or {}

    for role in roles:
        role_name = role.get("RoleName", "Unknown")
        trust_doc = role.get("AssumeRolePolicyDocument", {})

        if not trust_doc:
            continue

        stmt_list = trust_doc.get("Statement", [])
        if isinstance(stmt_list, dict):
            stmt_list = [stmt_list]
        elif not isinstance(stmt_list, list):
            stmt_list = []

        is_admin_role = role_analyses.get(role_name, {}).get("is_admin", False)

        for stmt in stmt_list:
            if not isinstance(stmt, dict):
                continue

            if stmt.get("Effect") != "Allow":
                continue

            principals = parse_trust_principals(stmt.get("Principal"))
            conditions = stmt.get("Condition", {}) if isinstance(stmt.get("Condition"), dict) else {}

            has_external_id = any(
                "sts:ExternalId" in str(cond_val)
                for cond_op, cond_val in conditions.items()
            )
            has_org_id = any(
                "aws:PrincipalOrgID" in str(cond_val)
                for cond_op, cond_val in conditions.items()
            )

            for p in principals:
                p_type = p["type"]
                p_val = p["value"]

                # 1. Public Wildcard Trust Check
                if p_val == "*" or (p_type == "AWS" and p_val == "*"):
                    if not has_external_id and not has_org_id:
                        findings.append(
                            SecurityFinding(
                                id="IAM_ROLE_PUBLIC_TRUST_RISK",
                                rule_id="IAM_ROLE_PUBLIC_TRUST_RISK",
                                category="ROLE_TRUST",
                                severity="CRITICAL",
                                confidence="CONFIRMED",
                                resource=f"{role_name} (IAM Role)",
                                resource_type="IAM Role",
                                issue=f"Role '{role_name}' has a trust policy allowing wildcard principal '*' without conditions.",
                                impact="Anyone in any AWS account can assume this IAM role and acquire its permissions.",
                                recommendation="Restrict role trust policy to specific AWS accounts, IAM users, or service principals.",
                                compliance_mappings=[
                                    "CIS AWS Foundations Benchmark v3.0 Control 1.16",
                                    "SOC 2 Type II CC6.1",
                                ],
                                evidence={
                                    "role_name": role_name,
                                    "principal": p_val,
                                    "has_external_id": has_external_id,
                                    "has_org_id": has_org_id,
                                },
                                detection_source="IAM Role Trust Auditor",
                                collection_status="CONFIRMED",
                            )
                        )

                # 2. Cross-Account Trust Check
                elif p_type == "AWS" and ":" in p_val:
                    # Extract account ID from ARN arn:aws:iam::123456789012:root or arn:aws:iam::123456789012:user/alice
                    parts = p_val.split(":")
                    if len(parts) >= 5 and parts[4].isdigit():
                        acct_id = parts[4]
                        if current_account_id and acct_id != current_account_id:
                            findings.append(
                                SecurityFinding(
                                    id="IAM_ROLE_CROSS_ACCOUNT_TRUST",
                                    rule_id="IAM_ROLE_CROSS_ACCOUNT_TRUST",
                                    category="ROLE_TRUST",
                                    severity="MEDIUM",
                                    confidence="CONFIRMED",
                                    resource=f"{role_name} (IAM Role)",
                                    resource_type="IAM Role",
                                    issue=f"Role '{role_name}' trusts external AWS Account ID '{acct_id}'.",
                                    impact="Users in external account '{acct_id}' can assume this role if authorized.",
                                    recommendation="Verify cross-account trust relationships and enforce sts:ExternalId.",
                                    compliance_mappings=["CIS AWS Foundations Benchmark v3.0 Control 1.16"],
                                    evidence={
                                        "role_name": role_name,
                                        "trusted_account_id": acct_id,
                                        "trusted_principal": p_val,
                                        "has_external_id": has_external_id,
                                    },
                                    detection_source="IAM Role Trust Auditor",
                                    collection_status="CONFIRMED",
                                )
                            )

                # 3. Trust + Privileged Role Correlation Check
                if is_admin_role and (p_val == "*" or p_type == "AWS") and not has_external_id and not has_org_id:
                    findings.append(
                            SecurityFinding(
                                id="IAM_ROLE_TRUST_WITH_PRIVILEGED_PERMISSIONS",
                                rule_id="IAM_ROLE_TRUST_WITH_PRIVILEGED_PERMISSIONS",
                                category="ROLE_TRUST",
                                severity="CRITICAL",
                                confidence="CONFIRMED",
                                resource=f"{role_name} (IAM Role)",
                                resource_type="IAM Role",
                                issue=f"Administrator role '{role_name}' has an unconstrained or broad trust policy.",
                                impact="Combines full administrator privileges with broad trust accessibility.",
                                recommendation="Restrict trust policy on administrator roles to highly trusted identities.",
                                compliance_mappings=["CIS AWS Foundations Benchmark v3.0 Control 1.16"],
                                evidence={
                                    "role_name": role_name,
                                    "trusted_principal": p_val,
                                    "is_admin_role": True,
                                },
                                detection_source="IAM Role Trust Auditor",
                                collection_status="CONFIRMED",
                            )
                        )

    return findings, errors
