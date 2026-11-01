"""AWS IAM Threat & Privilege Escalation Detection Engine (Phase 2).

Detects dangerous permission combinations, privilege escalation vectors,
and sensitive service wildcards using statement-level policy evaluation.
"""

from typing import Any

from aws.policy_evaluator import PolicyEvaluator
from iam_audit.core.models import SecurityFinding

# Sensitive service wildcard definitions
SENSITIVE_SERVICES = {
    "iam:*": ("IAM_PRIVILEGE_MANAGEMENT_PERMISSION", "CRITICAL", "Full administrative control over AWS IAM (iam:*)."),
    "s3:*": ("IAM_BROAD_DATA_ACCESS", "HIGH", "Unrestricted data access and management over Amazon S3 (s3:*)."),
    "secretsmanager:*": ("IAM_BROAD_DATA_ACCESS", "HIGH", "Unrestricted access to all Secrets Manager secrets (secretsmanager:*)."),
    "kms:*": ("IAM_SENSITIVE_SERVICE_WILDCARD", "HIGH", "Unrestricted access to AWS KMS encryption keys (kms:*)."),
    "dynamodb:*": ("IAM_BROAD_DATA_ACCESS", "HIGH", "Unrestricted access to DynamoDB tables and data (dynamodb:*)."),
    "rds:*": ("IAM_BROAD_DATA_ACCESS", "HIGH", "Unrestricted management and access to RDS databases (rds:*)."),
    "lambda:*": ("IAM_SENSITIVE_SERVICE_WILDCARD", "MEDIUM", "Unrestricted execution and management of Lambda functions (lambda:*)."),
    "ec2:*": ("IAM_SENSITIVE_SERVICE_WILDCARD", "MEDIUM", "Unrestricted management over EC2 compute instances (ec2:*)."),
    "ssm:*": ("IAM_SENSITIVE_SERVICE_WILDCARD", "MEDIUM", "Unrestricted access to Systems Manager and parameters (ssm:*)."),
    "sts:*": ("IAM_SENSITIVE_SERVICE_WILDCARD", "MEDIUM", "Unrestricted access to Security Token Service (sts:*)."),
}


def audit_privilege_escalation_vectors(
    username: str, policy_sources: list[dict[str, Any]]
) -> list[SecurityFinding]:
    """Audit user permissions for known AWS IAM privilege escalation paths."""
    findings: list[SecurityFinding] = []
    evaluator = PolicyEvaluator(policy_sources)

    # 1. CreateAccessKey Escalation
    if evaluator.has_permission("iam:CreateAccessKey"):
        res = evaluator.evaluate_action("iam:CreateAccessKey")
        findings.append(
            SecurityFinding(
                id="IAM_PRIVILEGE_ESCALATION",
                rule_id="IAM_ESC_CREATE_ACCESS_KEY",
                category="PRIVILEGE_ESCALATION",
                severity="HIGH",
                confidence="CONFIRMED" if not res.is_condition_constrained else "POTENTIAL_PATH",
                resource=f"{username} (IAM User)",
                resource_type="IAM User",
                issue=f"User '{username}' can create access keys for any IAM user (iam:CreateAccessKey).",
                impact="An attacker could generate access keys for an administrator user and take over the account.",
                recommendation="Restrict iam:CreateAccessKey to self-service (${aws:username}) or disable it.",
                compliance_mappings=["CIS AWS Foundations Benchmark v3.0 Control 1.16"],
                evidence={
                    "initiating_principal": username,
                    "granted_action": "iam:CreateAccessKey",
                    "resource_constrained": res.is_resource_constrained,
                    "condition_constrained": res.is_condition_constrained,
                },
                detection_source="IAM Threat Detection Engine",
                collection_status="CONFIRMED",
            )
        )

    # 2. Login Profile Escalation (Create/Update Console Password)
    has_create_lp = evaluator.has_permission("iam:CreateLoginProfile")
    has_update_lp = evaluator.has_permission("iam:UpdateLoginProfile")
    if has_create_lp or has_update_lp:
        action_name = "iam:CreateLoginProfile" if has_create_lp else "iam:UpdateLoginProfile"
        res = evaluator.evaluate_action(action_name)
        findings.append(
            SecurityFinding(
                id="IAM_PRIVILEGE_ESCALATION",
                rule_id="IAM_ESC_LOGIN_PROFILE",
                category="PRIVILEGE_ESCALATION",
                severity="HIGH",
                confidence="CONFIRMED" if not res.is_condition_constrained else "POTENTIAL_PATH",
                resource=f"{username} (IAM User)",
                resource_type="IAM User",
                issue=f"User '{username}' can create or reset console passwords ({action_name}).",
                impact="An attacker could set a console password for an administrator and log in as them.",
                recommendation="Restrict console password management permissions to self-service only.",
                compliance_mappings=["CIS AWS Foundations Benchmark v3.0 Control 1.16"],
                evidence={
                    "initiating_principal": username,
                    "granted_action": action_name,
                    "resource_constrained": res.is_resource_constrained,
                },
                detection_source="IAM Threat Detection Engine",
                collection_status="CONFIRMED",
            )
        )

    # 3. Policy Attachment Escalation
    attach_actions = [
        "iam:AttachUserPolicy",
        "iam:PutUserPolicy",
        "iam:AttachGroupPolicy",
        "iam:PutGroupPolicy",
        "iam:AttachRolePolicy",
        "iam:PutRolePolicy",
    ]
    granted_attach = [act for act in attach_actions if evaluator.has_permission(act)]
    if granted_attach:
        findings.append(
            SecurityFinding(
                id="IAM_PRIVILEGE_ESCALATION",
                rule_id="IAM_ESC_POLICY_ATTACHMENT",
                category="PRIVILEGE_ESCALATION",
                severity="CRITICAL",
                confidence="CONFIRMED",
                resource=f"{username} (IAM User)",
                resource_type="IAM User",
                issue=f"User '{username}' can attach or inline IAM policies ({', '.join(granted_attach)}).",
                impact="An attacker could attach AdministratorAccess to themselves or an assumed role.",
                recommendation="Remove policy attachment/modification permissions from non-admin users.",
                compliance_mappings=["CIS AWS Foundations Benchmark v3.0 Control 1.16"],
                evidence={
                    "initiating_principal": username,
                    "granted_actions": granted_attach,
                },
                detection_source="IAM Threat Detection Engine",
                collection_status="CONFIRMED",
            )
        )

    # 4. Policy Versioning Escalation
    has_create_pv = evaluator.has_permission("iam:CreatePolicyVersion")
    has_set_pv = evaluator.has_permission("iam:SetDefaultPolicyVersion")
    if has_create_pv or has_set_pv:
        pv_actions = [act for act in ["iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion"] if evaluator.has_permission(act)]
        findings.append(
            SecurityFinding(
                id="IAM_PRIVILEGE_ESCALATION",
                rule_id="IAM_ESC_POLICY_VERSION",
                category="PRIVILEGE_ESCALATION",
                severity="CRITICAL",
                confidence="CONFIRMED",
                resource=f"{username} (IAM User)",
                resource_type="IAM User",
                issue=f"User '{username}' can modify policy versions ({', '.join(pv_actions)}).",
                impact="An attacker could edit an existing policy to grant full AdministratorAccess.",
                recommendation="Restrict policy version creation to security admins.",
                compliance_mappings=["CIS AWS Foundations Benchmark v3.0 Control 1.16"],
                evidence={"initiating_principal": username, "granted_actions": pv_actions},
                detection_source="IAM Threat Detection Engine",
                collection_status="CONFIRMED",
            )
        )

    # 5. PassRole + Compute Escalation
    if evaluator.has_permission("iam:PassRole"):
        compute_triggers = {
            "ec2:RunInstances": "EC2 Instances",
            "lambda:CreateFunction": "Lambda Functions",
            "lambda:UpdateFunctionCode": "Lambda Functions",
            "ecs:RunTask": "ECS Tasks",
            "ecs:RegisterTaskDefinition": "ECS Tasks",
            "glue:CreateDevEndpoint": "Glue Dev Endpoints",
            "cloudformation:CreateStack": "CloudFormation Stacks",
        }
        granted_compute = [act for act in compute_triggers if evaluator.has_permission(act)]
        if granted_compute:
            findings.append(
                SecurityFinding(
                    id="IAM_PRIVILEGE_ESCALATION",
                    rule_id="IAM_ESC_PASSROLE_COMPUTE",
                    category="PRIVILEGE_ESCALATION",
                    severity="HIGH",
                    confidence="POTENTIAL_PATH",
                    resource=f"{username} (IAM User)",
                    resource_type="IAM User",
                    issue=f"User '{username}' has iam:PassRole combined with compute execution ({', '.join(granted_compute)}).",
                    impact="An attacker could pass a privileged role to compute resources and execute arbitrary code.",
                    recommendation="Restrict iam:PassRole with resource conditions limiting which roles can be passed.",
                    compliance_mappings=["CIS AWS Foundations Benchmark v3.0 Control 1.16"],
                    evidence={
                        "initiating_principal": username,
                        "pass_role_granted": True,
                        "compute_actions": granted_compute,
                    },
                    detection_source="IAM Threat Detection Engine",
                    collection_status="POTENTIAL_PATH",
                )
            )

    # 6. UpdateAssumeRolePolicy Escalation
    if evaluator.has_permission("iam:UpdateAssumeRolePolicy"):
        findings.append(
            SecurityFinding(
                id="IAM_PRIVILEGE_ESCALATION",
                rule_id="IAM_ESC_UPDATE_ASSUME_ROLE_POLICY",
                category="PRIVILEGE_ESCALATION",
                severity="CRITICAL",
                confidence="CONFIRMED",
                resource=f"{username} (IAM User)",
                resource_type="IAM User",
                issue=f"User '{username}' can update IAM role trust policies (iam:UpdateAssumeRolePolicy).",
                impact="An attacker could alter any role's trust policy to allow themselves to assume it.",
                recommendation="Restrict iam:UpdateAssumeRolePolicy to privileged identity administrators.",
                compliance_mappings=["CIS AWS Foundations Benchmark v3.0 Control 1.16"],
                evidence={"initiating_principal": username, "granted_action": "iam:UpdateAssumeRolePolicy"},
                detection_source="IAM Threat Detection Engine",
                collection_status="CONFIRMED",
            )
        )

    # 7. Boundary Deletion Escalation
    has_del_user_b = evaluator.has_permission("iam:DeleteUserPermissionsBoundary")
    has_del_role_b = evaluator.has_permission("iam:DeleteRolePermissionsBoundary")
    if has_del_user_b or has_del_role_b:
        b_actions = [act for act in ["iam:DeleteUserPermissionsBoundary", "iam:DeleteRolePermissionsBoundary"] if evaluator.has_permission(act)]
        findings.append(
            SecurityFinding(
                id="IAM_PRIVILEGE_ESCALATION",
                rule_id="IAM_ESC_BOUNDARY_DELETION",
                category="PRIVILEGE_ESCALATION",
                severity="HIGH",
                confidence="CONFIRMED",
                resource=f"{username} (IAM User)",
                resource_type="IAM User",
                issue=f"User '{username}' can delete IAM permissions boundaries ({', '.join(b_actions)}).",
                impact="An attacker could delete permission boundaries enforcing least privilege.",
                recommendation="Protect permission boundaries with explicit Deny or SCPs.",
                compliance_mappings=["CIS AWS Foundations Benchmark v3.0 Control 1.16"],
                evidence={"initiating_principal": username, "granted_actions": b_actions},
                detection_source="IAM Threat Detection Engine",
                collection_status="CONFIRMED",
            )
        )

    return findings


def audit_sensitive_service_wildcards(
    username: str, policy_sources: list[dict[str, Any]]
) -> list[SecurityFinding]:
    """Audit user permissions for broad sensitive service wildcards."""
    findings: list[SecurityFinding] = []
    evaluator = PolicyEvaluator(policy_sources)

    # Skip users who already have full AdministratorAccess to avoid duplicate findings
    if evaluator.has_permission("*"):
        return findings

    for action_pattern, (rule_id, severity, desc) in SENSITIVE_SERVICES.items():
        if evaluator.has_permission(action_pattern):
            res = evaluator.evaluate_action(action_pattern)
            # Only flag if Resource is broad or unconstrained
            if not res.is_resource_constrained:
                service = action_pattern.split(":")[0].upper()
                findings.append(
                    SecurityFinding(
                        id=rule_id,
                        rule_id=rule_id,
                        category="SERVICE_WILDCARD",
                        severity=severity,
                        confidence="CONFIRMED",
                        resource=f"{username} (IAM User)",
                        resource_type="IAM User",
                        issue=f"User '{username}' has wildcard access over {service} ({action_pattern}).",
                        impact=desc,
                        recommendation=f"Replace '{action_pattern}' with specific actions and constrained resources.",
                        compliance_mappings=["CIS AWS Foundations Benchmark v3.0 Control 1.16"],
                        evidence={
                            "initiating_principal": username,
                            "action_pattern": action_pattern,
                            "service": service,
                            "condition_constrained": res.is_condition_constrained,
                        },
                        detection_source="IAM Threat Detection Engine",
                        collection_status="CONFIRMED",
                    )
                )

    return findings
