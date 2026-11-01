"""Tests for Phase 2 Advanced IAM Threat Detection and Attack Path Correlation."""


from aws.attack_paths import build_attack_path_graph
from aws.policy_evaluator import PolicyEvaluator
from aws.threats import (
    audit_privilege_escalation_vectors,
    audit_sensitive_service_wildcards,
)
from aws.trust import audit_role_trust_policies


def test_statement_level_policy_evaluator():
    """Test PolicyEvaluator for Action, NotAction, Resource, NotResource, and Deny precedence."""
    policy_sources = [
        {
            "name": "AllowS3Get",
            "owner": "alice",
            "scope": "User",
            "type": "inline",
            "document": {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["s3:Get*", "s3:ListBucket"],
                        "Resource": "arn:aws:s3:::mybucket/*",
                    },
                    {
                        "Effect": "Deny",
                        "Action": "s3:GetObject",
                        "Resource": "arn:aws:s3:::mybucket/secret.txt",
                    },
                ]
            },
        }
    ]

    evaluator = PolicyEvaluator(policy_sources)

    # Allow check
    res1 = evaluator.evaluate_action("s3:ListBucket", "arn:aws:s3:::mybucket/*")
    assert res1.allowed is True
    assert res1.decision == "allowed"
    assert res1.is_resource_constrained is True

    # Explicit Deny check
    res2 = evaluator.evaluate_action("s3:GetObject", "arn:aws:s3:::mybucket/secret.txt")
    assert res2.allowed is False
    assert res2.decision == "explicitDeny"

    # Unmatching check
    res3 = evaluator.evaluate_action("dynamodb:PutItem", "*")
    assert res3.allowed is False
    assert res3.decision == "implicitDeny"


def test_privilege_escalation_create_access_key():
    """Test detection of iam:CreateAccessKey privilege escalation."""
    policy_sources = [
        {
            "name": "CreateKeyPolicy",
            "owner": "user1",
            "scope": "User",
            "type": "inline",
            "document": {
                "Statement": [
                    {"Effect": "Allow", "Action": "iam:CreateAccessKey", "Resource": "*"}
                ]
            },
        }
    ]

    findings = audit_privilege_escalation_vectors("user1", policy_sources)
    rule_ids = [f.rule_id for f in findings]
    assert "IAM_ESC_CREATE_ACCESS_KEY" in rule_ids
    f = next(f for f in findings if f.rule_id == "IAM_ESC_CREATE_ACCESS_KEY")
    assert f.severity == "HIGH"
    assert f.category == "PRIVILEGE_ESCALATION"


def test_privilege_escalation_passrole_compute():
    """Test detection of iam:PassRole combined with ec2:RunInstances."""
    policy_sources = [
        {
            "name": "PassRoleEC2",
            "owner": "developer",
            "scope": "User",
            "type": "inline",
            "document": {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["iam:PassRole", "ec2:RunInstances"],
                        "Resource": "*",
                    }
                ]
            },
        }
    ]

    findings = audit_privilege_escalation_vectors("developer", policy_sources)
    rule_ids = [f.rule_id for f in findings]
    assert "IAM_ESC_PASSROLE_COMPUTE" in rule_ids
    f = next(f for f in findings if f.rule_id == "IAM_ESC_PASSROLE_COMPUTE")
    assert f.confidence == "POTENTIAL_PATH"


def test_sensitive_service_wildcard():
    """Test detection of broad s3:* and secretsmanager:* wildcards."""
    policy_sources = [
        {
            "name": "BroadSecrets",
            "owner": "app_user",
            "scope": "User",
            "type": "inline",
            "document": {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "secretsmanager:*",
                        "Resource": "*",
                    }
                ]
            },
        }
    ]

    findings = audit_sensitive_service_wildcards("app_user", policy_sources)
    rule_ids = [f.rule_id for f in findings]
    assert "IAM_BROAD_DATA_ACCESS" in rule_ids
    f = next(f for f in findings if f.rule_id == "IAM_BROAD_DATA_ACCESS")
    assert f.category == "SERVICE_WILDCARD"


def test_role_trust_policy_public_wildcard():
    """Test detection of public wildcard trust policy without ExternalId/OrgID."""
    roles = [
        {
            "RoleName": "VulnerablePublicRole",
            "AssumeRolePolicyDocument": {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": "*",
                        "Action": "sts:AssumeRole",
                    }
                ]
            },
        }
    ]

    findings, errors = audit_role_trust_policies(roles)
    rule_ids = [f.rule_id for f in findings]
    assert "IAM_ROLE_PUBLIC_TRUST_RISK" in rule_ids
    f = next(f for f in findings if f.rule_id == "IAM_ROLE_PUBLIC_TRUST_RISK")
    assert f.severity == "CRITICAL"


def test_attack_path_graph_correlation():
    """Test bounded graph correlation tracing User -> PassRole -> Lambda -> Admin Role."""
    users = [{"UserName": "unprivileged_user"}]
    roles = [{"RoleName": "AdminRole"}]

    user_analyses = {
        "unprivileged_user": {
            "effective_actions": {"iam:PassRole", "lambda:CreateFunction"},
            "policies": [
                {
                    "name": "PassRolePolicy",
                    "owner": "unprivileged_user",
                    "scope": "User",
                    "type": "inline",
                    "document": {
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": ["iam:PassRole", "lambda:CreateFunction"],
                                "Resource": "*",
                            }
                        ]
                    },
                }
            ],
        }
    }

    role_analyses = {
        "AdminRole": {
            "effective_actions": {"*"},
            "policies": [],
        }
    }

    attack_paths = build_attack_path_graph(users, roles, user_analyses, role_analyses)
    assert len(attack_paths) == 1
    ap = attack_paths[0]
    assert ap.initiating_principal == "unprivileged_user"
    assert ap.target_principal_or_resource == "AdminRole"
    assert len(ap.steps) == 1
    assert ap.steps[0].action_or_edge == "CAN_PASS_ROLE_TO_LAMBDA"
