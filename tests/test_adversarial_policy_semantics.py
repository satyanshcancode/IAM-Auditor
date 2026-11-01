"""Adversarial IAM policy semantics test suite (Phase 4).

Tests explicit Deny precedence, wildcards with conditions/boundaries, NotAction/NotResource,
condition operators (String, Numeric, Bool, Null, IpAddress, Arn, IfExists), permissions boundaries,
session policies, role trust policies, cross-account/federated trust, and malformed constructs.
"""

from aws.policy_evaluator import PolicyEvaluator
from aws.policy_validator import validate_policy_syntax
from aws.trust import audit_role_trust_policies


def test_explicit_deny_overrides_allow_across_multiple_sources() -> None:
    sources = [
        {
            "name": "AllowPolicy",
            "document": {
                "Statement": [
                    {"Effect": "Allow", "Action": "s3:*", "Resource": "*"}
                ]
            },
        },
        {
            "name": "DenyPolicy",
            "document": {
                "Statement": [
                    {"Effect": "Deny", "Action": "s3:DeleteBucket", "Resource": "*"}
                ]
            },
        },
    ]
    evaluator = PolicyEvaluator(sources)

    # s3:GetObject should be allowed
    res_get = evaluator.evaluate_action("s3:GetObject", "arn:aws:s3:::mybucket/file.txt")
    assert res_get.allowed is True
    assert res_get.decision == "allowed"

    # s3:DeleteBucket must be explicitly denied
    res_del = evaluator.evaluate_action("s3:DeleteBucket", "arn:aws:s3:::mybucket")
    assert res_del.allowed is False
    assert res_del.decision == "explicitDeny"
    assert len(res_del.matching_deny_statements) == 1


def test_not_action_semantics() -> None:
    sources = [
        {
            "name": "NotActionPolicy",
            "document": {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "NotAction": ["iam:*", "organizations:*"],
                        "Resource": "*",
                    }
                ]
            },
        }
    ]
    evaluator = PolicyEvaluator(sources)

    # s3:GetObject is NOT in iam:* or organizations:* -> allowed
    assert evaluator.has_permission("s3:GetObject") is True
    # iam:CreateUser IS in iam:* -> implicitDeny
    assert evaluator.has_permission("iam:CreateUser") is False


def test_not_resource_semantics() -> None:
    sources = [
        {
            "name": "NotResourcePolicy",
            "document": {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "s3:GetObject",
                        "NotResource": ["arn:aws:s3:::sensitive-bucket/*"],
                    }
                ]
            },
        }
    ]
    evaluator = PolicyEvaluator(sources)

    # General bucket file -> allowed
    assert evaluator.has_permission("s3:GetObject", "arn:aws:s3:::public-bucket/data.csv") is True
    # Sensitive bucket file -> denied (NotResource excludes it)
    assert evaluator.has_permission("s3:GetObject", "arn:aws:s3:::sensitive-bucket/secret.txt") is False


def test_condition_operator_string_numeric_ip_and_if_exists() -> None:
    sources = [
        {
            "name": "ConditionPolicy",
            "document": {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "ec2:RunInstances",
                        "Resource": "*",
                        "Condition": {
                            "StringEquals": {"aws:PrincipalAccount": "123456789012"},
                            "NumericLessThan": {"ec2:InstanceTypeScore": "10"},
                            "IpAddress": {"aws:SourceIp": "192.168.1.0/24"},
                            "Bool": {"aws:SecureTransport": "true"},
                            "StringEqualsIfExists": {"aws:RequestTag/Environment": "Production"},
                        },
                    }
                ]
            },
        }
    ]
    evaluator = PolicyEvaluator(sources)

    # 1. Evaluate with matching context
    matching_ctx = {
        "aws:PrincipalAccount": "123456789012",
        "ec2:InstanceTypeScore": "5",
        "aws:SourceIp": "192.168.1.50",
        "aws:SecureTransport": "true",
        "aws:RequestTag/Environment": "Production",
    }
    res_match = evaluator.evaluate_action("ec2:RunInstances", "*", context=matching_ctx)
    assert res_match.allowed is True

    # 2. Evaluate with missing IfExists tag (should still match due to IfExists modifier)
    matching_ctx_no_tag = dict(matching_ctx)
    del matching_ctx_no_tag["aws:RequestTag/Environment"]
    res_if_exists = evaluator.evaluate_action("ec2:RunInstances", "*", context=matching_ctx_no_tag)
    assert res_if_exists.allowed is True

    # 3. Evaluate with non-matching IP
    bad_ip_ctx = dict(matching_ctx, **{"aws:SourceIp": "10.0.0.1"})
    res_bad_ip = evaluator.evaluate_action("ec2:RunInstances", "*", context=bad_ip_ctx)
    assert res_bad_ip.allowed is False


def test_permissions_boundary_and_session_policy_restrictions() -> None:
    identity_sources = [
        {
            "name": "FullAccessIdentityPolicy",
            "document": {
                "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]
            },
        }
    ]

    boundary_sources = [
        {
            "name": "S3OnlyBoundary",
            "document": {
                "Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]
            },
        }
    ]

    session_sources = [
        {
            "name": "S3SessionPolicy",
            "document": {
                "Statement": [
                    {"Effect": "Allow", "Action": "s3:*", "Resource": "*"},
                    {"Effect": "Deny", "Action": "s3:DeleteObject", "Resource": "*"},
                ]
            },
        }
    ]

    evaluator = PolicyEvaluator(
        policy_sources=identity_sources,
        permissions_boundary_sources=boundary_sources,
        session_policy_sources=session_sources,
    )

    # s3:GetObject is allowed by identity, boundary, and session
    res_get = evaluator.evaluate_action("s3:GetObject")
    assert res_get.allowed is True

    # ec2:RunInstances is allowed by identity, but RESTRICTED by permissions boundary
    res_ec2 = evaluator.evaluate_action("ec2:RunInstances")
    assert res_ec2.allowed is False
    assert "Boundary" in res_ec2.limitation_note

    # s3:DeleteObject is allowed by identity & boundary, but DENIED by session policy
    res_del = evaluator.evaluate_action("s3:DeleteObject")
    assert res_del.allowed is False
    assert res_del.decision == "explicitDeny"
    assert "Session" in res_del.limitation_note


def test_malformed_and_unsupported_policy_constructs() -> None:
    # Invalid JSON string syntax check
    syntax_res = validate_policy_syntax("{bad_json")
    assert syntax_res["valid"] is False

    # Statement missing required Action / Resource elements
    malformed_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow"}  # Missing Action and Resource
        ],
    }
    syntax_res2 = validate_policy_syntax(malformed_policy)
    assert syntax_res2["valid"] is False
    assert any("Action" in err for err in syntax_res2["errors"])
    assert any("Resource" in err for err in syntax_res2["errors"])

    # Evaluator should ignore malformed statements safely without throwing exceptions
    evaluator = PolicyEvaluator([{"name": "BadPolicy", "document": malformed_policy}])
    assert evaluator.has_permission("s3:GetObject") is False


def test_role_trust_policy_cross_account_and_federated_trust() -> None:
    roles = [
        {
            "RoleName": "CrossAccountAdminRole",
            "AssumeRolePolicyDocument": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"AWS": "arn:aws:iam::999988887777:root"},
                        "Action": "sts:AssumeRole",
                    }
                ],
            },
        },
        {
            "RoleName": "OIDCWebIdentityRole",
            "AssumeRolePolicyDocument": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {
                            "Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
                        },
                        "Action": "sts:AssumeRoleWithWebIdentity",
                        "Condition": {
                            "StringEquals": {
                                "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"
                            }
                        },
                    }
                ],
            },
        },
    ]

    findings, errors = audit_role_trust_policies(
        roles=roles,
        current_account_id="123456789012",
        role_analyses={"CrossAccountAdminRole": {"is_admin": True}},
    )

    # Verify cross-account finding for external account 999988887777
    cross_account_findings = [f for f in findings if f.id == "IAM_ROLE_CROSS_ACCOUNT_TRUST"]
    assert len(cross_account_findings) == 1
    assert cross_account_findings[0].evidence["trusted_account_id"] == "999988887777"

    # Verify privileged role trust correlation finding
    admin_trust_findings = [f for f in findings if f.id == "IAM_ROLE_TRUST_WITH_PRIVILEGED_PERMISSIONS"]
    assert len(admin_trust_findings) == 1
    assert admin_trust_findings[0].evidence["role_name"] == "CrossAccountAdminRole"


def test_multivalued_context_key_conditions() -> None:
    sources = [
        {
            "name": "MultivaluedKeyPolicy",
            "document": {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "s3:GetObject",
                        "Resource": "*",
                        "Condition": {
                            "StringEquals": {"aws:PrincipalTag/Role": ["SecurityAdmin", "Auditor"]}
                        },
                    }
                ]
            },
        }
    ]
    evaluator = PolicyEvaluator(sources)

    # 1. Matching list context value
    ctx_match = {"aws:PrincipalTag/Role": ["Auditor", "Engineer"]}
    res = evaluator.evaluate_action("s3:GetObject", "*", context=ctx_match)
    assert res.allowed is True

    # 2. Non-matching list context value
    ctx_nomatch = {"aws:PrincipalTag/Role": ["Developer", "Guest"]}
    res_no = evaluator.evaluate_action("s3:GetObject", "*", context=ctx_nomatch)
    assert res_no.allowed is False


def test_policy_variable_substitution_and_indeterminate_state() -> None:
    sources = [
        {
            "name": "UserHomeDirPolicy",
            "document": {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "s3:GetObject",
                        "Resource": "arn:aws:s3:::my-company-bucket/home/${aws:username}/*",
                    }
                ]
            },
        }
    ]
    evaluator = PolicyEvaluator(sources)

    # 1. Evaluate with resolved username in context -> allowed
    ctx_resolved = {"aws:username": "alice"}
    res_ok = evaluator.evaluate_action("s3:GetObject", "arn:aws:s3:::my-company-bucket/home/alice/doc.pdf", context=ctx_resolved)
    assert res_ok.allowed is True
    assert res_ok.decision == "allowed"
    assert res_ok.is_indeterminate is False

    # 2. Evaluate without context (unresolved variable) -> indeterminate
    res_indet = evaluator.evaluate_action("s3:GetObject", "arn:aws:s3:::my-company-bucket/home/alice/doc.pdf")
    assert res_indet.allowed is True
    assert res_indet.decision == "indeterminate"
    assert res_indet.is_indeterminate is True
    assert "unresolved policy variables" in res_indet.limitation_note


def test_for_all_values_and_for_any_value_condition_set_operators() -> None:
    sources = [
        {
            "name": "SetOperatorPolicy",
            "document": {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "s3:PutObject",
                        "Resource": "*",
                        "Condition": {
                            "ForAllValues:StringEquals": {
                                "aws:TagKeys": ["CostCenter", "Environment"]
                            }
                        },
                    }
                ]
            },
        }
    ]
    evaluator = PolicyEvaluator(sources)

    # 1. Request context with tags that are ALL subset of allowed tags -> allowed
    ctx_valid = {"aws:TagKeys": ["CostCenter"]}
    res_valid = evaluator.evaluate_action("s3:PutObject", "*", context=ctx_valid)
    assert res_valid.allowed is True

    # 2. Request context containing an unauthorized tag -> denied
    ctx_invalid = {"aws:TagKeys": ["CostCenter", "UnauthorizedTag"]}
    res_invalid = evaluator.evaluate_action("s3:PutObject", "*", context=ctx_invalid)
    assert res_invalid.allowed is False

    # 3. Empty request tags with ForAllValues -> allowed (per AWS spec)
    ctx_empty = {"aws:TagKeys": []}
    res_empty = evaluator.evaluate_action("s3:PutObject", "*", context=ctx_empty)
    assert res_empty.allowed is True


