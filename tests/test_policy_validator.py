"""Unit tests for aws/policy_validator.py module."""

from unittest.mock import MagicMock

from aws.policy_validator import (
    SIMULATION_LIMITATIONS_DOC,
    simulate_custom_policy,
    validate_policy_syntax,
)


def test_validate_policy_syntax_valid() -> None:
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject"],
                "Resource": "*",
            }
        ],
    }

    res = validate_policy_syntax(policy)
    assert res["valid"] is True
    assert len(res["errors"]) == 0


def test_validate_policy_syntax_invalid_json() -> None:
    res = validate_policy_syntax("{invalid_json_string")
    assert res["valid"] is False
    assert any("Invalid JSON" in err for err in res["errors"])


def test_validate_policy_syntax_missing_statement() -> None:
    res = validate_policy_syntax({"Version": "2012-10-17"})
    assert res["valid"] is False
    assert any("Missing required 'Statement'" in err for err in res["errors"])


def test_validate_policy_syntax_invalid_effect() -> None:
    policy = {
        "Statement": [
            {
                "Effect": "MAYBE",
                "Action": "s3:GetObject",
                "Resource": "*",
            }
        ]
    }
    res = validate_policy_syntax(policy)
    assert res["valid"] is False
    assert any("invalid Effect 'MAYBE'" in err for err in res["errors"])


def test_simulate_custom_policy_success() -> None:
    mock_iam = MagicMock()
    mock_iam.simulate_custom_policy.return_value = {
        "EvaluationResults": [
            {
                "EvalActionName": "s3:GetObject",
                "EvalDecision": "allowed",
                "MatchedStatements": [],
            }
        ]
    }

    policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "*"}],
    }

    res = simulate_custom_policy(
        policy_doc=policy,
        action_names=["s3:GetObject"],
        iam_client=mock_iam,
    )

    assert res["status"] == "SUCCESS"
    assert len(res["results"]) == 1
    assert res["results"][0]["decision"] == "allowed"
    assert res["limitations_disclaimer"] == SIMULATION_LIMITATIONS_DOC
