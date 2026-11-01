"""Adversarial Security Test Suite for IAM Auditor.

Tests cross-account STS failures, account ID guard enforcement, partial org scan tagging,
Access Advisor NO_DATA states, untracked action safeguard retention, simulation disclaimer checks,
remediation script dry-run safety, and backup failure halts.
"""

from unittest.mock import MagicMock, patch

from botocore.exceptions import ClientError

from aws.access_advisor import (
    generate_right_sized_policy_proposal,
    get_service_last_accessed_details,
)
from aws.organizations import scan_organization, scan_single_account
from aws.policy_validator import (
    SIMULATION_LIMITATIONS_DOC,
    simulate_custom_policy,
    validate_policy_syntax,
)
from aws.remediation import generate_remediation_script_for_finding


def test_adversarial_cross_account_assume_role_access_denied() -> None:
    """Verify that role assumption failure returns status FAILED with error message."""
    error_response = {"Error": {"Code": "AccessDenied", "Message": "Not authorized to perform sts:AssumeRole"}}
    client_error = ClientError(error_response, "AssumeRole")

    with patch("aws.organizations.get_iam_client_for_account", side_effect=client_error):
        result = scan_single_account("999999999999", role_name="UnAuthorizedRole")
        assert result["status"] == "FAILED"
        assert "AccessDenied" in result["error"]
        assert result["report"] is None


def test_adversarial_account_id_guard_enforcement() -> None:
    """Verify that generated remediation scripts strictly check target Account ID."""
    finding = {
        "id": "f-sec-1",
        "rule_id": "IAM_ACCESS_KEY_OLD",
        "resource": "alice AKIA1234567890",
    }
    script_obj = generate_remediation_script_for_finding(finding=finding, account_id="888888888888")
    script = script_obj["script_content"]

    # Verify strict equality check without default fallback bypass
    assert 'CURRENT_ACCOUNT=$(aws sts get-caller-identity --query Account --output text 2>/dev/null || echo "UNKNOWN")' in script
    assert 'if [ "$CURRENT_ACCOUNT" != "888888888888" ]; then' in script
    assert "exit 1" in script


def test_adversarial_remediation_script_dry_run_precedence() -> None:
    """Verify that DRY_RUN check occurs BEFORE any snapshot backup command or mutation."""
    finding = {
        "id": "f-sec-2",
        "rule_id": "IAM_INLINE_POLICY_PRESENT",
        "resource": "bob",
    }
    script_obj = generate_remediation_script_for_finding(finding=finding, account_id="777777777777")
    script = script_obj["script_content"]

    # Find line index of dry-run check vs step 1 backup
    dry_run_idx = script.find('if [ "$DRY_RUN" = true ]; then')
    backup_step_idx = script.find("# Safeguard 3: Create state snapshot backup")

    assert dry_run_idx != -1
    assert backup_step_idx != -1
    assert dry_run_idx < backup_step_idx, "DRY_RUN check must occur before backup creation!"


def test_adversarial_remediation_script_backup_failure_halt() -> None:
    """Verify remediation script halts with non-zero exit code if snapshot backup fails."""
    finding = {
        "id": "f-sec-3",
        "rule_id": "IAM_ACCESS_KEY_OLD",
        "resource": "alice AKIA1234567890",
    }
    script_obj = generate_remediation_script_for_finding(finding=finding, account_id="666666666666")
    script = script_obj["script_content"]

    assert 'if ! aws iam list-access-keys --user-name "alice" > snapshot_access_key.json; then' in script
    assert "[-] ERROR: Backup snapshot creation failed" in script
    assert "exit 1" in script


def test_adversarial_partial_organization_scan_tagging() -> None:
    """Verify an organization scan with 1 failed account returns PARTIAL_SCAN_COMPLETED status."""
    def mock_scan_account(account_id: str, **kwargs: str) -> dict:
        if account_id == "111111111111":
            return {
                "account_id": "111111111111",
                "account_name": "Prod",
                "status": "SUCCESS",
                "report": {"findings": []},
                "findings_count": 0,
            }
        return {
            "account_id": account_id,
            "account_name": "Dev",
            "status": "FAILED",
            "error": "[ThrottlingException] Rate exceeded",
            "report": None,
            "findings_count": 0,
        }

    with patch("aws.organizations.scan_single_account", side_effect=mock_scan_account):
        res = scan_organization(account_ids=["111111111111", "222222222222"])
        assert res["scan_status"] == "PARTIAL_SCAN_COMPLETED"
        assert res["successful_scans"] == 1
        assert res["failed_scans"] == 1
        assert len(res["collection_errors"]) == 1
        assert res["collection_errors"][0]["account_id"] == "222222222222"


def test_adversarial_access_advisor_no_data_state() -> None:
    """Verify Access Advisor handles job failure by setting status to NO_DATA."""
    mock_iam = MagicMock()
    mock_iam.generate_service_last_accessed_details.side_effect = ClientError(
        {"Error": {"Code": "NoSuchEntity", "Message": "ARN not found"}}, "GenerateServiceLastAccessedDetails"
    )

    res = get_service_last_accessed_details(arn="arn:aws:iam::111:user/nonexistent", iam_client=mock_iam)
    assert res["job_status"] == "NO_DATA"
    assert res["services"] == []
    assert "NoSuchEntity" in res["error"]


def test_adversarial_untracked_permission_safeguard_retention() -> None:
    """Verify candidate right-sized policy engine preserves untracked operations."""
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "codecommit:GitPull",
                    "iam:PassRole",
                    "sts:AssumeRoleWithSAML",
                    "kms:Decrypt",
                ],
                "Resource": "*",
            }
        ],
    }

    proposal = generate_right_sized_policy_proposal(
        original_policy_doc=policy_doc,
        inactive_services=["codecommit", "iam", "sts", "kms"],
    )

    proposed_actions = proposal["proposed_policy"]["Statement"][0]["Action"]
    assert "codecommit:GitPull" not in proposed_actions
    assert "iam:PassRole" in proposed_actions
    assert "sts:AssumeRoleWithSAML" in proposed_actions
    assert "kms:Decrypt" in proposed_actions


def test_adversarial_policy_simulation_disclaimer() -> None:
    """Verify custom policy simulation includes explicit disclaimer on evaluation limitations."""
    mock_iam = MagicMock()
    mock_iam.simulate_custom_policy.return_value = {
        "EvaluationResults": [{"EvalActionName": "s3:GetObject", "EvalDecision": "allowed"}]
    }

    res = simulate_custom_policy(
        policy_doc={"Statement": [{"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "*"}]},
        action_names=["s3:GetObject"],
        iam_client=mock_iam,
    )

    assert res["status"] == "SUCCESS"
    assert res["limitations_disclaimer"] == SIMULATION_LIMITATIONS_DOC
    assert "Service Control Policies (SCPs)" in res["limitations_disclaimer"]


def test_adversarial_malformed_policy_validation() -> None:
    """Verify syntax validator flags missing Effect, missing Statement, and bad JSON."""
    assert validate_policy_syntax("{bad_json")["valid"] is False
    assert validate_policy_syntax({"Version": "2012-10-17"})["valid"] is False
    assert validate_policy_syntax({"Statement": [{"Action": "s3:GetObject", "Resource": "*"}]})["valid"] is False
