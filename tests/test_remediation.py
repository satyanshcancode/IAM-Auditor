"""Unit tests for aws/remediation.py module."""


from aws.remediation import (
    generate_batch_remediation_suite,
    generate_remediation_script_for_finding,
)


def test_generate_remediation_script_access_key() -> None:
    finding = {
        "id": "f-1",
        "rule_id": "IAM_ACCESS_KEY_OLD",
        "resource": "alice AKIA1234567890EXAMPLE",
        "resource_type": "IAM Access Key",
    }

    res = generate_remediation_script_for_finding(finding=finding, account_id="999888777666")
    script = res["script_content"]

    # Verify safeguards present in generated script
    assert "#!/usr/bin/env bash" in script
    assert "CURRENT_ACCOUNT=$(aws sts get-caller-identity --query Account --output text" in script
    assert "999888777666" in script  # Account ID guard
    assert "--dry-run" in script      # Dry-run flag handling
    assert "snapshot_access_key.json" in script  # Backup snapshot
    assert "CONFIRM" in script        # User approval gate
    assert res["rollback_instructions"] != ""


def test_generate_remediation_script_privilege_escalation() -> None:
    finding = {
        "id": "f-2",
        "rule_id": "IAM_ESC_CREATE_ACCESS_KEY",
        "resource": "bob",
        "resource_type": "IAM User",
    }

    res = generate_remediation_script_for_finding(finding=finding, account_id="123456789012")
    script = res["script_content"]

    assert "policy_patch.json" in script
    assert "RemediatedRestrictedAccess" in script


def test_generate_batch_remediation_suite() -> None:
    findings = [
        {"id": "f-1", "rule_id": "IAM_ACCESS_KEY_OLD", "resource": "alice"},
        {"id": "f-2", "rule_id": "IAM_INLINE_POLICY_PRESENT", "resource": "bob"},
    ]

    suite = generate_batch_remediation_suite(findings=findings, account_id="111222333444")
    assert len(suite) == 2
    assert suite[0]["finding_id"] == "f-1"
    assert suite[1]["finding_id"] == "f-2"
