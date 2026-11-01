"""Tests for Phase 1 Compliance Hygiene checks."""

from datetime import datetime, timedelta, timezone

import boto3
from moto import mock_aws

import aws.policies as iam_policies
from aws.hygiene import (
    audit_access_key_hygiene,
    audit_inline_policies,
    audit_mfa_hygiene,
    audit_user_inactivity_hygiene,
)
from iam_audit.core.engine import run_full_audit
from iam_audit.exporters.base import export_console_summary, export_csv, export_sarif


def fixed_now() -> datetime:
    """Fixed reference timestamp: 2026-10-01T12:00:00Z."""
    return datetime(2026, 10, 1, 12, 0, 0, tzinfo=timezone.utc)


@mock_aws
def test_mfa_hygiene_root_and_users():
    """Test MFA hygiene for root account and console users."""
    iam = boto3.client("iam", region_name="us-east-1")
    iam_policies.iam = iam

    # Create user with console access but no MFA
    iam.create_user(UserName="console_no_mfa")
    iam.create_login_profile(UserName="console_no_mfa", Password="Password123!")

    # Create API-only user
    iam.create_user(UserName="api_only_user")

    # Create console user WITH MFA
    iam.create_user(UserName="console_with_mfa")
    iam.create_login_profile(UserName="console_with_mfa", Password="Password123!")
    iam.enable_mfa_device(
        UserName="console_with_mfa",
        SerialNumber="arn:aws:iam::123456789012:mfa/console_with_mfa",
        AuthenticationCode1="123456",
        AuthenticationCode2="654321",
    )

    users = iam.list_users()["Users"]
    summary = iam.get_account_summary()["SummaryMap"]
    summary["AccountMFAEnabled"] = 0  # Root MFA disabled

    findings, errors = audit_mfa_hygiene(users, account_summary=summary)

    rule_ids = [f.id for f in findings]
    assert "IAM_ROOT_NO_MFA" in rule_ids
    assert "IAM_CONSOLE_USER_NO_MFA" in rule_ids

    mfa_user_resources = [f.resource for f in findings if f.id == "IAM_CONSOLE_USER_NO_MFA"]
    assert "console_no_mfa (IAM User)" in mfa_user_resources
    assert "api_only_user (IAM User)" not in mfa_user_resources
    assert "console_with_mfa (IAM User)" not in mfa_user_resources


@mock_aws
def test_mfa_hygiene_root_mfa_unknown():
    """Test root MFA status unknown when account summary is empty/failed."""
    iam = boto3.client("iam", region_name="us-east-1")
    iam_policies.iam = iam
    iam.create_user(UserName="alice")

    findings, errors = audit_mfa_hygiene(iam.list_users()["Users"], account_summary=None)

    rule_ids = [f.id for f in findings]
    assert "IAM_ROOT_MFA_UNKNOWN" in rule_ids
    assert len(errors) == 1


@mock_aws
def test_access_key_age_and_activity():
    """Test access key age (>90 days), unused (>90 days), never used, and inactive key handling."""
    iam = boto3.client("iam", region_name="us-east-1")
    iam_policies.iam = iam

    iam.create_user(UserName="key_user")

    # Key 1: Active key created 100 days ago (Old key)
    k1 = iam.create_access_key(UserName="key_user")["AccessKey"]
    k1_id = k1["AccessKeyId"]

    # Key 2: Inactive key created 120 days ago (Should be skipped)
    k2 = iam.create_access_key(UserName="key_user")["AccessKey"]
    k2_id = k2["AccessKeyId"]
    iam.update_access_key(UserName="key_user", AccessKeyId=k2_id, Status="Inactive")

    now = fixed_now()
    # Mock user keys list with custom CreateDate
    users = [{"UserName": "key_user"}]

    # Patch list_access_keys to return custom CreateDate for k1
    original_list_keys = iam_policies.list_access_keys

    def mock_list_keys(username: str):
        keys = original_list_keys(username)
        for k in keys:
            if k["AccessKeyId"] == k1_id:
                k["CreateDate"] = now - timedelta(days=100)
        return keys

    iam_policies.list_access_keys = mock_list_keys

    try:
        findings, errors = audit_access_key_hygiene(users, now_func=fixed_now)
    finally:
        iam_policies.list_access_keys = original_list_keys

    old_findings = [f for f in findings if f.id == "IAM_ACCESS_KEY_OLD"]
    never_used_findings = [f for f in findings if f.id == "IAM_ACCESS_KEY_NEVER_USED"]

    assert len(old_findings) == 1
    assert k1_id in old_findings[0].resource
    assert len(never_used_findings) == 1
    assert k1_id in never_used_findings[0].resource


@mock_aws
def test_user_inactivity_hygiene():
    """Test user inactivity detection across console and access keys."""
    iam = boto3.client("iam", region_name="us-east-1")
    iam_policies.iam = iam

    # Inactive console user (created 100 days ago)
    iam.create_user(UserName="inactive_user")
    iam.create_login_profile(UserName="inactive_user", Password="Password123!")

    # Active console user
    iam.create_user(UserName="active_user")

    now = fixed_now()
    users = [
        {"UserName": "inactive_user", "CreateDate": now - timedelta(days=100)},
        {"UserName": "active_user", "CreateDate": now - timedelta(days=5)},
    ]

    findings, errors = audit_user_inactivity_hygiene(users, now_func=fixed_now)

    inactive_resources = [f.resource for f in findings if f.id == "IAM_USER_INACTIVE"]
    assert "inactive_user (IAM User)" in inactive_resources
    assert "active_user (IAM User)" not in inactive_resources


@mock_aws
def test_inline_policy_hygiene():
    """Test inline policy detection for users, groups, and roles."""
    iam = boto3.client("iam", region_name="us-east-1")
    iam_policies.iam = iam

    # User inline policy
    iam.create_user(UserName="user1")
    iam.put_user_policy(
        UserName="user1",
        PolicyName="UserInline",
        PolicyDocument='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}',
    )

    # Group inline policy
    iam.create_group(GroupName="group1")
    iam.put_group_policy(
        GroupName="group1",
        PolicyName="GroupInline",
        PolicyDocument='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"}]}',
    )

    # Role inline policy
    trust_policy = '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}'
    iam.create_role(RoleName="role1", AssumeRolePolicyDocument=trust_policy)
    iam.put_role_policy(
        RoleName="role1",
        PolicyName="RoleInline",
        PolicyDocument='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"ec2:*","Resource":"*"}]}',
    )

    users = iam.list_users()["Users"]
    groups = iam.list_groups()["Groups"]
    roles = iam.list_roles()["Roles"]

    findings, errors = audit_inline_policies(users, groups, roles)

    assert len(findings) == 3
    resources = [f.resource for f in findings]
    assert "user1 / UserInline (User Inline Policy)" in resources
    assert "group1 / GroupInline (Group Inline Policy)" in resources
    assert "role1 / RoleInline (Role Inline Policy)" in resources


@mock_aws
def test_run_full_audit_integration(tmp_path):
    """Integration test checking full audit output, CSV, SARIF, and console summary."""
    iam = boto3.client("iam", region_name="us-east-1")
    iam_policies.iam = iam

    iam.create_user(UserName="audit_user")
    iam.create_login_profile(UserName="audit_user", Password="Password123!")

    report = run_full_audit()

    assert report.total_users == 1
    assert report.mfa_issues >= 1

    summary_str = export_console_summary(report)
    assert "MFA Issues" in summary_str
    assert "IAM_CONSOLE_USER_NO_MFA" in summary_str

    sarif_file = tmp_path / "findings.sarif"
    export_sarif(report, sarif_file)
    assert sarif_file.exists()

    csv_file = tmp_path / "findings.csv"
    export_csv(report, csv_file)
    assert csv_file.exists()
