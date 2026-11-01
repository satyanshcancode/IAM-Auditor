"""Unit and integration tests for aws/organizations.py multi-account scanner."""

from unittest.mock import MagicMock, patch

from botocore.exceptions import ClientError

from aws.organizations import (
    assume_role,
    list_organization_accounts,
    scan_organization,
    scan_single_account,
)


def test_assume_role_success() -> None:
    mock_sts = MagicMock()
    mock_sts.assume_role.return_value = {
        "Credentials": {
            "AccessKeyId": "ASIAEXAMPLEKEY",
            "SecretAccessKey": "SecretKeyExample",
            "SessionToken": "TokenExample",
        }
    }

    with patch("aws.organizations.get_sts_client", return_value=mock_sts):
        creds = assume_role("123456789012", role_name="AuditRole")
        assert creds["aws_access_key_id"] == "ASIAEXAMPLEKEY"
        assert creds["aws_secret_access_key"] == "SecretKeyExample"
        mock_sts.assume_role.assert_called_once_with(
            RoleArn="arn:aws:iam::123456789012:role/AuditRole",
            RoleSessionName="IAMAuditorSession",
            DurationSeconds=3600,
        )


def test_list_organization_accounts_paginated() -> None:
    mock_org = MagicMock()
    paginator = MagicMock()
    paginator.paginate.return_value = [
        {
            "Accounts": [
                {"Id": "111111111111", "Name": "Prod", "Status": "ACTIVE", "Email": "prod@example.com"},
                {"Id": "222222222222", "Name": "Dev", "Status": "ACTIVE", "Email": "dev@example.com"},
            ]
        },
        {
            "Accounts": [
                {"Id": "333333333333", "Name": "Suspended", "Status": "SUSPENDED", "Email": "sub@example.com"},
            ]
        },
    ]
    mock_org.get_paginator.return_value = paginator

    accounts = list_organization_accounts(org_client=mock_org)
    assert len(accounts) == 3
    assert accounts[0]["Id"] == "111111111111"
    assert accounts[2]["Status"] == "SUSPENDED"


def test_scan_single_account_success() -> None:
    mock_iam = MagicMock()
    mock_report = {
        "findings": [{"id": "IAM_CONSOLE_USER_NO_MFA", "resource": "alice"}],
        "users": [{"UserName": "alice"}],
    }

    with patch("aws.organizations.get_iam_client_for_account", return_value=mock_iam), patch(
        "aws.organizations.collect_account_audit", return_value=mock_report
    ):
        res = scan_single_account("111111111111", account_name="ProdAccount")
        assert res["status"] == "SUCCESS"
        assert res["account_id"] == "111111111111"
        assert res["findings_count"] == 1


def test_scan_single_account_role_error() -> None:
    error_response = {"Error": {"Code": "AccessDenied", "Message": "Not authorized to assume role"}}
    client_error = ClientError(error_response, "AssumeRole")

    with patch("aws.organizations.get_iam_client_for_account", side_effect=client_error):
        res = scan_single_account("999999999999")
        assert res["status"] == "FAILED"
        assert "AccessDenied" in res["error"]


def test_scan_organization_partial_completed() -> None:
    # 1 success, 1 failure => PARTIAL_SCAN_COMPLETED
    def mock_scan_single(account_id: str, **kwargs: str) -> dict:
        if account_id == "111111111111":
            return {
                "account_id": account_id,
                "account_name": "Prod",
                "status": "SUCCESS",
                "report": {"findings": [{"id": "IAM_ROOT_NO_MFA", "resource": "root"}]},
                "findings_count": 1,
            }
        else:
            return {
                "account_id": account_id,
                "account_name": "Dev",
                "status": "FAILED",
                "error": "[AccessDenied] Role assumption refused",
                "report": None,
                "findings_count": 0,
            }

    with patch("aws.organizations.scan_single_account", side_effect=mock_scan_single):
        res = scan_organization(account_ids=["111111111111", "222222222222"], max_workers=2)
        assert res["scan_status"] == "PARTIAL_SCAN_COMPLETED"
        assert res["total_accounts"] == 2
        assert res["successful_scans"] == 1
        assert res["failed_scans"] == 1
        assert len(res["collection_errors"]) == 1
        assert res["collection_errors"][0]["account_id"] == "222222222222"
