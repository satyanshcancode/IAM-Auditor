"""Enhanced tests for IAM audit engine with type hints."""

import unittest
from unittest.mock import patch

from botocore.exceptions import ClientError

from iam_audit.core.engine import (
    check_permission,
    compare_two_users,
    get_user_analysis,
    list_inventory,
    run_full_audit,
    search_by_permission,
)
from iam_audit.core.models import PermissionAnalysis, UserComparisonResult, AuditReport, SecurityFinding


class FakeIAM:
    """Mock IAM client for testing."""

    def __init__(self):
        self.managed_documents = {
            "arn:user-managed": {
                "Statement": {
                    "Effect": "Allow",
                    "Action": ["s3:GetObject", "ec2:Describe*"],
                    "Resource": "*",
                }
            },
            "arn:group-managed": {
                "Statement": [
                    {"Effect": "Allow", "Action": "logs:*", "Resource": "*"},
                    {"Effect": "Deny", "Action": "s3:DeleteObject", "Resource": "*"},
                ]
            },
        }

    def get_user(self, UserName: str) -> dict:
        return {
            "User": {
                "UserName": UserName,
                "Arn": f"arn:aws:iam::123456789012:user/{UserName}",
            }
        }

    def get_paginator(self, operation_name: str):
        pages = {
            "list_groups_for_user": [{"Groups": [{"GroupName": "Developers"}]}],
            "list_attached_user_policies": [
                {
                    "AttachedPolicies": [
                        {"PolicyName": "UserManaged", "PolicyArn": "arn:user-managed"}
                    ]
                }
            ],
            "list_user_policies": [{"PolicyNames": ["UserInline"]}],
            "list_attached_group_policies": [
                {
                    "AttachedPolicies": [
                        {"PolicyName": "GroupManaged", "PolicyArn": "arn:group-managed"}
                    ]
                }
            ],
            "list_group_policies": [{"PolicyNames": ["GroupInline"]}],
        }

        class Paginator:
            def __init__(self, p):
                self.pages = p

            def paginate(self, **kwargs):
                return self.pages

        return Paginator(pages[operation_name])

    def get_policy(self, PolicyArn: str) -> dict:
        return {"Policy": {"DefaultVersionId": "v1"}}

    def get_policy_version(self, PolicyArn: str, VersionId: str) -> dict:
        return {"PolicyVersion": {"Document": self.managed_documents[PolicyArn]}}

    def get_user_policy(self, UserName: str, PolicyName: str) -> dict:
        return {
            "PolicyDocument": {
                "Statement": {"Effect": "Allow", "Action": "iam:CreateUser", "Resource": "*"}
            }
        }

    def get_group_policy(self, GroupName: str, PolicyName: str) -> dict:
        return {
            "PolicyDocument": {
                "Statement": {"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": "*"}
            }
        }

    def simulate_principal_policy(self, PolicySourceArn: str, ActionNames: list[str]) -> dict:
        return {"EvaluationResults": [{"EvalDecision": "allowed"}]}


class TestPermissionAnalysis(unittest.TestCase):
    def test_get_user_analysis(self):
        with patch("aws.policies.iam", FakeIAM()):
            result = get_user_analysis("alice")

        self.assertIsNotNone(result)
        assert isinstance(result, PermissionAnalysis)
        self.assertEqual(result.username, "alice")
        self.assertIn("s3:GetObject", result.effective_actions)
        self.assertIn("ec2:Describe*", result.effective_actions)
        self.assertIn("s3:DeleteObject", result.denied_actions)

    def test_get_user_analysis_not_found(self):
        fake = FakeIAM()
        fake.get_user = lambda **kwargs: (_ for _ in ()).throw(
            ClientError({"Error": {"Code": "NoSuchEntity", "Message": "Not found"}}, "GetUser")
        )

        with patch("aws.policies.iam", fake):
            result = get_user_analysis("nobody")

        self.assertIsNone(result)


class TestPermissionCheck(unittest.TestCase):
    def test_check_permission_allowed(self):
        with patch("aws.policies.iam", FakeIAM()):
            result = check_permission("alice", "s3:GetObject")

        self.assertTrue(result["allowed"])
        self.assertEqual(result["decision"], "allowed")

    def test_check_permission_user_not_found(self):
        fake = FakeIAM()
        fake.get_user = lambda **kwargs: (_ for _ in ()).throw(
            ClientError({"Error": {"Code": "NoSuchEntity", "Message": "Not found"}}, "GetUser")
        )

        with patch("aws.policies.iam", fake):
            result = check_permission("nobody", "s3:GetObject")

        self.assertFalse(result["allowed"])
        self.assertIn("does not exist", result["error"])


class TestSearchByPermission(unittest.TestCase):
    def test_search_found(self):
        with patch("aws.policies.iam", FakeIAM()):
            with patch("aws.policies.list_users", return_value=[
                {"UserName": "alice", "Arn": "arn:aws:iam::123456789012:user/alice"},
                {"UserName": "bob", "Arn": "arn:aws:iam::123456789012:user/bob"},
            ]):
                result = search_by_permission("s3:GetObject")

        self.assertIn("alice", result)
        self.assertIn("bob", result)


class TestCompareUsers(unittest.TestCase):
    def test_compare_users(self):
        with patch("aws.policies.iam", FakeIAM()):
            result = compare_two_users("alice", "bob")

        self.assertIsNotNone(result)
        assert isinstance(result, UserComparisonResult)
        self.assertEqual(result.user1, "alice")
        self.assertEqual(result.user2, "bob")


class TestFullAuditAndInventory(unittest.TestCase):
    def test_run_full_audit(self) -> None:
        snapshot = {
            "users": [{"UserName": "admin"}],
            "groups": [{"GroupName": "empty"}],
            "roles": [],
            "admin_accounts": ["admin"],
            "empty_groups": ["empty"],
            "users_without_groups": ["admin"],
            "users_without_policies": [],
            "roles_without_policies": [],
            "findings": [
                {
                    "id": "IAM-001",
                    "severity": "CRITICAL",
                    "resource": "admin (IAM User)",
                    "resource_type": "IAM User",
                    "issue": "AdministratorAccess grants unrestricted access (*).",
                    "impact": "This account has unrestricted access to all AWS resources.",
                    "recommendation": "Replace AdministratorAccess with least-privilege permissions.",
                }
            ],
        }
        with patch("iam_audit.core.engine.collect_account_audit", return_value=snapshot):
            report = run_full_audit()

        self.assertEqual(report.total_users, 1)
        self.assertEqual(report.critical_findings, 1)
        self.assertEqual(report.overall_status, "NEEDS ATTENTION")
        self.assertEqual(report.admin_accounts, ["admin"])

    def test_list_inventory(self) -> None:
        with (
            patch("iam_audit.core.engine.iam_policies.list_users", return_value=[{"UserName": "a"}]),
            patch("iam_audit.core.engine.iam_policies.list_groups", return_value=[]),
            patch("iam_audit.core.engine.iam_policies.list_roles", return_value=[{"RoleName": "r"}]),
        ):
            data = list_inventory()

        self.assertEqual(len(data["users"]), 1)
        self.assertEqual(len(data["roles"]), 1)


class TestAuditReport(unittest.TestCase):
    def test_audit_report_model(self):
        from datetime import datetime, timezone

        finding = SecurityFinding(
            id="IAM-001",
            severity="CRITICAL",
            resource="admin-user",
            issue="Admin access",
            impact="Full access",
            recommendation="Remove admin",
        )

        report = AuditReport(
            generated_at=datetime.now(timezone.utc).isoformat(),
            total_users=5,
            critical_findings=1,
            findings=[finding],
        )

        self.assertEqual(report.critical_findings, 1)
        self.assertEqual(report.overall_status, "HEALTHY")


if __name__ == "__main__":
    unittest.main()
