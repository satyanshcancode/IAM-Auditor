import unittest
from unittest.mock import patch

from aws.compare import is_covered
from aws.report import build_findings, collect_account_audit


class CompareTests(unittest.TestCase):
    def test_is_covered_supports_iam_wildcards(self):
        self.assertTrue(is_covered("s3:GetObject", {"s3:*"}))
        self.assertTrue(is_covered("s3:GetObject", {"s3:Get*"}))
        self.assertTrue(is_covered("iam:CreateUser", {"*"}))
        self.assertFalse(is_covered("s3:DeleteObject", {"s3:Get*"}))


class ReportTests(unittest.TestCase):
    def test_build_findings_assigns_unique_ids(self):
        with patch(
            "aws.report.find_admin_accounts",
            return_value=["alice", "bob"],
        ), patch(
            "aws.report.find_empty_groups",
            return_value=["UnusedGroup"],
        ):
            findings = build_findings()

        self.assertEqual(
            [finding["id"] for finding in findings],
            ["IAM-001", "IAM-002", "IAM-003"],
        )
        self.assertEqual(
            [finding["severity"] for finding in findings],
            ["CRITICAL", "CRITICAL", "WARNING"],
        )


class CollectAuditTests(unittest.TestCase):
    def test_collect_account_audit_analyzes_each_user_once(self) -> None:
        analyses = {
            "admin": {
                "groups": [],
                "effective_actions": {"*"},
                "denied_actions": set(),
            },
            "alice": {
                "groups": [{"GroupName": "devs"}],
                "effective_actions": {"s3:GetObject"},
                "denied_actions": set(),
            },
        }
        calls: list[str] = []

        def fake_analyze(username: str):
            calls.append(username)
            return analyses[username]

        with (
            patch(
                "aws.report.iam_policies.list_users",
                return_value=[{"UserName": "admin"}, {"UserName": "alice"}],
            ),
            patch("aws.report.iam_policies.list_groups", return_value=[]),
            patch("aws.report.iam_policies.list_roles", return_value=[]),
            patch("aws.report.analyze_user_permissions", side_effect=fake_analyze),
            patch("aws.report.find_empty_groups", return_value=[]),
            patch("aws.report.roles_without_policies", return_value=[]),
        ):
            snapshot = collect_account_audit()

        self.assertEqual(calls, ["admin", "alice"])
        self.assertEqual(snapshot["admin_accounts"], ["admin"])
        self.assertEqual(snapshot["users_without_groups"], ["admin"])
        self.assertEqual(len(snapshot["findings"]), 1)


if __name__ == "__main__":
    unittest.main()
