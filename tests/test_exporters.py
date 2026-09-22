"""Tests for exporters."""

import csv
import json
import tempfile
import unittest
from pathlib import Path

from iam_audit.core.models import AuditReport, PermissionAnalysis, SecurityFinding
from iam_audit.exporters.base import (
    export_console_summary,
    export_csv,
    export_json,
    export_sarif,
)


class TestExporters(unittest.TestCase):
    def setUp(self) -> None:
        self.report = AuditReport(
            generated_at="2024-01-01T00:00:00+00:00",
            total_users=3,
            total_groups=2,
            total_roles=1,
            critical_findings=1,
            warnings=1,
            overall_status="NEEDS ATTENTION",
            findings=[
                SecurityFinding(
                    id="IAM-001",
                    severity="CRITICAL",
                    resource="admin",
                    resource_type="IAM User",
                    issue="Admin access",
                    impact="Full access",
                    recommendation="Remove admin",
                ),
                SecurityFinding(
                    id="IAM-002",
                    severity="WARNING",
                    resource="empty-group",
                    resource_type="IAM Group",
                    issue="Empty group",
                    impact="Complexity",
                    recommendation="Delete",
                ),
            ],
            admin_accounts=["admin"],
            empty_groups=["empty-group"],
        )

    def test_export_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "report.json"
            export_json(self.report, path)

            with open(path) as f:
                data = json.load(f)

            self.assertEqual(data["total_users"], 3)
            self.assertEqual(len(data["findings"]), 2)

    def test_export_json_permission_analysis(self) -> None:
        analysis = PermissionAnalysis(
            username="alice",
            effective_actions={"s3:GetObject", "ec2:Describe*"},
            denied_actions={"s3:DeleteObject"},
        )
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "alice.json"
            export_json(analysis, path)
            with open(path) as f:
                data = json.load(f)
            self.assertEqual(data["username"], "alice")
            self.assertIn("s3:GetObject", data["effective_actions"])
            self.assertIn("s3:DeleteObject", data["denied_actions"])

    def test_export_json_plain_dict(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "raw.json"
            export_json({"ok": True, "tags": {"b", "a"}}, path)
            with open(path) as f:
                data = json.load(f)
            self.assertEqual(data["ok"], True)
            self.assertEqual(data["tags"], ["a", "b"])

    def test_export_csv(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "report.csv"
            export_csv(self.report, path)

            with open(path, newline="") as f:
                reader = csv.reader(f)
                rows = list(reader)

            self.assertEqual(
                rows[0],
                [
                    "Finding ID",
                    "Severity",
                    "Resource",
                    "Resource Type",
                    "Issue",
                    "Impact",
                    "Recommendation",
                ],
            )
            self.assertEqual(len(rows), 3)  # header + 2 findings

    def test_export_sarif(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "report.sarif"
            export_sarif(self.report, path)

            with open(path) as f:
                data = json.load(f)

            self.assertEqual(data["version"], "2.1.0")
            self.assertEqual(len(data["runs"][0]["results"]), 2)

    def test_export_console_summary(self) -> None:
        summary = export_console_summary(self.report)
        self.assertIn("NEEDS ATTENTION", summary)
        self.assertIn("IAM-001", summary)


if __name__ == "__main__":
    unittest.main()
