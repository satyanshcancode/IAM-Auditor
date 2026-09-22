"""Tests for the Typer CLI."""

from pathlib import Path
from unittest.mock import patch

from typer.testing import CliRunner

from iam_audit.cli.main import app
from iam_audit.core.models import (
    AuditReport,
    PermissionAnalysis,
    SecurityFinding,
    UserComparisonResult,
)

runner = CliRunner()


def _report() -> AuditReport:
    return AuditReport(
        generated_at="2024-01-01T00:00:00+00:00",
        total_users=2,
        total_groups=1,
        total_roles=0,
        critical_findings=1,
        warnings=0,
        overall_status="NEEDS ATTENTION",
        findings=[
            SecurityFinding(
                id="IAM-001",
                severity="CRITICAL",
                resource="admin",
                issue="Admin access",
                impact="Full access",
                recommendation="Remove admin",
            )
        ],
        admin_accounts=["admin"],
    )


def test_audit_console() -> None:
    with patch("iam_audit.cli.main.run_full_audit", return_value=_report()):
        result = runner.invoke(app, ["audit"])
    assert result.exit_code == 0
    assert "NEEDS ATTENTION" in result.stdout


def test_audit_json_requires_output() -> None:
    result = runner.invoke(app, ["audit", "--format", "json"])
    assert result.exit_code == 2
    assert "--output is required" in result.stdout


def test_audit_unknown_format() -> None:
    result = runner.invoke(app, ["audit", "--format", "xml"])
    assert result.exit_code == 2
    assert "Unknown format" in result.stdout


def test_audit_json_export(tmp_path: Path) -> None:
    out = tmp_path / "report.json"
    with patch("iam_audit.cli.main.run_full_audit", return_value=_report()):
        result = runner.invoke(app, ["audit", "--format", "json", "--output", str(out)])
    assert result.exit_code == 0
    assert out.exists()
    assert "exported" in result.stdout


def test_audit_csv_and_sarif(tmp_path: Path) -> None:
    csv_path = tmp_path / "report.csv"
    sarif_path = tmp_path / "report.sarif"
    with patch("iam_audit.cli.main.run_full_audit", return_value=_report()):
        csv_result = runner.invoke(app, ["audit", "-f", "csv", "-o", str(csv_path)])
        sarif_result = runner.invoke(app, ["audit", "-f", "sarif", "-o", str(sarif_path)])
    assert csv_result.exit_code == 0
    assert sarif_result.exit_code == 0
    assert csv_path.exists()
    assert sarif_path.exists()


def test_inventory_command() -> None:
    data = {
        "users": [{"UserName": "alice"}],
        "groups": [{"GroupName": "devs"}],
        "roles": [{"RoleName": "lambda-role"}],
    }
    with patch("iam_audit.cli.main.list_inventory", return_value=data):
        result = runner.invoke(app, ["inventory"])
    assert result.exit_code == 0
    assert "alice" in result.stdout


def test_permissions_not_found() -> None:
    with patch("iam_audit.cli.main.get_user_analysis", return_value=None):
        result = runner.invoke(app, ["permissions", "nobody"])
    assert result.exit_code == 1


def test_permissions_json_export(tmp_path: Path) -> None:
    analysis = PermissionAnalysis(
        username="alice",
        effective_actions={"s3:GetObject", "logs:*"},
        denied_actions={"s3:DeleteObject"},
    )
    out = tmp_path / "alice.json"
    with patch("iam_audit.cli.main.get_user_analysis", return_value=analysis):
        result = runner.invoke(app, ["permissions", "alice", "--output", str(out)])
    assert result.exit_code == 0
    assert out.exists()
    body = out.read_text(encoding="utf-8")
    assert "alice" in body
    assert "s3:GetObject" in body


def test_check_allowed() -> None:
    with patch(
        "iam_audit.cli.main.check_permission",
        return_value={"allowed": True, "decision": "allowed"},
    ):
        result = runner.invoke(app, ["check", "alice", "s3:GetObject"])
    assert result.exit_code == 0
    assert "ALLOWED" in result.stdout


def test_check_error() -> None:
    with patch(
        "iam_audit.cli.main.check_permission",
        return_value={"allowed": False, "error": "User 'nobody' does not exist"},
    ):
        result = runner.invoke(app, ["check", "nobody", "s3:GetObject"])
    assert result.exit_code == 1


def test_search_found() -> None:
    with patch("iam_audit.cli.main.search_by_permission", return_value=["alice"]):
        result = runner.invoke(app, ["search", "s3:GetObject"])
    assert result.exit_code == 0
    assert "alice" in result.stdout


def test_search_none() -> None:
    with patch("iam_audit.cli.main.search_by_permission", return_value=[]):
        result = runner.invoke(app, ["search", "s3:GetObject"])
    assert result.exit_code == 0
    assert "No users" in result.stdout


def test_compare_users() -> None:
    result_model = UserComparisonResult(
        user1="alice",
        user2="bob",
        only_user1=["iam:CreateUser"],
        only_user2=["s3:PutObject"],
        common=["s3:GetObject"],
        user1_admin=True,
    )
    with patch("iam_audit.cli.main.compare_two_users", return_value=result_model):
        result = runner.invoke(app, ["compare", "alice", "bob"])
    assert result.exit_code == 0
    assert "alice" in result.stdout


def test_compare_missing() -> None:
    with patch("iam_audit.cli.main.compare_two_users", return_value=None):
        result = runner.invoke(app, ["compare", "a", "b"])
    assert result.exit_code == 1
