"""Tests for FastAPI layer."""

from unittest.mock import patch

from fastapi.testclient import TestClient

from iam_audit.api.main import app
from iam_audit.core.models import (
    AuditReport,
    PermissionAnalysis,
    UserComparisonResult,
)

client = TestClient(app)


def test_health() -> None:
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_root() -> None:
    response = client.get("/")
    assert response.status_code == 200
    assert "docs" in response.json()


def test_inventory_success() -> None:
    payload = {
        "users": [{"UserName": "alice"}],
        "groups": [{"GroupName": "devs"}],
        "roles": [{"RoleName": "role-a"}],
    }
    with patch("iam_audit.api.main.list_inventory", return_value=payload):
        response = client.get("/api/v1/inventory")
    assert response.status_code == 200
    assert response.json()["users"][0]["UserName"] == "alice"


def test_inventory_error() -> None:
    with patch("iam_audit.api.main.list_inventory", side_effect=RuntimeError("boom")):
        response = client.get("/api/v1/inventory")
    assert response.status_code == 500
    assert response.json()["detail"] == "boom"


def test_audit_success() -> None:
    report = AuditReport(
        generated_at="2024-01-01T00:00:00+00:00",
        total_users=1,
        overall_status="HEALTHY",
    )
    with patch("iam_audit.api.main.run_full_audit", return_value=report):
        response = client.get("/api/v1/audit")
    assert response.status_code == 200
    assert response.json()["overall_status"] == "HEALTHY"


def test_user_permissions_not_found() -> None:
    with patch("iam_audit.api.main.get_user_analysis", return_value=None):
        response = client.get("/api/v1/users/nobody/permissions")
    assert response.status_code == 404


def test_user_permissions_ok() -> None:
    analysis = PermissionAnalysis(username="alice", effective_actions={"s3:GetObject"})
    with patch("iam_audit.api.main.get_user_analysis", return_value=analysis):
        response = client.get("/api/v1/users/alice/permissions")
    assert response.status_code == 200
    assert response.json()["username"] == "alice"


def test_permission_check() -> None:
    with patch(
        "iam_audit.api.main.check_permission",
        return_value={"username": "alice", "action": "s3:GetObject", "allowed": True, "decision": "allowed"},
    ):
        response = client.post(
            "/api/v1/permissions/check",
            json={"username": "alice", "action": "s3:GetObject"},
        )
    assert response.status_code == 200
    assert response.json()["allowed"] is True


def test_permission_search_error() -> None:
    with patch("iam_audit.api.main.search_by_permission", side_effect=RuntimeError("aws down")):
        response = client.post("/api/v1/permissions/search", json={"action": "s3:GetObject"})
    assert response.status_code == 500


def test_permission_search_ok() -> None:
    with patch("iam_audit.api.main.search_by_permission", return_value=["alice"]):
        response = client.post("/api/v1/permissions/search", json={"action": "s3:GetObject"})
    assert response.status_code == 200
    assert response.json()["count"] == 1


def test_compare_users() -> None:
    result = UserComparisonResult(user1="alice", user2="bob", common=["s3:GetObject"])
    with patch("iam_audit.api.main.compare_two_users", return_value=result):
        response = client.get("/api/v1/users/compare", params={"user1": "alice", "user2": "bob"})
    assert response.status_code == 200
    assert response.json()["user1"] == "alice"


def test_compare_users_not_found() -> None:
    with patch("iam_audit.api.main.compare_two_users", return_value=None):
        response = client.get("/api/v1/users/compare", params={"user1": "a", "user2": "b"})
    assert response.status_code == 404


def test_api_key_required(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv("IAM_AUDIT_API_KEY", "secret")
    response = client.get("/api/v1/inventory")
    assert response.status_code == 401

    with patch("iam_audit.api.main.list_inventory", return_value={"users": [], "groups": [], "roles": []}):
        authorized = client.get("/api/v1/inventory", headers={"X-API-Key": "secret"})
    assert authorized.status_code == 200
    # health remains public
    assert client.get("/health").status_code == 200
