"""FastAPI REST API for IAM Access Auditor."""

import os
from typing import Any

from fastapi import APIRouter, Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel

from iam_audit.core.engine import (
    check_permission,
    compare_two_users,
    get_user_analysis,
    list_inventory,
    run_full_audit,
    search_by_permission,
)
from iam_audit.core.models import AuditReport, PermissionAnalysis, UserComparisonResult

app = FastAPI(
    title="IAM Access Auditor API",
    description=(
        "REST API for AWS IAM permission analysis and security auditing. "
        "Set IAM_AUDIT_API_KEY and send it as X-API-Key to protect inventory endpoints."
    ),
    version="2.0.0",
)


class PermissionCheckRequest(BaseModel):
    username: str
    action: str


class PermissionCheckResponse(BaseModel):
    username: str
    action: str
    allowed: bool
    decision: str | None = None
    error: str | None = None


class SearchRequest(BaseModel):
    action: str


def require_api_key(x_api_key: str | None = Header(default=None, alias="X-API-Key")) -> None:
    """Require X-API-Key when IAM_AUDIT_API_KEY is configured."""
    expected = os.environ.get("IAM_AUDIT_API_KEY", "").strip()
    if not expected:
        return
    if not x_api_key or x_api_key != expected:
        raise HTTPException(status_code=401, detail="Invalid or missing API key")


def _call(fn: Any, *args: Any, **kwargs: Any) -> Any:
    try:
        return fn(*args, **kwargs)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e


protected = APIRouter(prefix="/api/v1", dependencies=[Depends(require_api_key)])


@app.get("/")
def root() -> dict[str, str]:
    return {"message": "IAM Access Auditor API v2.0", "docs": "/docs"}


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@protected.get("/inventory")
def inventory() -> dict[str, Any]:
    """Get full IAM inventory (users, groups, roles)."""
    data: dict[str, Any] = _call(list_inventory)
    return data


@protected.get("/audit")
def audit() -> AuditReport:
    """Run a full security audit."""
    report: AuditReport = _call(run_full_audit)
    return report


@protected.get("/users/{username}/permissions")
def user_permissions(username: str) -> PermissionAnalysis:
    """Get permission analysis for a specific user."""
    result: PermissionAnalysis | None = _call(get_user_analysis, username)
    if result is None:
        raise HTTPException(status_code=404, detail=f"User '{username}' not found")
    return result


@protected.post("/permissions/check", response_model=PermissionCheckResponse)
def permission_check(req: PermissionCheckRequest) -> dict[str, Any]:
    """Check if a user has a specific permission."""
    result: dict[str, Any] = _call(check_permission, req.username, req.action)
    return result


@protected.post("/permissions/search")
def permission_search(req: SearchRequest) -> dict[str, Any]:
    """Search for users with a specific permission."""
    matched = _call(search_by_permission, req.action)
    return {"action": req.action, "matched_users": matched, "count": len(matched)}


@protected.get("/users/compare")
def compare_users(user1: str, user2: str) -> UserComparisonResult:
    """Compare permissions between two users."""
    result: UserComparisonResult | None = _call(compare_two_users, user1, user2)
    if result is None:
        raise HTTPException(status_code=404, detail="One or both users not found")
    return result


app.include_router(protected)