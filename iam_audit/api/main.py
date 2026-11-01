"""FastAPI REST API for IAM Access Auditor."""

import logging
import os
import secrets
from typing import Any

from fastapi import APIRouter, Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel

from iam_audit.core.engine import (
    build_remediation_script,
    build_right_sized_policy,
    check_permission,
    compare_two_users,
    get_user_analysis,
    list_inventory,
    run_access_advisor_audit,
    run_full_audit,
    run_organization_audit,
    search_by_permission,
    validate_and_simulate_policy,
)
from iam_audit.core.models import (
    AccessAdvisorReport,
    AuditReport,
    MultiAccountAuditReport,
    PermissionAnalysis,
    RemediationScript,
    RightSizedPolicyResponse,
    UserComparisonResult,
)

logger = logging.getLogger(__name__)

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


# Phase 3 API Models
class OrgAuditRequest(BaseModel):
    role_name: str = "IAMAuditorRole"
    account_ids: list[str] | None = None
    external_id: str | None = None
    max_workers: int = 5


class RightSizePolicyRequest(BaseModel):
    policy_doc: dict[str, Any]
    inactive_services: list[str]
    policy_name: str = "ProposedRightSizedPolicy"


class RemediationRequest(BaseModel):
    finding: dict[str, Any]
    account_id: str = "123456789012"


class PolicyValidationRequest(BaseModel):
    policy_doc: dict[str, Any]
    action_names: list[str]


def require_api_key(x_api_key: str | None = Header(default=None, alias="X-API-Key")) -> None:
    """Require X-API-Key. Fails closed when IAM_AUDIT_API_KEY is unset."""
    expected = os.environ.get("IAM_AUDIT_API_KEY", "").strip()
    if not expected:
        raise HTTPException(
            status_code=503,
            detail="IAM_AUDIT_API_KEY is not configured; refusing to serve /api/v1",
        )
    if not x_api_key or not secrets.compare_digest(x_api_key, expected):
        raise HTTPException(status_code=401, detail="Invalid or missing API key")


def _call(fn: Any, *args: Any, **kwargs: Any) -> Any:
    try:
        return fn(*args, **kwargs)
    except HTTPException:
        raise
    except Exception:
        logger.exception("API request failed")
        raise HTTPException(status_code=500, detail="Internal server error") from None


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
    if result.get("error"):
        raise HTTPException(status_code=404, detail=f"User '{req.username}' not found")
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


# Phase 3 Endpoints


@protected.post("/org/audit", response_model=MultiAccountAuditReport)
def org_audit(req: OrgAuditRequest) -> MultiAccountAuditReport:
    """Run multi-account organization audit scan."""
    report: MultiAccountAuditReport = _call(
        run_organization_audit,
        role_name=req.role_name,
        account_ids=req.account_ids,
        external_id=req.external_id,
        max_workers=req.max_workers,
    )
    return report


@protected.get("/access-advisor/{arn:path}", response_model=AccessAdvisorReport)
def access_advisor_endpoint(arn: str, threshold_days: int = 90) -> AccessAdvisorReport:
    """Get Access Advisor service last accessed analysis for an IAM entity ARN."""
    report: AccessAdvisorReport = _call(run_access_advisor_audit, arn=arn, threshold_days=threshold_days)
    return report


@protected.post("/policies/right-size", response_model=RightSizedPolicyResponse)
def right_size_policy(req: RightSizePolicyRequest) -> RightSizedPolicyResponse:
    """Generate candidate right-sized policy proposal."""
    res: RightSizedPolicyResponse = _call(
        build_right_sized_policy,
        original_policy_doc=req.policy_doc,
        inactive_services=req.inactive_services,
        policy_name=req.policy_name,
    )
    return res


@protected.post("/remediations/generate", response_model=RemediationScript)
def generate_remediation(req: RemediationRequest) -> RemediationScript:
    """Generate safe remediation shell script artifact."""
    res: RemediationScript = _call(
        build_remediation_script,
        finding=req.finding,
        account_id=req.account_id,
    )
    return res


@protected.post("/policies/validate")
def validate_policy(req: PolicyValidationRequest) -> dict[str, Any]:
    """Validate JSON policy syntax and simulate actions."""
    res: dict[str, Any] = _call(
        validate_and_simulate_policy,
        policy_doc=req.policy_doc,
        action_names=req.action_names,
    )
    return res


app.include_router(protected)
