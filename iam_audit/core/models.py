"""Core IAM audit models and schemas."""

from typing import Any

from pydantic import BaseModel, Field


class PolicySource(BaseModel):
    """Represents a policy attached to an IAM entity."""

    scope: str = Field(..., description="Scope: User, Group, or Role")
    owner: str = Field(..., description="Name of the owning entity")
    type: str = Field(..., description="Type: managed or inline")
    name: str = Field(..., description="Policy name")
    arn: str | None = Field(None, description="Policy ARN (None for inline)")
    document: dict[str, Any] = Field(..., description="Policy document")


class PermissionAnalysis(BaseModel):
    """Result of analyzing a user's permissions."""

    username: str = Field(..., description="IAM username")
    groups: list[dict[str, Any]] = Field(default_factory=list)
    policies: list[PolicySource] = Field(default_factory=list)
    effective_actions: set[str] = Field(default_factory=set)
    denied_actions: set[str] = Field(default_factory=set)
    not_actions: list[dict[str, Any]] = Field(default_factory=list)
    constrained_statements: int = Field(0, description="Statements with Resource/Condition")


class SecurityFinding(BaseModel):
    """A single security finding from the audit."""

    id: str
    severity: str = Field(..., pattern="^(CRITICAL|HIGH|MEDIUM|LOW|WARNING|INFO)$")
    resource: str
    resource_type: str = "IAM User"
    issue: str
    impact: str
    recommendation: str


class AuditReport(BaseModel):
    """Complete audit report structure."""

    generated_at: str
    tool_name: str = "IAM Access Auditor & Permission Analyzer v2.0"
    total_users: int = 0
    total_groups: int = 0
    total_roles: int = 0
    critical_findings: int = 0
    warnings: int = 0
    overall_status: str = "HEALTHY"
    findings: list[SecurityFinding] = Field(default_factory=list)
    users_without_groups: list[str] = Field(default_factory=list)
    users_without_policies: list[str] = Field(default_factory=list)
    roles_without_policies: list[str] = Field(default_factory=list)
    empty_groups: list[str] = Field(default_factory=list)
    admin_accounts: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)


class UserComparisonResult(BaseModel):
    """Result of comparing two IAM users."""

    user1: str
    user2: str
    only_user1: list[str] = Field(default_factory=list)
    only_user2: list[str] = Field(default_factory=list)
    common: list[str] = Field(default_factory=list)
    user1_admin: bool = False
    user2_admin: bool = False
