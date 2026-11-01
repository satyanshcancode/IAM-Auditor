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


class AttackPathStep(BaseModel):
    """Step in an attack path sequence."""

    step_number: int
    source_entity: str
    action_or_edge: str
    target_entity: str
    evidence: str


class AttackPath(BaseModel):
    """Chained multi-step attack path graph finding."""

    path_id: str
    title: str
    initiating_principal: str
    target_principal_or_resource: str
    steps: list[AttackPathStep] = Field(default_factory=list)
    confidence: str = "CONFIRMED"
    severity: str = "HIGH"
    risk_summary: str
    remediation: str


class SecurityFinding(BaseModel):
    """A single security finding from the audit."""

    id: str
    rule_id: str | None = None
    category: str = Field(
        default="HYGIENE",
        pattern="^(PRIVILEGE_ESCALATION|SERVICE_WILDCARD|ROLE_TRUST|HYGIENE|ORGANIZATION|LEAST_PRIVILEGE)$",
    )
    severity: str = Field(..., pattern="^(CRITICAL|HIGH|MEDIUM|LOW|WARNING|INFO)$")
    confidence: str = Field(
        default="CONFIRMED",
        pattern="^(CONFIRMED|POTENTIAL_PATH|SUSPICIOUS_REVIEW|INSUFFICIENT_EVIDENCE)$",
    )
    resource: str
    resource_type: str = "IAM User"
    account_id: str | None = None
    entity_name: str | None = None
    access_key_id: str | None = None
    policy_name: str | None = None
    issue: str
    impact: str
    recommendation: str
    evidence: dict[str, Any] | str | None = None
    detection_source: str = "IAM Audit Engine"
    collection_status: str = "CONFIRMED"
    compliance_mappings: list[str] = Field(default_factory=list)


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
    attack_paths: list[AttackPath] = Field(default_factory=list)
    users_without_groups: list[str] = Field(default_factory=list)
    users_without_policies: list[str] = Field(default_factory=list)
    roles_without_policies: list[str] = Field(default_factory=list)
    empty_groups: list[str] = Field(default_factory=list)
    admin_accounts: list[str] = Field(default_factory=list)
    mfa_issues: int = 0
    old_access_keys: int = 0
    unused_access_keys: int = 0
    inactive_users: int = 0
    inline_policies_count: int = 0
    privilege_escalation_count: int = 0
    sensitive_wildcard_count: int = 0
    role_trust_issue_count: int = 0
    collection_errors: list[dict[str, Any]] = Field(default_factory=list)
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


# Phase 3 Models


class AccountScanResult(BaseModel):
    """Scan status and findings for a single AWS account."""

    account_id: str
    account_name: str
    status: str = Field("FAILED", pattern="^(SUCCESS|FAILED)$")
    error: str | None = None
    findings_count: int = 0
    report: dict[str, Any] | None = None


class MultiAccountAuditReport(BaseModel):
    """Aggregated organization-wide multi-account audit report."""

    scan_status: str = Field(..., pattern="^(COMPLETE|PARTIAL_SCAN_COMPLETED|FAILED)$")
    total_accounts: int = 0
    successful_scans: int = 0
    failed_scans: int = 0
    account_results: list[AccountScanResult] = Field(default_factory=list)
    aggregated_findings: list[SecurityFinding] = Field(default_factory=list)
    collection_errors: list[dict[str, Any]] = Field(default_factory=list)


class ServiceLastAccessedDetail(BaseModel):
    """Details of service last accessed history."""

    service_name: str | None = None
    service_namespace: str
    last_authenticated: str | None = None
    total_authenticated_entities: int = 0
    tracked_status: str = Field("NO_DATA", pattern="^(ACTIVE|CONFIRMED_INACTIVE|NO_DATA)$")


class AccessAdvisorReport(BaseModel):
    """Access Advisor analysis and service last accessed report."""

    arn: str
    job_status: str
    services: list[ServiceLastAccessedDetail] = Field(default_factory=list)
    active_services: list[str] = Field(default_factory=list)
    inactive_services: list[str] = Field(default_factory=list)
    no_data_services: list[str] = Field(default_factory=list)
    evidence: list[dict[str, Any]] = Field(default_factory=list)
    error: str | None = None


class RightSizedPolicyResponse(BaseModel):
    """Candidate right-sized policy proposal."""

    policy_name: str
    original_policy: dict[str, Any]
    proposed_policy: dict[str, Any]
    pruned_services: list[str] = Field(default_factory=list)
    safeguarded_permissions: list[str] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)


class RemediationScript(BaseModel):
    """Generated remediation script response."""

    finding_id: str
    rule_id: str
    resource: str
    script_type: str = "bash"
    script_content: str
    dry_run_supported: bool = True
    rollback_instructions: str
