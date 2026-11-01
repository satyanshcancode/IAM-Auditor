"""Core business logic for the IAM audit application."""

from datetime import datetime, timezone

from aws import access_advisor, organizations, policy_validator, remediation
from aws import policies as iam_policies
from aws.compare import compute_user_comparison
from aws.permissions import analyze_user_permissions
from aws.report import collect_account_audit, recommended_actions
from aws.search import find_users_with_permission
from iam_audit.core.models import (
    AccessAdvisorReport,
    AccountScanResult,
    AttackPath,
    AuditReport,
    MultiAccountAuditReport,
    PermissionAnalysis,
    PolicySource,
    RemediationScript,
    RightSizedPolicyResponse,
    SecurityFinding,
    ServiceLastAccessedDetail,
    UserComparisonResult,
)


def get_user_analysis(username: str) -> PermissionAnalysis | None:
    """Return structured permission analysis for an IAM user."""

    analysis = analyze_user_permissions(username)

    if analysis is None:
        return None

    return PermissionAnalysis(
        username=username,
        groups=analysis.get("groups", []),
        policies=[PolicySource(**source) for source in analysis.get("policies", [])],
        effective_actions=set(analysis.get("effective_actions", set())),
        denied_actions=set(analysis.get("denied_actions", set())),
        not_actions=analysis.get("not_actions", []),
        constrained_statements=analysis.get(
            "constrained_statements",
            0,
        ),
    )


def check_permission(username: str, action: str) -> dict:
    """Check an IAM action using AWS policy simulation."""

    try:
        user = iam_policies.iam.get_user(UserName=username)["User"]

    except Exception as exc:
        code = (
            getattr(
                exc,
                "response",
                {},
            )
            .get(
                "Error",
                {},
            )
            .get("Code")
        )

        if code == "NoSuchEntity":
            return {
                "username": username,
                "action": action,
                "allowed": False,
                "decision": "denied",
                "error": (f"User '{username}' does not exist."),
            }

        raise

    response = iam_policies.iam.simulate_principal_policy(
        PolicySourceArn=user["Arn"],
        ActionNames=[action],
    )

    results = response.get(
        "EvaluationResults",
        [],
    )

    decision = (
        results[0].get(
            "EvalDecision",
            "implicitDeny",
        )
        if results
        else "implicitDeny"
    )

    return {
        "username": username,
        "action": action,
        "allowed": decision.lower() == "allowed",
        "decision": decision.lower(),
    }


def search_by_permission(action: str) -> list[str]:
    """Return users allowed to perform an IAM action."""

    return find_users_with_permission(action)


def compare_two_users(
    user1: str,
    user2: str,
) -> UserComparisonResult | None:
    """Compare effective permissions of two IAM users."""

    result = compute_user_comparison(
        user1,
        user2,
    )

    if result is None:
        return None

    return UserComparisonResult(
        user1=result["user1"],
        user2=result["user2"],
        only_user1=result["only_user1"],
        only_user2=result["only_user2"],
        common=result["common"],
        user1_admin=result["user1_admin"],
        user2_admin=result["user2_admin"],
    )


def list_inventory() -> dict:
    """Return the IAM users, groups, and roles."""

    return {
        "users": iam_policies.list_users(),
        "groups": iam_policies.list_groups(),
        "roles": iam_policies.list_roles(),
    }


def run_full_audit() -> AuditReport:
    """Run the complete IAM account audit."""

    snapshot = collect_account_audit()

    findings = [SecurityFinding(**finding) for finding in snapshot.get("findings", [])]

    critical_findings = sum(finding.severity == "CRITICAL" for finding in findings)
    warnings = sum(finding.severity in ("WARNING", "HIGH") for finding in findings)

    mfa_issues = sum(
        1 for f in findings if f.id in ("IAM_CONSOLE_USER_NO_MFA", "IAM_ROOT_NO_MFA")
    )
    old_access_keys = sum(1 for f in findings if f.id == "IAM_ACCESS_KEY_OLD")
    unused_access_keys = sum(
        1 for f in findings if f.id in ("IAM_ACCESS_KEY_UNUSED", "IAM_ACCESS_KEY_NEVER_USED")
    )
    inactive_users = sum(1 for f in findings if f.id == "IAM_USER_INACTIVE")
    inline_policies_count = sum(1 for f in findings if f.id == "IAM_INLINE_POLICY_PRESENT")
    privilege_escalation_count = sum(1 for f in findings if f.id == "IAM_PRIVILEGE_ESCALATION")
    sensitive_wildcard_count = sum(1 for f in findings if f.category == "SERVICE_WILDCARD")
    role_trust_issue_count = sum(1 for f in findings if f.category == "ROLE_TRUST")

    attack_paths = [AttackPath(**ap) for ap in snapshot.get("attack_paths", [])]

    overall_status = (
        "NEEDS ATTENTION"
        if critical_findings or warnings or privilege_escalation_count or role_trust_issue_count
        else "HEALTHY"
    )

    recommendations = recommended_actions(
        snapshot.get("admin_accounts", []), snapshot.get("empty_groups", [])
    )
    if privilege_escalation_count:
        recommendations.append("Remediate IAM privilege escalation paths by restricting iam:PassRole and policy attachment.")
    if role_trust_issue_count:
        recommendations.append("Restrict IAM role trust policies by removing wildcard principals and enforcing conditions.")
    if mfa_issues:
        recommendations.append("Enforce Multi-Factor Authentication (MFA) across all console users.")
    if old_access_keys or unused_access_keys:
        recommendations.append("Rotate old access keys and deactivate unused IAM credentials.")
    if inactive_users:
        recommendations.append("Remove or disable inactive IAM user accounts.")
    if inline_policies_count:
        recommendations.append("Migrate inline policies to managed policies for better governance.")

    return AuditReport(
        generated_at=datetime.now(timezone.utc).isoformat(),
        total_users=len(snapshot.get("users", [])),
        total_groups=len(snapshot.get("groups", [])),
        total_roles=len(snapshot.get("roles", [])),
        critical_findings=critical_findings,
        warnings=warnings,
        overall_status=overall_status,
        findings=findings,
        attack_paths=attack_paths,
        users_without_groups=snapshot.get("users_without_groups", []),
        users_without_policies=snapshot.get("users_without_policies", []),
        roles_without_policies=snapshot.get("roles_without_policies", []),
        empty_groups=snapshot.get("empty_groups", []),
        admin_accounts=snapshot.get("admin_accounts", []),
        mfa_issues=mfa_issues,
        old_access_keys=old_access_keys,
        unused_access_keys=unused_access_keys,
        inactive_users=inactive_users,
        inline_policies_count=inline_policies_count,
        privilege_escalation_count=privilege_escalation_count,
        sensitive_wildcard_count=sensitive_wildcard_count,
        role_trust_issue_count=role_trust_issue_count,
        collection_errors=snapshot.get("collection_errors", []),
        recommendations=recommendations,
    )


# Phase 3 Engine Functions


def run_organization_audit(
    role_name: str = "IAMAuditorRole",
    account_ids: list[str] | None = None,
    external_id: str | None = None,
    max_workers: int = 5,
) -> MultiAccountAuditReport:
    """Perform a multi-account AWS Organization audit scan with bounded concurrency."""
    raw_res = organizations.scan_organization(
        role_name=role_name,
        account_ids=account_ids,
        external_id=external_id,
        max_workers=max_workers,
    )

    account_results = []
    for acc_res in raw_res.get("account_results", []):
        account_results.append(
            AccountScanResult(
                account_id=acc_res["account_id"],
                account_name=acc_res["account_name"],
                status=acc_res["status"],
                error=acc_res.get("error"),
                findings_count=acc_res.get("findings_count", 0),
                report=acc_res.get("report"),
            )
        )

    aggregated_findings = []
    for f in raw_res.get("aggregated_findings", []):
        if isinstance(f, dict):
            aggregated_findings.append(SecurityFinding(**f))
        else:
            aggregated_findings.append(f)

    return MultiAccountAuditReport(
        scan_status=raw_res["scan_status"],
        total_accounts=raw_res["total_accounts"],
        successful_scans=raw_res["successful_scans"],
        failed_scans=raw_res["failed_scans"],
        account_results=account_results,
        aggregated_findings=aggregated_findings,
        collection_errors=raw_res["collection_errors"],
    )


def run_access_advisor_audit(
    arn: str,
    threshold_days: int = 90,
) -> AccessAdvisorReport:
    """Generate and analyze IAM service last accessed details for an entity ARN."""
    raw_details = access_advisor.get_service_last_accessed_details(arn=arn)
    job_status = raw_details.get("job_status", "NO_DATA")
    services = raw_details.get("services", [])
    error = raw_details.get("error")

    analysis = access_advisor.analyze_unused_services(
        services_last_accessed=services,
        threshold_days=threshold_days,
    )

    parsed_services = [ServiceLastAccessedDetail(**s) for s in services]

    return AccessAdvisorReport(
        arn=arn,
        job_status=job_status,
        services=parsed_services,
        active_services=analysis.get("active_services", []),
        inactive_services=analysis.get("inactive_services", []),
        no_data_services=analysis.get("no_data_services", []),
        evidence=analysis.get("evidence", []),
        error=error,
    )


def build_right_sized_policy(
    original_policy_doc: dict,
    inactive_services: list[str],
    policy_name: str = "ProposedRightSizedPolicy",
) -> RightSizedPolicyResponse:
    """Generate candidate right-sized policy proposal."""
    res = access_advisor.generate_right_sized_policy_proposal(
        original_policy_doc=original_policy_doc,
        inactive_services=inactive_services,
        policy_name=policy_name,
    )
    return RightSizedPolicyResponse(**res)


def build_remediation_script(
    finding: dict,
    account_id: str = "123456789012",
) -> RemediationScript:
    """Generate safe remediation shell script artifact for a single finding."""
    res = remediation.generate_remediation_script_for_finding(finding=finding, account_id=account_id)
    return RemediationScript(**res)


def validate_and_simulate_policy(
    policy_doc: dict,
    action_names: list[str],
) -> dict:
    """Validate JSON syntax and test action evaluation with simulator wrapper."""
    syntax_res = policy_validator.validate_policy_syntax(policy_doc)
    if not syntax_res["valid"]:
        return {
            "valid": False,
            "syntax_errors": syntax_res["errors"],
            "simulation": None,
        }

    sim_res = policy_validator.simulate_custom_policy(policy_doc=policy_doc, action_names=action_names)
    return {
        "valid": True,
        "syntax_errors": [],
        "warnings": syntax_res["warnings"],
        "simulation": sim_res,
    }
