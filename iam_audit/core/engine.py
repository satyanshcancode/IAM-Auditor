"""Core business logic for the IAM audit application."""

from datetime import datetime, timezone

from aws import policies as iam_policies
from aws.compare import compute_user_comparison
from aws.permissions import analyze_user_permissions
from aws.report import collect_account_audit
from aws.search import find_users_with_permission

from iam_audit.core.models import (
    AuditReport,
    PermissionAnalysis,
    PolicySource,
    SecurityFinding,
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
        policies=[
            PolicySource(**source)
            for source in analysis.get("policies", [])
        ],
        effective_actions=set(
            analysis.get("effective_actions", set())
        ),
        denied_actions=set(
            analysis.get("denied_actions", set())
        ),
        not_actions=analysis.get("not_actions", []),
        constrained_statements=analysis.get(
            "constrained_statements",
            0,
        ),
    )


def check_permission(username: str, action: str) -> dict:
    """Check an IAM action using AWS policy simulation."""

    try:
        user = iam_policies.iam.get_user(
            UserName=username
        )["User"]

    except Exception as exc:
        code = getattr(
            exc,
            "response",
            {},
        ).get(
            "Error",
            {},
        ).get(
            "Code"
        )

        if code == "NoSuchEntity":
            return {
                "username": username,
                "action": action,
                "allowed": False,
                "decision": "denied",
                "error": (
                    f"User '{username}' does not exist."
                ),
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

    findings = [
        SecurityFinding(**finding)
        for finding in snapshot.get("findings", [])
    ]

    critical_findings = sum(
        finding.severity == "CRITICAL"
        for finding in findings
    )

    warnings = sum(
        finding.severity == "WARNING"
        for finding in findings
    )

    overall_status = (
        "NEEDS ATTENTION"
        if critical_findings or warnings
        else "HEALTHY"
    )

    recommendations = [
        "Review administrator accounts regularly.",
        "Remove unused IAM groups.",
        "Apply the Principle of Least Privilege.",
        "Perform periodic IAM security audits.",
    ]

    return AuditReport(
        generated_at=datetime.now(
            timezone.utc
        ).isoformat(),
        total_users=len(
            snapshot.get("users", [])
        ),
        total_groups=len(
            snapshot.get("groups", [])
        ),
        total_roles=len(
            snapshot.get("roles", [])
        ),
        critical_findings=critical_findings,
        warnings=warnings,
        overall_status=overall_status,
        findings=findings,
        users_without_groups=snapshot.get(
            "users_without_groups",
            [],
        ),
        users_without_policies=snapshot.get(
            "users_without_policies",
            [],
        ),
        roles_without_policies=snapshot.get(
            "roles_without_policies",
            [],
        ),
        empty_groups=snapshot.get(
            "empty_groups",
            [],
        ),
        admin_accounts=snapshot.get(
            "admin_accounts",
            [],
        ),
        recommendations=recommendations,
    )