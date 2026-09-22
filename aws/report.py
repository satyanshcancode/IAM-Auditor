import os
from datetime import datetime
from typing import Any

from aws import policies as iam_policies
from aws.permissions import analyze_user_permissions, extract_user_permissions


def total_users() -> int:
    return len(iam_policies.list_users())


def total_groups() -> int:
    return len(iam_policies.list_groups())


def total_roles() -> int:
    return len(iam_policies.list_roles())


def find_admin_accounts(
    analyses: dict[str, dict[str, Any] | None] | None = None,
) -> list[str]:
    if analyses is not None:
        return [
            username
            for username, analysis in analyses.items()
            if analysis
            and "*" in analysis["effective_actions"]
            and not analysis["denied_actions"]
        ]

    admins: list[str] = []
    for user in iam_policies.list_users():
        username = user["UserName"]
        analysis = analyze_user_permissions(username)
        if (
            analysis
            and "*" in analysis["effective_actions"]
            and not analysis["denied_actions"]
        ):
            admins.append(username)
    return admins


def find_empty_groups() -> list[str]:
    empty_groups: list[str] = []
    for group in iam_policies.list_groups():
        users = iam_policies.list_users_in_group(group["GroupName"])
        if len(users) == 0:
            empty_groups.append(group["GroupName"])
    return empty_groups


def users_without_groups(
    analyses: dict[str, dict[str, Any] | None] | None = None,
) -> list[str]:
    if analyses is not None:
        return [
            username
            for username, analysis in analyses.items()
            if analysis is None or not analysis.get("groups")
        ]

    users_without_group: list[str] = []
    for user in iam_policies.list_users():
        groups = iam_policies.list_groups_for_user(user["UserName"])
        if len(groups) == 0:
            users_without_group.append(user["UserName"])
    return users_without_group


def users_without_policies(
    analyses: dict[str, dict[str, Any] | None] | None = None,
) -> list[str]:
    if analyses is not None:
        return [
            username
            for username, analysis in analyses.items()
            if analysis is None or len(analysis.get("effective_actions") or []) == 0
        ]

    users_without_policy: list[str] = []
    for user in iam_policies.list_users():
        username = user["UserName"]
        permissions = extract_user_permissions(username)
        if permissions is None or len(permissions) == 0:
            users_without_policy.append(username)
    return users_without_policy


def roles_without_policies() -> list[str]:
    roles_without_policy: list[str] = []
    for role in iam_policies.list_roles():
        attached_policies = iam_policies.list_attached_role_policies(role["RoleName"])
        inline_policies = iam_policies.list_role_policy_names(role["RoleName"])
        if len(attached_policies) == 0 and len(inline_policies) == 0:
            roles_without_policy.append(role["RoleName"])
    return roles_without_policy


def build_findings(
    admin_accounts: list[str] | None = None,
    empty_groups: list[str] | None = None,
) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    finding_number = 1

    admins = find_admin_accounts() if admin_accounts is None else admin_accounts
    empty = find_empty_groups() if empty_groups is None else empty_groups

    for admin in admins:
        findings.append(
            {
                "id": f"IAM-{finding_number:03}",
                "severity": "CRITICAL",
                "resource": f"{admin} (IAM User)",
                "resource_type": "IAM User",
                "issue": "AdministratorAccess grants unrestricted access (*).",
                "impact": "This account has unrestricted access to all AWS resources.",
                "recommendation": "Replace AdministratorAccess with least-privilege permissions.",
            }
        )
        finding_number += 1

    for group in empty:
        findings.append(
            {
                "id": f"IAM-{finding_number:03}",
                "severity": "WARNING",
                "resource": f"{group} (IAM Group)",
                "resource_type": "IAM Group",
                "issue": "No users are assigned to this IAM group.",
                "impact": "Unused IAM groups increase administrative complexity.",
                "recommendation": "Delete the unused group or assign users.",
            }
        )
        finding_number += 1

    return findings


def collect_account_audit() -> dict[str, Any]:
    """Gather inventory, per-user analyses, and findings in a single pass."""
    users = iam_policies.list_users()
    groups = iam_policies.list_groups()
    roles = iam_policies.list_roles()

    analyses: dict[str, dict[str, Any] | None] = {}
    for user in users:
        username = user["UserName"]
        analyses[username] = analyze_user_permissions(username)

    admin_accounts = find_admin_accounts(analyses)
    no_groups = users_without_groups(analyses)
    no_policies = users_without_policies(analyses)
    empty_groups = find_empty_groups()
    empty_roles = roles_without_policies()
    findings = build_findings(admin_accounts, empty_groups)

    return {
        "users": users,
        "groups": groups,
        "roles": roles,
        "analyses": analyses,
        "admin_accounts": admin_accounts,
        "users_without_groups": no_groups,
        "users_without_policies": no_policies,
        "empty_groups": empty_groups,
        "roles_without_policies": empty_roles,
        "findings": findings,
    }


def generate_report() -> None:
    os.makedirs("reports", exist_ok=True)
    report_path = "reports/audit_report.txt"

    snapshot = collect_account_audit()
    findings = snapshot["findings"]
    admin_accounts = snapshot["admin_accounts"]
    empty_groups = snapshot["empty_groups"]
    no_groups = snapshot["users_without_groups"]
    no_policies = snapshot["users_without_policies"]
    empty_roles = snapshot["roles_without_policies"]
    user_count = len(snapshot["users"])
    group_count = len(snapshot["groups"])
    role_count = len(snapshot["roles"])

    critical = sum(1 for finding in findings if finding["severity"] == "CRITICAL")
    warnings = sum(1 for finding in findings if finding["severity"] == "WARNING")
    status = "NEEDS ATTENTION" if critical > 0 or warnings > 0 else "HEALTHY"

    with open(report_path, "w", encoding="utf-8") as report:
        report.write("=" * 70 + "\n")
        report.write("                 IAM SECURITY AUDIT REPORT\n")
        report.write("=" * 70 + "\n\n")

        report.write(f"Generated On : {datetime.now().strftime('%d-%b-%Y %H:%M:%S')}\n")
        report.write("Generated By : IAM Access Auditor & Permission Analyzer\n\n")

        report.write("=" * 70 + "\n")
        report.write("EXECUTIVE SUMMARY\n")
        report.write("=" * 70 + "\n\n")

        report.write(f"Users Audited           : {user_count}\n")
        report.write(f"Groups Audited          : {group_count}\n")
        report.write(f"Roles Audited           : {role_count}\n\n")

        report.write(f"Critical Findings       : {critical}\n")
        report.write(f"Warnings                : {warnings}\n\n")

        report.write(f"Overall Security Status : {status}\n\n")

        report.write("=" * 70 + "\n")
        report.write("SECURITY FINDINGS\n")
        report.write("=" * 70 + "\n\n")

        if findings:
            for finding in findings:
                report.write(f"Finding ID : {finding['id']}\n\n")
                report.write(f"Severity   : {finding['severity']}\n\n")
                report.write(f"Resource   : {finding['resource']}\n\n")
                report.write("Issue\n")
                report.write("-----\n")
                report.write(f"{finding['issue']}\n\n")
                report.write("Impact\n")
                report.write("------\n")
                report.write(f"{finding['impact']}\n\n")
                report.write("Recommendation\n")
                report.write("--------------\n")
                report.write(f"{finding['recommendation']}\n\n")
                report.write("-" * 70 + "\n\n")
        else:
            report.write("No security findings were detected.\n\n")

        report.write("=" * 70 + "\n")
        report.write("IAM CONFIGURATION REVIEW\n")
        report.write("=" * 70 + "\n\n")

        report.write(f"Total Users                 : {user_count}\n")
        report.write(f"Total Groups                : {group_count}\n")
        report.write(f"Total Roles                 : {role_count}\n\n")
        report.write(f"Users without Groups        : {len(no_groups)}\n")
        report.write(f"Users without Policies      : {len(no_policies)}\n")
        report.write(f"Roles without Policies      : {len(empty_roles)}\n")
        report.write(f"Empty IAM Groups            : {len(empty_groups)}\n")
        report.write(f"Administrator Accounts      : {len(admin_accounts)}\n\n")

        report.write("=" * 70 + "\n")
        report.write("SECURITY RECOMMENDATIONS\n")
        report.write("=" * 70 + "\n\n")

        recommendations = []
        if admin_accounts:
            recommendations.append("Review administrator accounts regularly.")
        if empty_groups:
            recommendations.append("Remove unused IAM groups.")
        recommendations.append("Apply the Principle of Least Privilege.")
        recommendations.append("Perform periodic IAM security audits.")

        for index, recommendation in enumerate(recommendations, start=1):
            report.write(f"{index}. {recommendation}\n\n")

        report.write("=" * 70 + "\n")
        report.write("AUDIT CONCLUSION\n")
        report.write("=" * 70 + "\n\n")
        report.write("Audit completed successfully.\n\n")
        report.write(f"Critical Findings : {critical}\n")
        report.write(f"Warnings          : {warnings}\n\n")
        report.write("Overall Assessment\n\n")

        if critical == 0 and warnings == 0:
            report.write("HEALTHY\n\n")
            report.write("No critical security findings were detected.\n")
        else:
            report.write("ACTION REQUIRED\n\n")
            report.write("One or more security findings were detected.\n")
            report.write("Immediate review of the identified resources is recommended.\n")

        report.write("\n")
        report.write("=" * 70 + "\n")
        report.write("END OF REPORT\n")
        report.write("=" * 70 + "\n")

    print("\n[OK] Audit report generated successfully.")
    print(f"Location : {report_path}")
