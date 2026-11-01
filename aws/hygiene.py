"""AWS IAM Compliance Hygiene audit logic (Phase 1).

Implements checks for:
- Console Password and MFA Hygiene (Users & Root Account)
- Access-Key Age and Inactivity
- Inactive IAM Users
- Inline Policy Hygiene (Users, Groups, Roles)
"""

from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any

from aws import policies as iam_policies
from iam_audit.core.models import SecurityFinding


def parse_datetime(dt_val: Any) -> datetime | None:
    """Parse string or datetime object into a UTC-aware datetime."""
    if dt_val is None:
        return None
    if isinstance(dt_val, datetime):
        if dt_val.tzinfo is None:
            return dt_val.replace(tzinfo=timezone.utc)
        return dt_val
    if isinstance(dt_val, str):
        if dt_val in ("N/A", "not_supported", "no_information", "false", "true", ""):
            return None
        try:
            # ISO format parsing
            dt = datetime.fromisoformat(dt_val.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except Exception:
            return None
    return None


def audit_mfa_hygiene(
    users: list[dict[str, Any]],
    account_summary: dict[str, Any] | None = None,
    cred_report: list[dict[str, str]] | None = None,
) -> tuple[list[SecurityFinding], list[dict[str, Any]]]:
    """Audit MFA hygiene for console users and root account."""
    findings: list[SecurityFinding] = []
    errors: list[dict[str, Any]] = []

    # 1. Audit Root MFA
    root_mfa_checked = False
    if account_summary:
        root_mfa_enabled = account_summary.get("AccountMFAEnabled", 0) == 1
        root_mfa_checked = True
    elif cred_report:
        root_row = next((r for r in cred_report if r.get("user") == "<root_account>"), None)
        if root_row:
            root_mfa_enabled = root_row.get("mfa_active", "").lower() == "true"
            root_mfa_checked = True
        else:
            root_mfa_enabled = False
    else:
        root_mfa_enabled = False

    if root_mfa_checked:
        if not root_mfa_enabled:
            findings.append(
                SecurityFinding(
                    id="IAM_ROOT_NO_MFA",
                    rule_id="IAM_ROOT_NO_MFA",
                    severity="CRITICAL",
                    resource="AWS Root Account",
                    resource_type="AWS Account",
                    issue="Root account does not have Multi-Factor Authentication (MFA) enabled.",
                    impact="Compromise of root credentials grants unrestricted administrative access.",
                    recommendation="Enable hardware or virtual MFA on the AWS root account immediately.",
                    compliance_mappings=[
                        "CIS AWS Foundations Benchmark v3.0 Control 1.1",
                        "ISO 27001 A.9.4.2",
                    ],
                    detection_source="IAM Compliance Hygiene Engine",
                    collection_status="CONFIRMED",
                )
            )
    else:
        errors.append(
            {
                "check": "IAM_ROOT_NO_MFA",
                "resource": "AWS Root Account",
                "message": "Unable to determine Root account MFA status (AccessDenied or AccountSummary failed).",
            }
        )
        findings.append(
            SecurityFinding(
                id="IAM_ROOT_MFA_UNKNOWN",
                rule_id="IAM_ROOT_NO_MFA",
                severity="WARNING",
                resource="AWS Root Account",
                resource_type="AWS Account",
                issue="Root MFA status could not be verified due to API collection restrictions.",
                impact="Unverified root MFA configuration.",
                recommendation="Ensure iam:GetAccountSummary or credential report permissions are granted.",
                detection_source="IAM Compliance Hygiene Engine",
                collection_status="COLLECTION_FAILED",
            )
        )

    # Build cred report lookup map by username if available
    cred_map = {row.get("user"): row for row in (cred_report or []) if row.get("user")}

    # 2. Audit Console Users MFA
    for user in users:
        username = user["UserName"]
        cred_row = cred_map.get(username)

        has_console = False
        mfa_active = False

        if cred_row:
            has_console = cred_row.get("password_enabled", "").lower() == "true"
            mfa_active = cred_row.get("mfa_active", "").lower() == "true"
        else:
            profile = iam_policies.get_login_profile(username)
            has_console = profile is not None
            if has_console:
                mfa_devices = iam_policies.list_mfa_devices(username)
                mfa_active = len(mfa_devices) > 0

        # Only evaluate MFA for console-enabled users
        if has_console and not mfa_active:
            findings.append(
                SecurityFinding(
                    id="IAM_CONSOLE_USER_NO_MFA",
                    rule_id="IAM_CONSOLE_USER_NO_MFA",
                    severity="HIGH",
                    resource=f"{username} (IAM User)",
                    resource_type="IAM User",
                    issue="Console access is enabled but Multi-Factor Authentication (MFA) is not configured.",
                    impact="Console accounts without MFA are vulnerable to credential theft and brute-force attacks.",
                    recommendation="Enforce Multi-Factor Authentication (MFA) for all console users.",
                    compliance_mappings=[
                        "CIS AWS Foundations Benchmark v3.0 Control 1.5",
                        "SOC 2 Type II CC6.1",
                    ],
                    evidence={"username": username, "console_access": True, "mfa_active": False},
                    detection_source="IAM Compliance Hygiene Engine",
                    collection_status="CONFIRMED",
                )
            )

    return findings, errors


def audit_access_key_hygiene(
    users: list[dict[str, Any]],
    access_key_age_threshold_days: int = 90,
    access_key_unused_threshold_days: int = 90,
    now_func: Callable[[], datetime] | None = None,
) -> tuple[list[SecurityFinding], list[dict[str, Any]]]:
    """Audit access key age and activity."""
    findings: list[SecurityFinding] = []
    errors: list[dict[str, Any]] = []
    now = now_func() if now_func else datetime.now(timezone.utc)

    for user in users:
        username = user["UserName"]
        try:
            keys = iam_policies.list_access_keys(username)
        except Exception as exc:
            errors.append(
                {
                    "check": "access_keys",
                    "resource": username,
                    "message": f"Failed to list access keys for user {username}: {exc}",
                }
            )
            continue

        for key in keys:
            if key.get("Status") != "Active":
                continue

            key_id = key["AccessKeyId"]
            create_dt = parse_datetime(key.get("CreateDate"))

            if not create_dt:
                continue

            age_days = (now - create_dt).days

            # 1. Key Age Check
            if age_days > access_key_age_threshold_days:
                findings.append(
                    SecurityFinding(
                        id="IAM_ACCESS_KEY_OLD",
                        rule_id="IAM_ACCESS_KEY_OLD",
                        severity="MEDIUM",
                        resource=f"{username} / {key_id} (IAM Access Key)",
                        resource_type="IAM Access Key",
                        entity_name=username,
                        access_key_id=key_id,
                        issue=f"Active access key is {age_days} days old (Threshold: {access_key_age_threshold_days} days).",
                        impact="Long-lived access keys increase exposure risks if credentials are leaked.",
                        recommendation="Rotate access keys regularly (every 90 days or fewer).",
                        compliance_mappings=["CIS AWS Foundations Benchmark v3.0 Control 1.14"],
                        evidence={"username": username, "key_id": key_id, "age_days": age_days},
                        detection_source="IAM Compliance Hygiene Engine",
                        collection_status="CONFIRMED",
                    )
                )

            # 2. Key Last Used Check
            last_used_info = iam_policies.get_access_key_last_used(key_id)
            last_used_dt = parse_datetime(last_used_info.get("LastUsedDate"))

            if last_used_dt:
                unused_days = (now - last_used_dt).days
                if unused_days > access_key_unused_threshold_days:
                    findings.append(
                        SecurityFinding(
                            id="IAM_ACCESS_KEY_UNUSED",
                            rule_id="IAM_ACCESS_KEY_UNUSED",
                            severity="MEDIUM",
                            resource=f"{username} / {key_id} (IAM Access Key)",
                            resource_type="IAM Access Key",
                            entity_name=username,
                            access_key_id=key_id,
                            issue=f"Active access key has not been used for {unused_days} days (Threshold: {access_key_unused_threshold_days} days).",
                            impact="Unused credentials expand the attack surface.",
                            recommendation="Deactivate or delete unused access keys.",
                            compliance_mappings=[
                                "CIS AWS Foundations Benchmark v3.0 Control 1.12"
                            ],
                            evidence={
                                "username": username,
                                "key_id": key_id,
                                "unused_days": unused_days,
                            },
                            detection_source="IAM Compliance Hygiene Engine",
                            collection_status="CONFIRMED",
                        )
                    )
            else:
                # Key has never been used. Only flag if key age > 1 day to avoid flagging brand new keys
                if age_days > 1:
                    findings.append(
                        SecurityFinding(
                            id="IAM_ACCESS_KEY_NEVER_USED",
                            rule_id="IAM_ACCESS_KEY_NEVER_USED",
                            severity="MEDIUM",
                            resource=f"{username} / {key_id} (IAM Access Key)",
                            resource_type="IAM Access Key",
                            entity_name=username,
                            access_key_id=key_id,
                            issue=f"Active access key has never been used (Created {age_days} days ago).",
                            impact="Unused active keys pose an unnecessary security risk.",
                            recommendation="Delete access keys that have never been used.",
                            compliance_mappings=[
                                "CIS AWS Foundations Benchmark v3.0 Control 1.12"
                            ],
                            evidence={
                                "username": username,
                                "key_id": key_id,
                                "age_days": age_days,
                            },
                            detection_source="IAM Compliance Hygiene Engine",
                            collection_status="CONFIRMED",
                        )
                    )

    return findings, errors


def audit_user_inactivity_hygiene(
    users: list[dict[str, Any]],
    inactivity_threshold_days: int = 90,
    cred_report: list[dict[str, str]] | None = None,
    now_func: Callable[[], datetime] | None = None,
    ignored_users: list[str] | None = None,
) -> tuple[list[SecurityFinding], list[dict[str, Any]]]:
    """Audit user inactivity across console password and access keys."""
    findings: list[SecurityFinding] = []
    errors: list[dict[str, Any]] = []
    now = now_func() if now_func else datetime.now(timezone.utc)
    ignored_set = set(ignored_users or [])

    cred_map = {row.get("user"): row for row in (cred_report or []) if row.get("user")}

    for user in users:
        username = user["UserName"]
        if username in ignored_set:
            continue

        cred_row = cred_map.get(username)

        # Parse password activity
        user_create_dt = parse_datetime(user.get("CreateDate"))
        user_age_days = (now - user_create_dt).days if user_create_dt else 0

        has_console = False
        password_inactive = False

        if cred_row:
            has_console = cred_row.get("password_enabled", "").lower() == "true"
            pass_last_used_dt = parse_datetime(cred_row.get("password_last_used"))
            if has_console:
                if pass_last_used_dt:
                    password_inactive = (now - pass_last_used_dt).days > inactivity_threshold_days
                else:
                    # Password never used; check account age
                    password_inactive = user_age_days > inactivity_threshold_days
        else:
            profile = iam_policies.get_login_profile(username)
            has_console = profile is not None
            pass_last_used_dt = parse_datetime(user.get("PasswordLastUsed"))
            if has_console:
                if pass_last_used_dt:
                    password_inactive = (now - pass_last_used_dt).days > inactivity_threshold_days
                else:
                    password_inactive = user_age_days > inactivity_threshold_days

        # Parse access key activity
        keys = iam_policies.list_access_keys(username)
        active_keys = [k for k in keys if k.get("Status") == "Active"]

        keys_inactive = True
        for key in active_keys:
            key_id = key["AccessKeyId"]
            last_used_info = iam_policies.get_access_key_last_used(key_id)
            last_used_dt = parse_datetime(last_used_info.get("LastUsedDate"))
            key_create_dt = parse_datetime(key.get("CreateDate"))
            key_age_days = (now - key_create_dt).days if key_create_dt else 0

            if last_used_dt:
                if (now - last_used_dt).days <= inactivity_threshold_days:
                    keys_inactive = False
                    break
            else:
                # Key never used; if created recently (<= threshold), consider active usage pending
                if key_age_days <= inactivity_threshold_days:
                    keys_inactive = False
                    break

        # Determine overall user inactivity
        is_inactive = bool(
            (has_console and password_inactive and keys_inactive)
            or (not has_console and active_keys and keys_inactive)
            or (not has_console and not active_keys and user_age_days > inactivity_threshold_days)
        )

        if is_inactive:
            findings.append(
                SecurityFinding(
                    id="IAM_USER_INACTIVE",
                    rule_id="IAM_USER_INACTIVE",
                    severity="MEDIUM",
                    resource=f"{username} (IAM User)",
                    resource_type="IAM User",
                    issue=f"IAM user account has been inactive for more than {inactivity_threshold_days} days.",
                    impact="Inactive user accounts pose a risk of unauthorized access if compromised.",
                    recommendation="Disable or delete inactive IAM user accounts.",
                    compliance_mappings=[
                        "CIS AWS Foundations Benchmark v3.0 Control 1.12",
                        "SOC 2 Type II CC6.2",
                    ],
                    evidence={
                        "username": username,
                        "console_enabled": has_console,
                        "account_age_days": user_age_days,
                    },
                    detection_source="IAM Compliance Hygiene Engine",
                    collection_status="CONFIRMED",
                )
            )

    return findings, errors


def audit_inline_policies(
    users: list[dict[str, Any]],
    groups: list[dict[str, Any]],
    roles: list[dict[str, Any]],
) -> tuple[list[SecurityFinding], list[dict[str, Any]]]:
    """Audit inline policies attached to users, groups, and roles."""
    findings: list[SecurityFinding] = []
    errors: list[dict[str, Any]] = []

    # 1. Users Inline Policies
    for user in users:
        username = user["UserName"]
        try:
            policy_names = iam_policies.list_user_policy_names(username)
            for policy_name in policy_names:
                findings.append(
                    SecurityFinding(
                        id="IAM_INLINE_POLICY_PRESENT",
                        rule_id="IAM_INLINE_POLICY_PRESENT",
                        severity="LOW",
                        resource=f"{username} / {policy_name} (User Inline Policy)",
                        resource_type="IAM User",
                        entity_name=username,
                        policy_name=policy_name,
                        issue=f"User '{username}' has inline policy '{policy_name}' attached.",
                        impact="Inline policies increase management complexity and bypass central policy governance.",
                        recommendation="Replace inline policies with managed IAM policies.",
                        compliance_mappings=["CIS AWS Foundations Benchmark v3.0 Control 1.16"],
                        evidence={
                            "principal_type": "IAM User",
                            "principal_name": username,
                            "policy_name": policy_name,
                        },
                        detection_source="IAM Compliance Hygiene Engine",
                        collection_status="CONFIRMED",
                    )
                )
        except Exception as exc:
            errors.append(
                {
                    "check": "inline_policies_user",
                    "resource": username,
                    "message": f"Failed to list user policies for {username}: {exc}",
                }
            )

    # 2. Groups Inline Policies
    for group in groups:
        group_name = group["GroupName"]
        try:
            policy_names = iam_policies.list_group_policy_names(group_name)
            for policy_name in policy_names:
                findings.append(
                    SecurityFinding(
                        id="IAM_INLINE_POLICY_PRESENT",
                        rule_id="IAM_INLINE_POLICY_PRESENT",
                        severity="LOW",
                        resource=f"{group_name} / {policy_name} (Group Inline Policy)",
                        resource_type="IAM Group",
                        entity_name=group_name,
                        policy_name=policy_name,
                        issue=f"Group '{group_name}' has inline policy '{policy_name}' attached.",
                        impact="Inline policies bypass centralized customer-managed policy governance.",
                        recommendation="Replace inline policies with managed IAM policies.",
                        compliance_mappings=["CIS AWS Foundations Benchmark v3.0 Control 1.16"],
                        evidence={
                            "principal_type": "IAM Group",
                            "principal_name": group_name,
                            "policy_name": policy_name,
                        },
                        detection_source="IAM Compliance Hygiene Engine",
                        collection_status="CONFIRMED",
                    )
                )
        except Exception as exc:
            errors.append(
                {
                    "check": "inline_policies_group",
                    "resource": group_name,
                    "message": f"Failed to list group policies for {group_name}: {exc}",
                }
            )

    # 3. Roles Inline Policies
    for role in roles:
        role_name = role["RoleName"]
        try:
            policy_names = iam_policies.list_role_policy_names(role_name)
            for policy_name in policy_names:
                findings.append(
                    SecurityFinding(
                        id="IAM_INLINE_POLICY_PRESENT",
                        rule_id="IAM_INLINE_POLICY_PRESENT",
                        severity="LOW",
                        resource=f"{role_name} / {policy_name} (Role Inline Policy)",
                        resource_type="IAM Role",
                        entity_name=role_name,
                        policy_name=policy_name,
                        issue=f"Role '{role_name}' has inline policy '{policy_name}' attached.",
                        impact="Inline policies on roles hinder policy reuse and central governance.",
                        recommendation="Replace inline policies with managed IAM policies.",
                        compliance_mappings=["CIS AWS Foundations Benchmark v3.0 Control 1.16"],
                        evidence={
                            "principal_type": "IAM Role",
                            "principal_name": role_name,
                            "policy_name": policy_name,
                        },
                        detection_source="IAM Compliance Hygiene Engine",
                        collection_status="CONFIRMED",
                    )
                )
        except Exception as exc:
            errors.append(
                {
                    "check": "inline_policies_role",
                    "resource": role_name,
                    "message": f"Failed to list role policies for {role_name}: {exc}",
                }
            )

    return findings, errors
