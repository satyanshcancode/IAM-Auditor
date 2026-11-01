"""IAM Access Advisor and Least-Privilege Policy Engine.

Provides service last accessed details retrieval via iam:GenerateServiceLastAccessedDetails,
distinguishes missing data (NO_DATA) from confirmed inactivity, safeguards untracked actions
(e.g., iam:PassRole, sts:AssumeRole), and generates proposed right-sized candidate IAM policies for review.
"""

import logging
import time
from datetime import datetime, timezone
from typing import Any

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)

# List of critical permissions and actions untracked or partially tracked by AWS Access Advisor
# These MUST be explicitly preserved in right-sized policies to prevent breaking application logic.
UNTRACKED_ACTIONS_SAFEGUARD: set[str] = {
    "iam:passrole",
    "sts:assumerole",
    "sts:assumerolewithsaml",
    "sts:assumerolewithwebidentity",
    "sts:getcalleridentity",
    "sts:getsessiontoken",
    "sts:getfederationtoken",
    "kms:decrypt",
    "kms:encrypt",
    "kms:generateendtoendkey",
    "kms:generatedatakey",
    "logs:createloggroup",
    "logs:createlogstream",
    "logs:putlogevents",
}

# Services known to have special untracked operational behaviors
UNTRACKED_SERVICES_SAFEGUARD: set[str] = {
    "sts",
    "kms",
}


def get_service_last_accessed_details(
    arn: str,
    iam_client: Any | None = None,
    poll_interval_seconds: float = 1.0,
    max_poll_attempts: int = 15,
) -> dict[str, Any]:
    """Generate and retrieve Service Last Accessed Details for an IAM entity ARN.

    Polls `iam:GetServiceLastAccessedDetails` until status is 'COMPLETED' or 'FAILED'.

    Returns:
        {
            "arn": arn,
            "job_status": "COMPLETED" | "FAILED" | "TIMED_OUT" | "NO_DATA",
            "services": [
                {
                    "service_name": ...,
                    "service_namespace": ...,
                    "last_authenticated": ... (ISO timestamp string or None),
                    "total_authenticated_entities": ...,
                    "tracked_status": "ACTIVE" | "CONFIRMED_INACTIVE" | "NO_DATA"
                },
                ...
            ],
            "error": None | str
        }
    """
    if iam_client is None:
        iam_client = boto3.client("iam")

    try:
        gen_res = iam_client.generate_service_last_accessed_details(Arn=arn)
        job_id = gen_res["JobId"]
    except ClientError as err:
        logger.error(f"Failed to generate service last accessed details for {arn}: {err}")
        return {
            "arn": arn,
            "job_status": "NO_DATA",
            "services": [],
            "error": str(err),
        }

    attempts = 0
    while attempts < max_poll_attempts:
        attempts += 1
        try:
            get_res = iam_client.get_service_last_accessed_details(JobId=job_id)
            job_status = get_res.get("JobStatus")

            if job_status == "COMPLETED":
                raw_services = get_res.get("ServicesLastAccessed", [])
                parsed_services = []
                for s in raw_services:
                    last_auth = s.get("LastAuthenticated")
                    last_auth_str = last_auth.isoformat() if isinstance(last_auth, datetime) else last_auth

                    parsed_services.append({
                        "service_name": s.get("ServiceName"),
                        "service_namespace": s.get("ServiceNamespace"),
                        "last_authenticated": last_auth_str,
                        "total_authenticated_entities": s.get("TotalAuthenticatedEntities", 0),
                        "tracked_status": "CONFIRMED_INACTIVE" if last_auth is None else "ACTIVE",
                    })

                return {
                    "arn": arn,
                    "job_status": "COMPLETED",
                    "services": parsed_services,
                    "error": None,
                }
            elif job_status == "FAILED":
                error_detail = get_res.get("Error", {}).get("Message", "Job failed")
                return {
                    "arn": arn,
                    "job_status": "FAILED",
                    "services": [],
                    "error": error_detail,
                }
        except ClientError as err:
            return {
                "arn": arn,
                "job_status": "FAILED",
                "services": [],
                "error": str(err),
            }

        time.sleep(poll_interval_seconds)

    return {
        "arn": arn,
        "job_status": "TIMED_OUT",
        "services": [],
        "error": f"Job polling timed out after {max_poll_attempts} attempts",
    }


def analyze_unused_services(
    services_last_accessed: list[dict[str, Any]],
    threshold_days: int = 90,
    reference_date: datetime | None = None,
) -> dict[str, Any]:
    """Analyze service access list and classify services into ACTIVE, CONFIRMED_INACTIVE, or NO_DATA.

    Args:
        services_last_accessed: List of service access dicts from get_service_last_accessed_details.
        threshold_days: Inactivity threshold in days (default 90).
        reference_date: Reference datetime for computing days idle (defaults to UTC now).

    Returns:
        {
            "active_services": list[str],
            "inactive_services": list[str],
            "no_data_services": list[str],
            "evidence": list[dict[str, Any]]
        }
    """
    if reference_date is None:
        reference_date = datetime.now(timezone.utc)

    active: list[str] = []
    inactive: list[str] = []
    no_data: list[str] = []
    evidence: list[dict[str, Any]] = []

    for item in services_last_accessed:
        namespace = item.get("service_namespace", "").lower()
        if not namespace:
            continue

        tracked_status = item.get("tracked_status")
        if tracked_status == "NO_DATA":
            no_data.append(namespace)
            evidence.append({
                "service_namespace": namespace,
                "status": "NO_DATA",
                "days_idle": None,
                "reason": f"Service last accessed tracking status is NO_DATA for service '{namespace}'.",
            })
            continue

        last_auth_raw = item.get("last_authenticated")
        if not last_auth_raw:
            inactive.append(namespace)
            evidence.append({
                "service_namespace": namespace,
                "status": "CONFIRMED_INACTIVE",
                "days_idle": None,
                "reason": f"No recorded service-level access history for service '{namespace}' within tracking window.",
            })
        else:
            try:
                if isinstance(last_auth_raw, str):
                    # Parse ISO timestamp string
                    dt = datetime.fromisoformat(last_auth_raw.replace("Z", "+00:00"))
                else:
                    dt = last_auth_raw

                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)

                days_idle = (reference_date - dt).days

                if days_idle > threshold_days:
                    inactive.append(namespace)
                    evidence.append({
                        "service_namespace": namespace,
                        "status": "CONFIRMED_INACTIVE",
                        "days_idle": days_idle,
                        "reason": f"Service '{namespace}' has not been accessed for {days_idle} days (threshold: {threshold_days} days).",
                    })
                else:
                    active.append(namespace)
                    evidence.append({
                        "service_namespace": namespace,
                        "status": "ACTIVE",
                        "days_idle": days_idle,
                        "reason": f"Service '{namespace}' accessed {days_idle} days ago.",
                    })
            except Exception as exc:
                no_data.append(namespace)
                evidence.append({
                    "service_namespace": namespace,
                    "status": "NO_DATA",
                    "days_idle": None,
                    "reason": f"Could not parse last authenticated timestamp '{last_auth_raw}': {exc}",
                })

    return {
        "active_services": active,
        "inactive_services": inactive,
        "no_data_services": no_data,
        "evidence": evidence,
    }


def generate_right_sized_policy_proposal(
    original_policy_doc: dict[str, Any],
    inactive_services: list[str],
    policy_name: str = "ProposedRightSizedPolicy",
) -> dict[str, Any]:
    """Generate a candidate right-sized JSON IAM policy proposal for review.

    Preserves original policy and explicitly safeguards untracked permissions
    (e.g., iam:PassRole, sts:AssumeRole, KMS operations).

    Returns:
        {
            "policy_name": policy_name,
            "original_policy": original_policy_doc,
            "proposed_policy": candidate_policy_doc,
            "pruned_services": list[str],
            "safeguarded_permissions": list[str],
            "evidence": list[str]
        }
    """
    inactive_set = {s.lower() for s in inactive_services}
    pruned_services: set[str] = set()
    safeguarded_permissions: list[str] = []
    evidence_messages: list[str] = []

    statements = original_policy_doc.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]

    new_statements: list[dict[str, Any]] = []

    for stmt in statements:
        if not isinstance(stmt, dict):
            continue

        # Explicit Deny statements are ALWAYS preserved intact
        if stmt.get("Effect") == "Deny":
            new_statements.append(stmt)
            continue

        actions = stmt.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]

        retained_actions: list[str] = []

        for action in actions:
            action_lower = action.lower()
            prefix = action_lower.split(":")[0] if ":" in action_lower else ""

            # Check if action is in untracked safeguards
            if action_lower in UNTRACKED_ACTIONS_SAFEGUARD or prefix in UNTRACKED_SERVICES_SAFEGUARD:
                retained_actions.append(action)
                safeguarded_permissions.append(action)
                continue

            # Check if action prefix matches an inactive service
            if prefix in inactive_set:
                pruned_services.add(prefix)
                evidence_messages.append(
                    f"Action '{action}' pruned because service '{prefix}' is confirmed inactive."
                )
            else:
                retained_actions.append(action)

        if retained_actions:
            new_stmt = dict(stmt)
            new_stmt["Action"] = retained_actions if len(retained_actions) > 1 else retained_actions[0]
            new_statements.append(new_stmt)

    proposed_doc = {
        "Version": original_policy_doc.get("Version", "2012-10-17"),
        "Statement": new_statements,
    }

    return {
        "policy_name": policy_name,
        "original_policy": original_policy_doc,
        "proposed_policy": proposed_doc,
        "pruned_services": sorted(pruned_services),
        "safeguarded_permissions": sorted(set(safeguarded_permissions)),
        "evidence": evidence_messages,
    }
