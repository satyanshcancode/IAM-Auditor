from typing import Any

from botocore.exceptions import ClientError

from aws import policies


def analyze_user_permissions(username: str) -> dict[str, Any] | None:
    try:
        groups, policy_sources = policies.collect_user_policy_sources(username)
        summary = policies.summarize_policy_sources(policy_sources)
        summary["groups"] = groups
        summary["policies"] = policy_sources
        return summary
    except ClientError:
        return None


def extract_user_permissions(username: str) -> set[str] | None:
    analysis = analyze_user_permissions(username)

    if analysis is None:
        return None

    return analysis["effective_actions"]


def format_action(action: str, denied_actions: set[str] | None = None) -> str:
    denied_actions = denied_actions or set()

    if action == "*":
        if denied_actions:
            return "[BROAD] All AWS actions (*) with explicit denies present"
        return "[FULL] Full AWS Administrator Access (*)"

    if action.endswith(":*"):
        service = action.split(":")[0].upper()
        return f"[FULL] Full access to {service} ({action})"

    if action.endswith("Get*"):
        service = action.split(":")[0].upper()
        return f"[ALLOW] All GET operations in {service} ({action})"

    if action.endswith("List*"):
        service = action.split(":")[0].upper()
        return f"[ALLOW] All LIST operations in {service} ({action})"

    if action.endswith("Describe*"):
        service = action.split(":")[0].upper()
        return f"[ALLOW] All DESCRIBE operations in {service} ({action})"

    return f"[ALLOW] {action}"


def print_policy_sources(policy_sources: list[dict[str, Any]]) -> None:
    if not policy_sources:
        print("No Policies")
        return

    for source in policy_sources:
        print(f"{source['name']} ({source['scope']} {source['type']}, {source['owner']})")


def print_analysis_notes(analysis: dict[str, Any]) -> None:
    if analysis["denied_actions"]:
        print("\nExplicit Denies")
        print("-" * 30)
        for action in sorted(analysis["denied_actions"]):
            print(f"[DENY] {action}")

    if analysis["not_actions"]:
        print("\nReview Notes")
        print("-" * 30)
        print("Some policies use NotAction, which is listed for review but")
        print("cannot be represented as a simple allowed-action list.")

    if analysis["constrained_statements"]:
        print("\nScope Notes")
        print("-" * 30)
        print("Some statements include Resource or Condition constraints.")
        print("Use permission simulation for action-specific AWS evaluation.")


def get_user_permissions(username: str) -> bool:
    analysis = analyze_user_permissions(username)

    if analysis is None:
        return False

    groups = analysis["groups"]
    permissions = analysis["effective_actions"]

    print("\n" + "=" * 60)
    print("USER PERMISSIONS")
    print("=" * 60)

    print(f"\nUsername : {username}")

    print("\nGroups")
    print("-" * 30)

    if groups:
        for group in groups:
            print(group["GroupName"])
    else:
        print("No Groups")

    print("\nPolicies")
    print("-" * 30)
    print_policy_sources(analysis["policies"])

    print("\nAllowed Actions")
    print("-" * 30)

    if permissions:
        for action in sorted(permissions):
            print(format_action(action, analysis["denied_actions"]))
    else:
        print("No allowed actions found")

    print_analysis_notes(analysis)

    return True
