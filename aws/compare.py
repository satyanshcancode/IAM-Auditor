from typing import Any

from botocore.exceptions import ClientError

from aws import policies
from aws.permissions import analyze_user_permissions, format_action


def user_exists(username: str) -> bool:
    try:
        policies.iam.get_user(UserName=username)
        return True
    except ClientError:
        return False


def is_covered(permission: str, permission_set: set[str] | list[str]) -> bool:
    return policies.action_is_covered(permission, permission_set)


def compute_user_comparison(user1: str, user2: str) -> dict[str, Any] | None:
    """Compare two users and return structured data (no printing)."""
    analysis1 = analyze_user_permissions(user1)
    analysis2 = analyze_user_permissions(user2)

    if analysis1 is None or analysis2 is None:
        return None

    permissions1 = analysis1["effective_actions"]
    permissions2 = analysis2["effective_actions"]

    only_user1: list[str] = []
    only_user2: list[str] = []
    common: list[str] = []

    for permission in permissions1:
        if is_covered(permission, permissions2):
            common.append(permission)
        else:
            only_user1.append(permission)

    for permission in permissions2:
        if not is_covered(permission, permissions1):
            only_user2.append(permission)

    return {
        "user1": user1,
        "user2": user2,
        "only_user1": sorted(only_user1),
        "only_user2": sorted(only_user2),
        "common": sorted(common),
        "user1_admin": "*" in permissions1 and not analysis1["denied_actions"],
        "user2_admin": "*" in permissions2 and not analysis2["denied_actions"],
        "analysis1": analysis1,
        "analysis2": analysis2,
    }


def compare_users(user1: str, user2: str) -> bool:
    try:
        result = compute_user_comparison(user1, user2)

        if result is None:
            return False

        analysis1 = result["analysis1"]
        analysis2 = result["analysis2"]
        only_user1 = result["only_user1"]
        only_user2 = result["only_user2"]
        common = result["common"]

        print("\n" + "=" * 65)
        print("                    USER COMPARISON")
        print("=" * 65)

        print(f"\nUser 1 : {user1}")
        print(f"User 2 : {user2}")

        print("\n" + "=" * 65)
        print(f"Permissions only {user1} has")
        print("=" * 65)

        if only_user1:
            for permission in only_user1:
                print(format_action(permission, analysis1["denied_actions"]))
        else:
            print("None")

        print("\n" + "=" * 65)
        print(f"Permissions only {user2} has")
        print("=" * 65)

        if only_user2:
            for permission in only_user2:
                print(format_action(permission, analysis2["denied_actions"]))
        else:
            print("None")

        print("\n" + "=" * 65)
        print("Common Permissions")
        print("=" * 65)

        if common:
            for permission in common:
                print(format_action(permission))
        else:
            print("None")

        print("\n" + "=" * 65)
        print("SUMMARY")
        print("=" * 65)

        print(f"Permissions only {user1:<15}: {len(only_user1)}")
        print(f"Permissions only {user2:<15}: {len(only_user2)}")
        print(f"Common Permissions        : {len(common)}")

        if result["user1_admin"]:
            print(f"\n[FULL] {user1} has broad AWS Administrator Access.")
            print("All listed permissions available to the other user are included.")
        elif result["user2_admin"]:
            print(f"\n[FULL] {user2} has broad AWS Administrator Access.")
            print("All listed permissions available to the other user are included.")

        return True

    except ClientError as e:
        print(f"\nAWS Error: {e}")
        return False

    except Exception as e:
        print(f"\nUnexpected Error: {e}")
        return False
