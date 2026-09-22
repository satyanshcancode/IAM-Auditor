from typing import Any

from botocore.exceptions import ClientError

from aws import policies
from aws.permissions import (
    analyze_user_permissions,
    format_action,
    print_analysis_notes,
    print_policy_sources,
)


def get_users() -> list[Any]:
    return policies.list_users()


def get_groups() -> list[Any]:
    return policies.list_groups()


def get_roles() -> list[Any]:
    return policies.list_roles()


def account_summary() -> None:
    users = get_users()
    groups = get_groups()
    roles = get_roles()

    print("\n" + "=" * 65)
    print("                     ACCOUNT SUMMARY")
    print("=" * 65)

    print(f"\nTotal Users  : {len(users)}")
    print(f"Total Groups : {len(groups)}")
    print(f"Total Roles  : {len(roles)}")

    print("\n" + "-" * 65)
    print("USERS")
    print("-" * 65)

    for user in users:
        print(f"- {user['UserName']}")

    print("\n" + "-" * 65)
    print("GROUPS")
    print("-" * 65)

    for group in groups:
        print(f"- {group['GroupName']}")

    print("\n" + "-" * 65)
    print("ROLES")
    print("-" * 65)

    for role in roles:
        print(f"- {role['RoleName']}")

    print("=" * 65)


def user_summary() -> None:
    users = get_users()

    print("\n" + "=" * 65)
    print("                      USER SUMMARY")
    print("=" * 65)

    for user in users:
        username = user["UserName"]

        print("\n" + "-" * 65)
        print(f"User   : {username}")

        analysis = analyze_user_permissions(username)

        if analysis is None:
            print("[ERROR] Unable to inspect this user.")
            continue

        groups = analysis["groups"]

        if groups:
            if len(groups) == 1:
                print(f"Group  : {groups[0]['GroupName']}")
            else:
                print("Groups :")
                for group in groups:
                    print(f"         - {group['GroupName']}")
        else:
            print("Group  : None")

        policy_sources = analysis["policies"]

        if policy_sources:
            if len(policy_sources) == 1:
                source = policy_sources[0]
                print(f"Policy : {source['name']} ({source['scope']} {source['type']})")
            else:
                print("Policies:")
                for source in policy_sources:
                    print(f"         - {source['name']} ({source['scope']} {source['type']})")
        else:
            print("Policy : None")

        permissions = analysis["effective_actions"]

        if permissions and "*" in permissions and not analysis["denied_actions"]:
            print("\n[WARNING] Full AWS Administrator Access (*)")

    print("\n" + "=" * 65)


def user_details(username: str) -> bool:
    try:
        user = policies.iam.get_user(UserName=username)["User"]
    except ClientError:
        return False

    analysis = analyze_user_permissions(username)

    if analysis is None:
        return False

    print("\n" + "=" * 65)
    print("                     USER DETAILS")
    print("=" * 65)

    print(f"\nUsername : {username}")
    print(f"ARN      : {user['Arn']}")

    groups = analysis["groups"]

    print("\nGroups")
    print("-" * 65)

    if groups:
        for group in groups:
            print(f"- {group['GroupName']}")
    else:
        print("No Groups")

    print("\nPolicies")
    print("-" * 65)
    print_policy_sources(analysis["policies"])

    permissions = analysis["effective_actions"]

    print("\nEffective Permissions")
    print("-" * 65)

    if permissions:
        for permission in sorted(permissions):
            print(format_action(permission, analysis["denied_actions"]))
    else:
        print("No Permissions")

    print_analysis_notes(analysis)

    if permissions and "*" in permissions and not analysis["denied_actions"]:
        print("\n" + "-" * 65)
        print("[WARNING] SECURITY WARNING")
        print("-" * 65)
        print("This user has Full AWS Administrator Access.")
        print("Review whether this level of access is necessary.")

    print("=" * 65)
    return True


def role_summary() -> None:
    roles = get_roles()

    print("\n" + "=" * 65)
    print("                     IAM ROLES")
    print("=" * 65)

    for role in roles:
        print("\n" + "-" * 65)
        print(f"Role : {role['RoleName']}")

        role_name = role["RoleName"]
        attached_policies = policies.list_attached_role_policies(role_name)
        inline_policies = policies.list_role_policy_names(role_name)

        if attached_policies or inline_policies:
            print("Policies")
            for policy in attached_policies:
                print(f"- {policy['PolicyName']} (managed)")
            for policy_name in inline_policies:
                print(f"- {policy_name} (inline)")
        else:
            print("Policies : None")

    print("\n" + "=" * 65)


def inventory_dashboard() -> None:
    while True:
        print("\n" + "=" * 65)
        print("                     IAM INVENTORY")
        print("=" * 65)
        print("1. Account Summary")
        print("2. User Summary")
        print("3. User Details")
        print("4. IAM Roles")
        print("5. Back")
        print("=" * 65)

        choice = input("\nChoose an option (1-5): ").strip()

        if choice == "1":
            account_summary()
        elif choice == "2":
            user_summary()
        elif choice == "3":
            while True:
                username = input("\nEnter username: ").strip()
                if not username:
                    print("[ERROR] Username cannot be empty.")
                    continue
                if user_details(username):
                    break
                print(f"[ERROR] User '{username}' does not exist.")
        elif choice == "4":
            role_summary()
        elif choice == "5":
            return
        else:
            print("[ERROR] Invalid option.")
