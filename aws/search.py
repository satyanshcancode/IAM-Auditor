import logging

from botocore.exceptions import ClientError

from aws import policies

logger = logging.getLogger(__name__)


def find_users_with_permission(permission: str) -> list[str]:
    """Return usernames allowed to perform the given action.

    Raises if every user's simulation attempt fails, so callers can tell
    "nobody has this permission" apart from "the check itself failed" -
    an empty list from this function always means a genuine true negative.
    """
    users = policies.list_users()
    matched_users: list[str] = []
    failures = 0

    for user in users:
        try:
            simulation = policies.iam.simulate_principal_policy(
                PolicySourceArn=user["Arn"],
                ActionNames=[permission],
            )
            decision = simulation["EvaluationResults"][0]["EvalDecision"]
            if decision.lower() == "allowed":
                matched_users.append(user["UserName"])
        except Exception as e:
            failures += 1
            logger.warning("Simulation failed for %s: %s", user.get("UserName"), e)

    if users and failures == len(users):
        raise RuntimeError(
            f"Permission simulation failed for all {len(users)} user(s); "
            "unable to determine who has this permission."
        )

    return matched_users


def search_permission(permission: str) -> bool:
    try:
        matched_users = find_users_with_permission(permission)

        print("\n" + "=" * 60)
        print("SEARCH RESULTS")
        print("=" * 60)

        print(f"\nPermission : {permission}\n")

        if matched_users:
            print("Users with this permission:\n")
            for user in matched_users:
                print(f"[MATCH] {user}")
        else:
            print("No users have this permission.")

        return True

    except ClientError as e:
        error = e.response["Error"]["Code"]

        if error == "ValidationError":
            print(f"\n[ERROR] '{permission}' is not a valid IAM action.")
        else:
            print(f"\nAWS Error: {e.response['Error']['Message']}")

        return False