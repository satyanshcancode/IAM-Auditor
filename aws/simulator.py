from typing import Any

from botocore.exceptions import ClientError

from aws import policies


def get_user_arn(username: str) -> str | None:
    try:
        response = policies.iam.get_user(UserName=username)
        arn: str = response["User"]["Arn"]
        return arn
    except ClientError:
        return None


def evaluate_permission(username: str, action: str) -> dict[str, Any]:
    """Evaluate a permission via IAM simulation and return structured data."""
    arn = get_user_arn(username)

    if arn is None:
        return {
            "username": username,
            "action": action,
            "allowed": False,
            "error": f"User '{username}' does not exist",
        }

    try:
        simulation = policies.iam.simulate_principal_policy(
            PolicySourceArn=arn,
            ActionNames=[action],
        )
        result = simulation["EvaluationResults"][0]["EvalDecision"]
        allowed = result.lower() == "allowed"
        return {
            "username": username,
            "action": action,
            "allowed": allowed,
            "decision": result,
        }
    except ClientError as e:
        error = e.response["Error"]["Code"]
        if error == "ValidationError":
            message = f"'{action}' is not a valid IAM action."
        else:
            message = e.response["Error"]["Message"]
        return {
            "username": username,
            "action": action,
            "allowed": False,
            "error": message,
        }
    except Exception as e:
        return {
            "username": username,
            "action": action,
            "allowed": False,
            "error": str(e),
        }


def simulate_permission(username: str, action: str) -> bool:
    evaluation = evaluate_permission(username, action)

    if evaluation.get("error") and "does not exist" in evaluation["error"]:
        print(f"\n[ERROR] User '{username}' does not exist.")
        return False

    if evaluation.get("error"):
        print(f"\n[ERROR] {evaluation['error']}")
        return False

    print("\n" + "=" * 60)
    print("PERMISSION CHECK")
    print("=" * 60)
    print(f"Username   : {username}")
    print(f"Permission : {action}")

    if evaluation["allowed"]:
        print("Status     : ALLOWED")
    else:
        print("Status     : DENIED")

    print("=" * 60)
    return True