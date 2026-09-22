from fnmatch import fnmatchcase
from typing import Any

from aws.client import iam


def paginate(operation_name: str, result_key: str, **kwargs: Any) -> list[Any]:
    """Return every item for an IAM list operation."""
    get_paginator = getattr(iam, "get_paginator", None)

    if get_paginator is not None:
        try:
            paginator = get_paginator(operation_name)
        except Exception:
            paginator = None

        if paginator is not None:
            items: list[Any] = []
            for page in paginator.paginate(**kwargs):
                items.extend(page.get(result_key, []))
            return items

    operation = getattr(iam, operation_name)
    response = operation(**kwargs)
    items = list(response.get(result_key, []))
    marker = response.get("Marker")

    while response.get("IsTruncated") and marker:
        next_kwargs = dict(kwargs)
        next_kwargs["Marker"] = marker
        response = operation(**next_kwargs)
        items.extend(response.get(result_key, []))
        marker = response.get("Marker")

    return items


def list_users() -> list[Any]:
    return paginate("list_users", "Users")


def list_groups() -> list[Any]:
    return paginate("list_groups", "Groups")


def list_roles() -> list[Any]:
    return paginate("list_roles", "Roles")


def list_groups_for_user(username: str) -> list[Any]:
    return paginate("list_groups_for_user", "Groups", UserName=username)


def list_attached_user_policies(username: str) -> list[Any]:
    return paginate(
        "list_attached_user_policies",
        "AttachedPolicies",
        UserName=username,
    )


def list_user_policy_names(username: str) -> list[Any]:
    return paginate("list_user_policies", "PolicyNames", UserName=username)


def list_attached_group_policies(group_name: str) -> list[Any]:
    return paginate(
        "list_attached_group_policies",
        "AttachedPolicies",
        GroupName=group_name,
    )


def list_group_policy_names(group_name: str) -> list[Any]:
    return paginate(
        "list_group_policies",
        "PolicyNames",
        GroupName=group_name,
    )


def list_attached_role_policies(role_name: str) -> list[Any]:
    return paginate(
        "list_attached_role_policies",
        "AttachedPolicies",
        RoleName=role_name,
    )


def list_role_policy_names(role_name: str) -> list[Any]:
    return paginate("list_role_policies", "PolicyNames", RoleName=role_name)


def list_users_in_group(group_name: str) -> list[Any]:
    return paginate("get_group", "Users", GroupName=group_name)


def get_managed_policy_document(policy_arn: str) -> dict[str, Any]:
    policy = iam.get_policy(PolicyArn=policy_arn)["Policy"]
    version_id = policy["DefaultVersionId"]

    response = iam.get_policy_version(
        PolicyArn=policy_arn,
        VersionId=version_id,
    )
    document: dict[str, Any] = response["PolicyVersion"]["Document"]
    return document


def get_user_inline_policy_document(username: str, policy_name: str) -> dict[str, Any]:
    response = iam.get_user_policy(
        UserName=username,
        PolicyName=policy_name,
    )
    document: dict[str, Any] = response["PolicyDocument"]
    return document


def get_group_inline_policy_document(group_name: str, policy_name: str) -> dict[str, Any]:
    response = iam.get_group_policy(
        GroupName=group_name,
        PolicyName=policy_name,
    )
    document: dict[str, Any] = response["PolicyDocument"]
    return document


def collect_user_policy_sources(username: str) -> tuple[list[Any], list[dict[str, Any]]]:
    iam.get_user(UserName=username)

    groups = list_groups_for_user(username)
    sources: list[dict[str, Any]] = []

    for policy in list_attached_user_policies(username):
        sources.append(
            {
                "scope": "User",
                "owner": username,
                "type": "managed",
                "name": policy["PolicyName"],
                "arn": policy["PolicyArn"],
                "document": get_managed_policy_document(policy["PolicyArn"]),
            }
        )

    for policy_name in list_user_policy_names(username):
        sources.append(
            {
                "scope": "User",
                "owner": username,
                "type": "inline",
                "name": policy_name,
                "arn": None,
                "document": get_user_inline_policy_document(
                    username,
                    policy_name,
                ),
            }
        )

    for group in groups:
        group_name = group["GroupName"]

        for policy in list_attached_group_policies(group_name):
            sources.append(
                {
                    "scope": "Group",
                    "owner": group_name,
                    "type": "managed",
                    "name": policy["PolicyName"],
                    "arn": policy["PolicyArn"],
                    "document": get_managed_policy_document(policy["PolicyArn"]),
                }
            )

        for policy_name in list_group_policy_names(group_name):
            sources.append(
                {
                    "scope": "Group",
                    "owner": group_name,
                    "type": "inline",
                    "name": policy_name,
                    "arn": None,
                    "document": get_group_inline_policy_document(
                        group_name,
                        policy_name,
                    ),
                }
            )

    return groups, sources


def normalize_to_list(value: Any) -> list[Any]:
    if value is None:
        return []

    if isinstance(value, list):
        return value

    return [value]


def document_statements(document: dict[str, Any]) -> list[Any]:
    statements = document.get("Statement", [])
    return normalize_to_list(statements)


def summarize_policy_sources(policy_sources: list[dict[str, Any]]) -> dict[str, Any]:
    allowed_actions: set[str] = set()
    denied_actions: set[str] = set()
    not_actions: list[dict[str, Any]] = []
    constrained_statements = 0

    for source in policy_sources:
        document = source["document"]

        for statement in document_statements(document):
            effect = statement.get("Effect", "")
            actions = normalize_to_list(statement.get("Action"))
            unsupported_not_actions = normalize_to_list(statement.get("NotAction"))

            if unsupported_not_actions:
                not_actions.append(
                    {
                        "policy": source["name"],
                        "effect": effect,
                        "actions": unsupported_not_actions,
                    }
                )

            if statement.get("Condition") or statement.get("Resource") not in (None, "*"):
                constrained_statements += 1

            if effect == "Allow":
                allowed_actions.update(actions)
            elif effect == "Deny":
                denied_actions.update(actions)

    return {
        "allowed_actions": allowed_actions,
        "denied_actions": denied_actions,
        "effective_actions": remove_actions_covered_by_denies(
            allowed_actions,
            denied_actions,
        ),
        "not_actions": not_actions,
        "constrained_statements": constrained_statements,
    }


def action_matches(pattern: str, action: str) -> bool:
    return fnmatchcase(action.lower(), pattern.lower())


def action_is_covered(action: str, permission_set: set[str] | list[str]) -> bool:
    return any(action_matches(pattern, action) for pattern in permission_set)


def remove_actions_covered_by_denies(
    allowed_actions: set[str], denied_actions: set[str]
) -> set[str]:
    if not denied_actions:
        return set(allowed_actions)

    return {action for action in allowed_actions if not action_is_covered(action, denied_actions)}