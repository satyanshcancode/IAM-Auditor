"""Tests for inventory dashboard helpers."""

from io import StringIO
from unittest.mock import patch

from aws.inventory import (
    account_summary,
    inventory_dashboard,
    role_summary,
    user_details,
    user_summary,
)


def test_account_summary_prints_entities() -> None:
    with (
        patch("aws.inventory.get_users", return_value=[{"UserName": "alice"}]),
        patch("aws.inventory.get_groups", return_value=[{"GroupName": "devs"}]),
        patch("aws.inventory.get_roles", return_value=[{"RoleName": "lambda-role"}]),
        patch("sys.stdout", new_callable=StringIO) as stdout,
    ):
        account_summary()
    text = stdout.getvalue()
    assert "alice" in text
    assert "devs" in text
    assert "lambda-role" in text


def test_user_summary_and_details() -> None:
    analysis = {
        "groups": [{"GroupName": "devs"}],
        "policies": [
            {"name": "UserManaged", "scope": "User", "type": "managed", "owner": "alice"}
        ],
        "effective_actions": {"s3:GetObject", "*"},
        "denied_actions": set(),
        "not_actions": [],
        "constrained_statements": 0,
    }

    class FakeIAM:
        def get_user(self, UserName):  # noqa: N803
            return {"User": {"Arn": f"arn:aws:iam::1:user/{UserName}"}}

    with (
        patch("aws.inventory.get_users", return_value=[{"UserName": "alice"}]),
        patch("aws.inventory.analyze_user_permissions", return_value=analysis),
        patch("aws.inventory.policies.iam", FakeIAM()),
        patch("sys.stdout", new_callable=StringIO) as stdout,
    ):
        user_summary()
        assert user_details("alice") is True
    text = stdout.getvalue()
    assert "alice" in text
    assert "Administrator" in text


def test_role_summary() -> None:
    with (
        patch("aws.inventory.get_roles", return_value=[{"RoleName": "lambda-role"}]),
        patch(
            "aws.inventory.policies.list_attached_role_policies",
            return_value=[{"PolicyName": "ReadOnly"}],
        ),
        patch("aws.inventory.policies.list_role_policy_names", return_value=["inline-one"]),
        patch("sys.stdout", new_callable=StringIO) as stdout,
    ):
        role_summary()
    text = stdout.getvalue()
    assert "lambda-role" in text
    assert "ReadOnly" in text


def test_inventory_dashboard_exit() -> None:
    with (
        patch("builtins.input", return_value="5"),
        patch("sys.stdout", new_callable=StringIO),
    ):
        inventory_dashboard()
