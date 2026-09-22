import unittest
from unittest.mock import patch

from aws.permissions import analyze_user_permissions


class StaticPaginator:
    def __init__(self, pages):
        self.pages = pages

    def paginate(self, **kwargs):
        return self.pages


class FakeIAM:
    def __init__(self):
        self.managed_documents = {
            "arn:user-managed": {
                "Statement": {
                    "Effect": "Allow",
                    "Action": ["s3:GetObject", "ec2:Describe*"],
                    "Resource": "*",
                }
            },
            "arn:group-managed": {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "logs:*",
                        "Resource": "*",
                    },
                    {
                        "Effect": "Deny",
                        "Action": "s3:DeleteObject",
                        "Resource": "*",
                    },
                ]
            },
        }

    def get_user(self, UserName):
        return {
            "User": {
                "UserName": UserName,
                "Arn": f"arn:aws:iam::123456789012:user/{UserName}",
            }
        }

    def get_paginator(self, operation_name):
        pages = {
            "list_groups_for_user": [
                {"Groups": [{"GroupName": "Developers"}]},
            ],
            "list_attached_user_policies": [
                {
                    "AttachedPolicies": [
                        {
                            "PolicyName": "UserManaged",
                            "PolicyArn": "arn:user-managed",
                        }
                    ]
                },
            ],
            "list_user_policies": [
                {"PolicyNames": ["UserInline"]},
            ],
            "list_attached_group_policies": [
                {
                    "AttachedPolicies": [
                        {
                            "PolicyName": "GroupManaged",
                            "PolicyArn": "arn:group-managed",
                        }
                    ]
                },
            ],
            "list_group_policies": [
                {"PolicyNames": ["GroupInline"]},
            ],
        }
        return StaticPaginator(pages[operation_name])

    def get_policy(self, PolicyArn):
        return {"Policy": {"DefaultVersionId": "v1"}}

    def get_policy_version(self, PolicyArn, VersionId):
        return {
            "PolicyVersion": {
                "Document": self.managed_documents[PolicyArn],
            }
        }

    def get_user_policy(self, UserName, PolicyName):
        return {
            "PolicyDocument": {
                "Statement": {
                    "Effect": "Allow",
                    "Action": "iam:CreateUser",
                    "Resource": "*",
                }
            }
        }

    def get_group_policy(self, GroupName, PolicyName):
        return {
            "PolicyDocument": {
                "Statement": {
                    "Effect": "Allow",
                    "Action": "sqs:SendMessage",
                    "Resource": "*",
                }
            }
        }


class PermissionAnalysisTests(unittest.TestCase):
    def test_analyze_user_permissions_collects_all_user_and_group_sources(self):
        with patch("aws.policies.iam", FakeIAM()):
            analysis = analyze_user_permissions("alice")

        self.assertEqual(
            analysis["effective_actions"],
            {
                "ec2:Describe*",
                "iam:CreateUser",
                "logs:*",
                "s3:GetObject",
                "sqs:SendMessage",
            },
        )
        self.assertEqual(analysis["denied_actions"], {"s3:DeleteObject"})
        self.assertEqual(
            [source["name"] for source in analysis["policies"]],
            ["UserManaged", "UserInline", "GroupManaged", "GroupInline"],
        )
        self.assertEqual(
            [group["GroupName"] for group in analysis["groups"]],
            ["Developers"],
        )


if __name__ == "__main__":
    unittest.main()
