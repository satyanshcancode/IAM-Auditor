"""Unit tests for aws/access_advisor.py module."""

from datetime import datetime, timezone
from unittest.mock import MagicMock

from aws.access_advisor import (
    analyze_unused_services,
    generate_right_sized_policy_proposal,
    get_service_last_accessed_details,
)


def test_get_service_last_accessed_details_completed() -> None:
    mock_iam = MagicMock()
    mock_iam.generate_service_last_accessed_details.return_value = {"JobId": "job-123"}
    mock_iam.get_service_last_accessed_details.return_value = {
        "JobStatus": "COMPLETED",
        "ServicesLastAccessed": [
            {
                "ServiceName": "Amazon S3",
                "ServiceNamespace": "s3",
                "LastAuthenticated": datetime(2026, 1, 1, tzinfo=timezone.utc),
            },
            {
                "ServiceName": "AWS CodeCommit",
                "ServiceNamespace": "codecommit",
                "LastAuthenticated": None,
            },
        ],
    }

    res = get_service_last_accessed_details(
        arn="arn:aws:iam::123456789012:user/alice",
        iam_client=mock_iam,
        poll_interval_seconds=0.01,
    )

    assert res["job_status"] == "COMPLETED"
    assert len(res["services"]) == 2
    assert res["services"][0]["service_namespace"] == "s3"
    assert res["services"][0]["tracked_status"] == "ACTIVE"
    assert res["services"][1]["tracked_status"] == "CONFIRMED_INACTIVE"


def test_analyze_unused_services_classification() -> None:
    ref_date = datetime(2026, 10, 1, tzinfo=timezone.utc)
    services_input = [
        {"service_namespace": "s3", "last_authenticated": "2026-09-15T00:00:00+00:00"},  # 16 days idle -> ACTIVE
        {"service_namespace": "codecommit", "last_authenticated": "2026-01-01T00:00:00+00:00"},  # 273 days idle -> INACTIVE
        {"service_namespace": "dynamodb", "last_authenticated": None},  # No access -> INACTIVE
    ]

    res = analyze_unused_services(
        services_last_accessed=services_input,
        threshold_days=90,
        reference_date=ref_date,
    )

    assert "s3" in res["active_services"]
    assert "codecommit" in res["inactive_services"]
    assert "dynamodb" in res["inactive_services"]
    assert len(res["evidence"]) == 3


def test_generate_right_sized_policy_proposal_with_untracked_safeguard() -> None:
    original_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowS3AndCodeCommitAndPassRole",
                "Effect": "Allow",
                "Action": [
                    "s3:GetObject",
                    "codecommit:GitPull",
                    "iam:PassRole",  # Critical untracked permission safeguard!
                    "kms:Decrypt",   # Critical untracked permission safeguard!
                ],
                "Resource": "*",
            },
            {
                "Sid": "ExplicitDeny",
                "Effect": "Deny",
                "Action": ["s3:DeleteBucket"],
                "Resource": "*",
            },
        ],
    }

    res = generate_right_sized_policy_proposal(
        original_policy_doc=original_policy,
        inactive_services=["codecommit"],
        policy_name="RightSizedTestPolicy",
    )

    proposed = res["proposed_policy"]
    stmt0_actions = proposed["Statement"][0]["Action"]

    assert "codecommit:GitPull" not in stmt0_actions
    assert "s3:GetObject" in stmt0_actions
    assert "iam:PassRole" in stmt0_actions  # Must be safeguarded!
    assert "kms:Decrypt" in stmt0_actions   # Must be safeguarded!
    assert "codecommit" in res["pruned_services"]
    assert "iam:PassRole" in res["safeguarded_permissions"]
