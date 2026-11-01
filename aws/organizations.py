"""AWS Organizations and Multi-Account Governance Module.

Provides cross-account STS role assumption, paginated AWS Organizations account discovery,
bounded parallel execution across multiple AWS accounts, and explicit partial scan status reporting.
"""

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

import boto3
from botocore.exceptions import ClientError

from aws.report import collect_account_audit

logger = logging.getLogger(__name__)


def get_sts_client(region_name: str = "us-east-1") -> Any:
    """Return an STS boto3 client."""
    return boto3.client("sts", region_name=region_name)


def get_org_client(region_name: str = "us-east-1") -> Any:
    """Return an AWS Organizations boto3 client."""
    return boto3.client("organizations", region_name=region_name)


def assume_role(
    account_id: str,
    role_name: str = "IAMAuditorRole",
    external_id: str | None = None,
    session_name: str = "IAMAuditorSession",
    region_name: str = "us-east-1",
) -> dict[str, Any]:
    """Assume a cross-account audit role in a target AWS account using STS.

    Returns temporary credentials dictionary with AccessKeyId, SecretAccessKey, and SessionToken.
    """
    role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"
    sts = get_sts_client(region_name=region_name)

    kwargs: dict[str, Any] = {
        "RoleArn": role_arn,
        "RoleSessionName": session_name,
        "DurationSeconds": 3600,
    }
    if external_id:
        kwargs["ExternalId"] = external_id

    try:
        response = sts.assume_role(**kwargs)
        creds = response["Credentials"]
        return {
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        }
    except ClientError as err:
        logger.error(f"Failed to assume role {role_arn}: {err}")
        raise


def get_iam_client_for_account(
    account_id: str,
    role_name: str = "IAMAuditorRole",
    external_id: str | None = None,
    region_name: str = "us-east-1",
) -> Any:
    """Create a boto3 IAM client using assumed cross-account credentials."""
    creds = assume_role(account_id=account_id, role_name=role_name, external_id=external_id, region_name=region_name)
    return boto3.client("iam", region_name=region_name, **creds)


def list_organization_accounts(org_client: Any | None = None) -> list[dict[str, Any]]:
    """List all accounts in the AWS Organization with full pagination support.

    Returns a list of dicts: [{'Id': ..., 'Name': ..., 'Status': ..., 'Email': ...}]
    """
    if org_client is None:
        org_client = get_org_client()

    accounts: list[dict[str, Any]] = []
    paginator = org_client.get_paginator("list_accounts")

    try:
        for page in paginator.paginate():
            for acc in page.get("Accounts", []):
                accounts.append({
                    "Id": acc.get("Id"),
                    "Name": acc.get("Name"),
                    "Status": acc.get("Status"),
                    "Email": acc.get("Email"),
                    "Arn": acc.get("Arn"),
                })
    except ClientError as err:
        logger.error(f"Failed to list organization accounts: {err}")
        raise

    return accounts


def scan_single_account(
    account_id: str,
    role_name: str = "IAMAuditorRole",
    external_id: str | None = None,
    account_name: str | None = None,
) -> dict[str, Any]:
    """Perform a security audit scan on a single target account.

    Handles role assumption failures, throttling, and collection errors gracefully.
    Returns account scan result dictionary.
    """
    result: dict[str, Any] = {
        "account_id": account_id,
        "account_name": account_name or f"Account-{account_id}",
        "status": "FAILED",
        "error": None,
        "report": None,
        "findings_count": 0,
    }

    try:
        iam_client = get_iam_client_for_account(account_id=account_id, role_name=role_name, external_id=external_id)
        # Run account audit collection using assumed role IAM client
        report = collect_account_audit(iam_client=iam_client)
        result["report"] = report
        result["status"] = "SUCCESS"
        result["findings_count"] = len(report.get("findings", []))
    except ClientError as err:
        code = err.response.get("Error", {}).get("Code", "ClientError")
        msg = err.response.get("Error", {}).get("Message", str(err))
        result["error"] = f"[{code}] {msg}"
        logger.warning(f"Scan failed for account {account_id}: [{code}] {msg}")
    except Exception as exc:
        result["error"] = str(exc)
        logger.warning(f"Unexpected error scanning account {account_id}: {exc}")

    return result


def scan_organization(
    role_name: str = "IAMAuditorRole",
    account_ids: list[str] | None = None,
    external_id: str | None = None,
    max_workers: int = 5,
) -> dict[str, Any]:
    """Perform a multi-account organization audit scan with bounded concurrency.

    If account_ids is None, discovers active accounts via AWS Organizations API.
    If any account fails, the overall status is set to 'PARTIAL_SCAN_COMPLETED' (never 'COMPLETE').

    Returns a Multi-Account Audit Summary.
    """
    # Enforce safe bounded concurrency between 1 and 10 workers
    workers = max(1, min(max_workers, 10))

    accounts_to_scan: list[dict[str, Any]] = []

    if account_ids:
        accounts_to_scan = [{"Id": acc_id, "Name": f"Account-{acc_id}"} for acc_id in account_ids]
    else:
        try:
            raw_accounts = list_organization_accounts()
            # Only scan ACTIVE accounts
            accounts_to_scan = [a for a in raw_accounts if a.get("Status") == "ACTIVE"]
        except Exception as exc:
            return {
                "scan_status": "FAILED",
                "total_accounts": 0,
                "successful_scans": 0,
                "failed_scans": 0,
                "collection_errors": [{"account_id": "ALL", "error": f"Failed to list organization accounts: {exc}"}],
                "account_results": [],
                "aggregated_findings": [],
            }

    account_results: list[dict[str, Any]] = []
    aggregated_findings: list[dict[str, Any]] = []
    collection_errors: list[dict[str, Any]] = []

    # Execute concurrent account scans with ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=workers) as executor:
        future_to_acc = {
            executor.submit(
                scan_single_account,
                account_id=acc["Id"],
                role_name=role_name,
                external_id=external_id,
                account_name=acc.get("Name"),
            ): acc["Id"]
            for acc in accounts_to_scan
        }

        for future in as_completed(future_to_acc):
            acc_id = future_to_acc[future]
            try:
                res = future.result()
                account_results.append(res)
                if res["status"] == "SUCCESS" and res.get("report"):
                    # Annotate findings with account ID
                    for finding in res["report"].get("findings", []):
                        finding_copy = dict(finding) if isinstance(finding, dict) else finding.model_dump()
                        finding_copy["account_id"] = acc_id
                        aggregated_findings.append(finding_copy)
                else:
                    collection_errors.append({
                        "account_id": acc_id,
                        "error": res.get("error") or "Unknown collection error",
                    })
            except Exception as exc:
                account_results.append({
                    "account_id": acc_id,
                    "status": "FAILED",
                    "error": str(exc),
                    "report": None,
                })
                collection_errors.append({"account_id": acc_id, "error": str(exc)})

    successful_count = sum(1 for r in account_results if r["status"] == "SUCCESS")
    failed_count = len(account_results) - successful_count

    # Determine overall scan status explicitly
    if failed_count == 0 and len(account_results) > 0:
        overall_status = "COMPLETE"
    elif successful_count > 0 and failed_count > 0:
        overall_status = "PARTIAL_SCAN_COMPLETED"
    else:
        overall_status = "FAILED"

    return {
        "scan_status": overall_status,
        "total_accounts": len(account_results),
        "successful_scans": successful_count,
        "failed_scans": failed_count,
        "account_results": account_results,
        "aggregated_findings": aggregated_findings,
        "collection_errors": collection_errors,
    }
