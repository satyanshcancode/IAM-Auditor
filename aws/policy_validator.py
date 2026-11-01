"""IAM Policy Validator and Simulator Wrapper Module.

Provides JSON structural validation for IAM policy documents and wraps `iam:SimulateCustomPolicy`
to test policy permissions against specific action lists while documenting simulator evaluation limitations.
"""

import json
import logging
from typing import Any

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)

# Documented IAM Simulator evaluation limitations for transparent audit reporting
SIMULATION_LIMITATIONS_DOC: str = (
    "Note on Policy Simulation Limitations: AWS IAM SimulateCustomPolicy evaluates principal-based policies only. "
    "It DOES NOT evaluate Service Control Policies (SCPs), Resource-Based Policies (e.g. S3 Bucket Policies, "
    "KMS Key Policies, RAM Shares), Session Policies, or Permission Boundaries unless explicitly passed in context. "
    "Passing simulator checks confirms syntactical evaluation, but DOES NOT guarantee full runtime access across all AWS services."
)


def validate_policy_syntax(policy_input: dict[str, Any] | str) -> dict[str, Any]:
    """Validate standard AWS IAM policy document syntax and structural correctness.

    Returns:
        {
            "valid": bool,
            "errors": list[str],
            "warnings": list[str],
            "policy_doc": dict[str, Any] | None
        }
    """
    errors: list[str] = []
    warnings: list[str] = []
    policy_doc: dict[str, Any] | None = None

    if isinstance(policy_input, str):
        try:
            policy_doc = json.loads(policy_input)
        except Exception as exc:
            errors.append(f"Invalid JSON format: {exc}")
            return {"valid": False, "errors": errors, "warnings": warnings, "policy_doc": None}
    elif isinstance(policy_input, dict):
        policy_doc = policy_input
    else:
        errors.append("Policy input must be a dictionary or a JSON string")
        return {"valid": False, "errors": errors, "warnings": warnings, "policy_doc": None}

    if not isinstance(policy_doc, dict):
        errors.append("Top-level IAM policy must be a JSON object (dict)")
        return {"valid": False, "errors": errors, "warnings": warnings, "policy_doc": None}

    # Version check
    version = policy_doc.get("Version")
    if not version:
        warnings.append("Missing 'Version' element; AWS defaults to '2008-10-17'. Recommended: '2012-10-17'")
    elif version not in ["2012-10-17", "2008-10-17"]:
        warnings.append(f"Unusual policy Version '{version}'")

    # Statement check
    statements = policy_doc.get("Statement")
    if statements is None:
        errors.append("Missing required 'Statement' element in IAM policy")
        return {"valid": False, "errors": errors, "warnings": warnings, "policy_doc": policy_doc}

    if isinstance(statements, dict):
        statements = [statements]
    elif not isinstance(statements, list):
        errors.append("'Statement' element must be a list or a single JSON object")
        return {"valid": False, "errors": errors, "warnings": warnings, "policy_doc": policy_doc}

    if len(statements) == 0:
        errors.append("'Statement' element list cannot be empty")
        return {"valid": False, "errors": errors, "warnings": warnings, "policy_doc": policy_doc}

    for idx, stmt in enumerate(statements):
        if not isinstance(stmt, dict):
            errors.append(f"Statement[{idx}] is not a valid JSON object")
            continue

        # Check Effect
        effect = stmt.get("Effect")
        if not effect:
            errors.append(f"Statement[{idx}] missing required 'Effect' element")
        elif effect not in ["Allow", "Deny"]:
            errors.append(f"Statement[{idx}] invalid Effect '{effect}'. Must be 'Allow' or 'Deny'")

        # Check Action / NotAction
        action = stmt.get("Action")
        not_action = stmt.get("NotAction")
        if not action and not not_action:
            errors.append(f"Statement[{idx}] must specify either 'Action' or 'NotAction'")

        # Check Resource / NotResource
        resource = stmt.get("Resource")
        not_resource = stmt.get("NotResource")
        if not resource and not not_resource:
            errors.append(f"Statement[{idx}] must specify either 'Resource' or 'NotResource'")

    is_valid = len(errors) == 0
    return {
        "valid": is_valid,
        "errors": errors,
        "warnings": warnings,
        "policy_doc": policy_doc,
    }


def simulate_custom_policy(
    policy_doc: dict[str, Any],
    action_names: list[str],
    resource_arns: list[str] | None = None,
    iam_client: Any | None = None,
) -> dict[str, Any]:
    """Wrapper around `iam:SimulateCustomPolicy` to test custom candidate policy evaluation.

    Returns:
        {
            "status": "SUCCESS" | "FAILED",
            "results": [
                {
                    "action": action,
                    "decision": "allowed" | "explicitDeny" | "implicitDeny",
                    "matched_statements": [...]
                }, ...
            ],
            "limitations_disclaimer": SIMULATION_LIMITATIONS_DOC,
            "error": None | str
        }
    """
    if iam_client is None:
        iam_client = boto3.client("iam")

    if resource_arns is None:
        resource_arns = ["*"]

    policy_json_str = json.dumps(policy_doc)

    try:
        response = iam_client.simulate_custom_policy(
            PolicyInputList=[policy_json_str],
            ActionNames=action_names,
            ResourceArns=resource_arns,
        )

        eval_results: list[dict[str, Any]] = []
        for res in response.get("EvaluationResults", []):
            eval_results.append({
                "action": res.get("EvalActionName"),
                "decision": res.get("EvalDecision"),
                "matched_statements": res.get("MatchedStatements", []),
            })

        return {
            "status": "SUCCESS",
            "results": eval_results,
            "limitations_disclaimer": SIMULATION_LIMITATIONS_DOC,
            "error": None,
        }
    except ClientError as err:
        logger.error(f"Policy simulation error: {err}")
        return {
            "status": "FAILED",
            "results": [],
            "limitations_disclaimer": SIMULATION_LIMITATIONS_DOC,
            "error": str(err),
        }
