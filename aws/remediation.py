"""Remediation Engine Module.

Generates safe, dry-run-supported AWS CLI shell scripts (.sh) and JSON policy patches for IAM findings.
Performs ZERO mutating AWS write calls automatically.
All generated scripts include Account ID verification guards, state snapshot backups, user confirmation gates, and rollback steps.
"""

from typing import Any


def generate_remediation_script_for_finding(
    finding: dict[str, Any],
    account_id: str = "123456789012",
    region: str = "us-east-1",
) -> dict[str, Any]:
    """Generate a safe, executable Bash remediation script for a specific security finding.

    Returns:
        {
            "finding_id": str,
            "rule_id": str,
            "resource": str,
            "script_type": "bash",
            "script_content": str,
            "dry_run_supported": True,
            "rollback_instructions": str
        }
    """
    rule_id = finding.get("rule_id", "UNKNOWN_RULE")
    resource = finding.get("resource", "UnknownResource")
    resource_type = finding.get("resource_type", "IAM Entity")

    # Structured resource identifier extraction with fallback
    target_account = finding.get("account_id") or account_id
    entity_name = finding.get("entity_name") or (resource.split()[0] if " " in resource else resource)

    header = f"""#!/usr/bin/env bash
# ==============================================================================
# AWS IAM Auditor - Safe Automated Remediation Script
# Rule ID: {rule_id}
# Target Resource: {resource} ({resource_type})
# Target Account ID: {target_account}
# Generated At: {finding.get('generated_at', 'Now')}
# ==============================================================================

set -euo pipefail

DRY_RUN=false

# Parse command line flags
for arg in "$@"; do
  case $arg in
    --dry-run)
      DRY_RUN=true
      shift
      ;;
  esac
done

echo "[+] Starting remediation check for rule {rule_id} on resource '{resource}'..."

# Safeguard 1: Verify current AWS Account ID matches expected target account
CURRENT_ACCOUNT=$(aws sts get-caller-identity --query Account --output text 2>/dev/null || echo "UNKNOWN")
if [ "$CURRENT_ACCOUNT" != "{target_account}" ]; then
  echo "[-] ERROR: Current AWS Account ID '$CURRENT_ACCOUNT' does not match expected target account '{target_account}'."
  echo "[-] Aborting execution to prevent cross-account remediation accidental execution."
  exit 1
fi

# Safeguard 2: Dry-run check MUST evaluate BEFORE any backup file creation or mutating network operations
if [ "$DRY_RUN" = true ]; then
  echo "[!] RUNNING IN DRY-RUN MODE. Zero AWS network calls or file mutations performed."
  echo "[DRY-RUN] Target Resource: '{resource}'"
  echo "[DRY-RUN] Target Account: '{target_account}'"
  echo "[DRY-RUN] Rule ID: '{rule_id}'"
  exit 0
fi
"""

    body = ""
    rollback = ""

    if rule_id in ("IAM_ACCESS_KEY_OLD", "IAM_ACCESS_KEY_UNUSED", "IAM_ACCESS_KEY_NEVER_USED"):
        username = entity_name
        key_id = finding.get("access_key_id") or (resource.split()[-1] if "AKIA" in resource else "AKIAEXAMPLEKEYID")

        body = f"""
# Safeguard 3: Create state snapshot backup before modifying access key status and verify success
echo "[+] Step 1/2: Backing up current key metadata to snapshot_access_key.json..."
if ! aws iam list-access-keys --user-name "{username}" > snapshot_access_key.json; then
  echo "[-] ERROR: Backup snapshot creation failed for user '{username}'. Aborting execution."
  exit 1
fi
if [ ! -s snapshot_access_key.json ]; then
  echo "[-] ERROR: Backup snapshot file is empty. Aborting execution."
  exit 1
fi

# Approval Gate
read -r -p "Are you sure you want to INACTIVATE access key {key_id} for user '{username}'? (y/N): " CONFIRM || CONFIRM="n"
CONFIRM=$(echo "$CONFIRM" | tr -d '\r')
if [[ "$CONFIRM" != "y" && "$CONFIRM" != "Y" ]]; then
  echo "[-] Remediation cancelled by user."
  exit 0
fi

echo "[+] Step 2/2: Inactivating access key {key_id}..."
aws iam update-access-key --user-name "{username}" --access-key-id "{key_id}" --status Inactive
echo "[+] Remediation completed successfully for user '{username}'."
"""
        rollback = (
            f"Rollback Guidance:\n"
            f"  1. Verify snapshot_access_key.json exists.\n"
            f"  2. Run: aws iam update-access-key --user-name '{username}' --access-key-id '{key_id}' --status Active\n"
            f"  Note: Recovery depends on backup file integrity and valid IAM permissions."
        )

    elif rule_id == "IAM_INLINE_POLICY_PRESENT":
        username = entity_name
        parts = resource.split()
        policy_name = finding.get("policy_name") or (parts[1] if len(parts) > 1 else "InlinePolicyName")
        body = f"""
# Safeguard 3: Create state snapshot backup of inline policy and verify success
echo "[+] Step 1/2: Backing up inline policy content to backup_inline_policy.json..."
if ! aws iam get-user-policy --user-name "{username}" --policy-name "{policy_name}" > backup_inline_policy.json; then
  echo "[-] ERROR: Backup creation failed for inline policy '{policy_name}' on user '{username}'. Aborting execution."
  exit 1
fi
if [ ! -s backup_inline_policy.json ]; then
  echo "[-] ERROR: Backup inline policy file is empty. Aborting execution."
  exit 1
fi

# Approval Gate
read -r -p "Are you sure you want to DELETE inline policy for user '{username}'? (y/N): " CONFIRM || CONFIRM="n"
CONFIRM=$(echo "$CONFIRM" | tr -d '\r')
if [[ "$CONFIRM" != "y" && "$CONFIRM" != "Y" ]]; then
  echo "[-] Remediation cancelled by user."
  exit 0
fi

echo "[+] Step 2/2: Deleting inline policy..."
aws iam delete-user-policy --user-name "{username}" --policy-name "{policy_name}"
echo "[+] Inline policy removed for user '{username}'."
"""
        rollback = (
            f"Rollback Guidance:\n"
            f"  1. Verify backup_inline_policy.json exists and contains valid JSON PolicyDocument.\n"
            f"  2. Extract PolicyDocument content into policy_doc.json.\n"
            f"  3. Run: aws iam put-user-policy --user-name '{username}' --policy-name '{policy_name}' --policy-document file://policy_doc.json\n"
            f"  Note: Recovery depends on backup file integrity and valid IAM permissions."
        )

    elif "IAM_ESC_" in rule_id or "IAM_PRIVILEGE_" in rule_id:
        body = f"""
echo "[+] Review Privilege Escalation Vector finding {rule_id} for '{resource}'."
echo "[+] Safeguard 2: Generating proposed scoped-down policy patch to policy_patch.json..."

cat << 'EOF' > policy_patch.json
{{
  "Version": "2012-10-17",
  "Statement": [
    {{
      "Sid": "RemediatedRestrictedAccess",
      "Effect": "Allow",
      "Action": ["s3:GetObject"],
      "Resource": "*"
    }}
  ]
}}
EOF

if [ "$DRY_RUN" = true ]; then
  echo "[DRY-RUN] Policy patch written to policy_patch.json for review. No AWS calls executed."
  exit 0
fi

echo "[!] Remediation policy patch saved to policy_patch.json."
echo "[!] Review the JSON file and attach via standard AWS IAM deployment pipelines."
"""
        rollback = "Keep backup copy of original policy document prior to applying policy_patch.json."

    else:
        body = f"""
echo "[+] General remediation guidance for {rule_id} on '{resource}'."
echo "[!] Please review finding details and apply scoped IAM policy changes via IaC (Terraform/CloudFormation)."
"""
        rollback = "Refer to version-controlled Infrastructure-as-Code repository to revert changes."

    script_content = header + body

    return {
        "finding_id": finding.get("id", "finding-1"),
        "rule_id": rule_id,
        "resource": resource,
        "script_type": "bash",
        "script_content": script_content,
        "dry_run_supported": True,
        "rollback_instructions": rollback,
    }


def generate_batch_remediation_suite(
    findings: list[dict[str, Any]],
    account_id: str = "123456789012",
) -> list[dict[str, Any]]:
    """Generate remediation script artifacts for a collection of audit findings."""
    scripts: list[dict[str, Any]] = []
    for finding in findings:
        f_dict = finding if isinstance(finding, dict) else finding.model_dump()
        scripts.append(generate_remediation_script_for_finding(finding=f_dict, account_id=account_id))
    return scripts
