"""Runtime Execution Security Tests for Generated Remediation Scripts.

Executes generated Bash remediation scripts in isolated subprocess environments with a mock AWS CLI.
Verifies runtime dry-run behavior, account ID guards, missing credentials, backup failures,
empty backups, declined approval, and confirmed execution.
"""

import os
import shutil
import stat
import subprocess
from pathlib import Path

from aws.remediation import generate_remediation_script_for_finding


def create_mock_aws_cli(
    bin_dir: Path,
    account_id: str = "123456789012",
    sts_fail: bool = False,
    backup_fail: bool = False,
    backup_empty: bool = False,
) -> Path:
    """Create a mock executable 'aws' script in bin_dir to log AWS calls and mock responses."""

    # Shell script content for mock aws CLI (strict LF line endings)
    mock_script_content = f"""#!/usr/bin/env bash
SCRIPT_DIR="$(cd "$(dirname "${{BASH_SOURCE[0]}}")" && pwd)"
echo "$@" >> "$SCRIPT_DIR/aws_calls.log"

if [ "$1" = "sts" ] && [ "$2" = "get-caller-identity" ]; then
  if [ "{'true' if sts_fail else 'false'}" = "true" ]; then
    echo "ExpiredToken: The security token included in the request is expired" >&2
    exit 1
  fi
  echo "{account_id}"
  exit 0
fi

if [ "$1" = "iam" ] && [ "$2" = "list-access-keys" ]; then
  if [ "{'true' if backup_fail else 'false'}" = "true" ]; then
    echo "AccessDenied: Not authorized to perform iam:ListAccessKeys" >&2
    exit 1
  fi
  if [ "{'true' if backup_empty else 'false'}" = "true" ]; then
    exit 0
  fi
  echo '{{"AccessKeyMetadata": [{{"AccessKeyId": "AKIAEXAMPLEKEYID", "Status": "Active"}}]}}'
  exit 0
fi

if [ "$1" = "iam" ] && [ "$2" = "get-user-policy" ]; then
  if [ "{'true' if backup_fail else 'false'}" = "true" ]; then
    echo "NoSuchEntity: Policy not found" >&2
    exit 1
  fi
  if [ "{'true' if backup_empty else 'false'}" = "true" ]; then
    exit 0
  fi
  echo '{{"PolicyDocument": {{"Version": "2012-10-17", "Statement": []}}}}'
  exit 0
fi

if [ "$1" = "iam" ] && [ "$2" = "update-access-key" ]; then
  echo "Updated key"
  exit 0
fi

if [ "$1" = "iam" ] && [ "$2" = "delete-user-policy" ]; then
  echo "Deleted inline policy"
  exit 0
fi

exit 0
"""
    # Replace any CRLF with LF
    mock_script_content = mock_script_content.replace("\r\n", "\n")

    aws_bin = bin_dir / "aws"
    with open(aws_bin, "w", encoding="utf-8", newline="\n") as f:
        f.write(mock_script_content)

    aws_bin.chmod(aws_bin.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return aws_bin


def run_script_in_test_env(
    script_content: str,
    tmp_path: Path,
    mock_aws_kwargs: dict | None = None,
    args: list[str] | None = None,
    input_str: str | None = None,
) -> subprocess.CompletedProcess:
    """Helper to run a generated remediation bash script inside a temporary directory."""
    if mock_aws_kwargs is None:
        mock_aws_kwargs = {}

    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    create_mock_aws_cli(bin_dir, **mock_aws_kwargs)

    # Ensure LF line endings for target bash script
    clean_script_content = script_content.replace("\r\n", "\n")
    script_path = tmp_path / "remediate.sh"
    with open(script_path, "w", encoding="utf-8", newline="\n") as f:
        f.write(clean_script_content)

    script_path.chmod(script_path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    # Set PATH so mock aws CLI comes first
    env = os.environ.copy()
    env["PATH"] = f"{bin_dir.as_posix()}{os.pathsep}{env.get('PATH', '')}"

    bash_bin = shutil.which("bash") or "bash"
    cmd = [bash_bin, "./remediate.sh"]
    if args:
        cmd.extend(args)

    res = subprocess.run(
        cmd,
        cwd=tmp_path.as_posix(),
        env=env,
        input=input_str,
        text=True,
        capture_output=True,
    )
    return res


def test_runtime_dry_run_zero_mutations(tmp_path: Path) -> None:
    """Runtime test: --dry-run mode executes zero network mutations and creates zero backup files."""
    finding = {"id": "f-rt-1", "rule_id": "IAM_ACCESS_KEY_OLD", "resource": "alice AKIAEXAMPLEKEYID"}
    script_data = generate_remediation_script_for_finding(finding=finding, account_id="123456789012")

    proc = run_script_in_test_env(
        script_content=script_data["script_content"],
        tmp_path=tmp_path,
        args=["--dry-run"],
    )

    assert proc.returncode == 0
    assert "[!] RUNNING IN DRY-RUN MODE" in proc.stdout
    # Zero backup snapshot files created
    assert not (tmp_path / "snapshot_access_key.json").exists()

    # Verify mock AWS call log contains zero mutating write calls
    log_file = tmp_path / "bin" / "aws_calls.log"
    if log_file.exists():
        calls = log_file.read_text(encoding="utf-8")
        assert "update-access-key" not in calls
        assert "list-access-keys" not in calls


def test_runtime_wrong_account_id_halt(tmp_path: Path) -> None:
    """Runtime test: Wrong account ID halts script execution cleanly with non-zero exit code."""
    finding = {"id": "f-rt-2", "rule_id": "IAM_ACCESS_KEY_OLD", "resource": "alice AKIAEXAMPLEKEYID"}
    script_data = generate_remediation_script_for_finding(finding=finding, account_id="123456789012")

    proc = run_script_in_test_env(
        script_content=script_data["script_content"],
        tmp_path=tmp_path,
        mock_aws_kwargs={"account_id": "999999999999"},  # Wrong caller account!
    )

    assert proc.returncode == 1
    assert "ERROR: Current AWS Account ID '999999999999' does not match expected target account '123456789012'" in proc.stdout


def test_runtime_sts_credentials_failure_halt(tmp_path: Path) -> None:
    """Runtime test: STS caller identity failure halts execution with non-zero exit code."""
    finding = {"id": "f-rt-3", "rule_id": "IAM_INLINE_POLICY_PRESENT", "resource": "bob InlinePolicy"}
    script_data = generate_remediation_script_for_finding(finding=finding, account_id="123456789012")

    proc = run_script_in_test_env(
        script_content=script_data["script_content"],
        tmp_path=tmp_path,
        mock_aws_kwargs={"sts_fail": True},
    )

    assert proc.returncode == 1
    assert "ERROR: Current AWS Account ID 'UNKNOWN' does not match" in proc.stdout


def test_runtime_backup_failure_halt(tmp_path: Path) -> None:
    """Runtime test: Snapshot backup failure halts script before mutating write actions."""
    finding = {"id": "f-rt-4", "rule_id": "IAM_ACCESS_KEY_OLD", "resource": "alice AKIAEXAMPLEKEYID"}
    script_data = generate_remediation_script_for_finding(finding=finding, account_id="123456789012")

    proc = run_script_in_test_env(
        script_content=script_data["script_content"],
        tmp_path=tmp_path,
        mock_aws_kwargs={"backup_fail": True},
    )

    assert proc.returncode == 1
    assert "ERROR: Backup snapshot creation failed" in proc.stdout

    # Verify no update-access-key call was attempted
    log_file = tmp_path / "bin" / "aws_calls.log"
    if log_file.exists():
        calls = log_file.read_text(encoding="utf-8")
        assert "update-access-key" not in calls


def test_runtime_empty_backup_file_halt(tmp_path: Path) -> None:
    """Runtime test: Empty backup snapshot file halts script execution."""
    finding = {"id": "f-rt-5", "rule_id": "IAM_ACCESS_KEY_OLD", "resource": "alice AKIAEXAMPLEKEYID"}
    script_data = generate_remediation_script_for_finding(finding=finding, account_id="123456789012")

    proc = run_script_in_test_env(
        script_content=script_data["script_content"],
        tmp_path=tmp_path,
        mock_aws_kwargs={"backup_empty": True},
    )

    assert proc.returncode == 1
    assert "ERROR: Backup snapshot file is empty" in proc.stdout


def test_runtime_user_declined_approval(tmp_path: Path) -> None:
    """Runtime test: User declining approval prompt ('n') cancels script execution without mutating state."""
    finding = {"id": "f-rt-6", "rule_id": "IAM_ACCESS_KEY_OLD", "resource": "alice AKIAEXAMPLEKEYID"}
    script_data = generate_remediation_script_for_finding(finding=finding, account_id="123456789012")

    proc = run_script_in_test_env(
        script_content=script_data["script_content"],
        tmp_path=tmp_path,
        input_str="n\n",
    )

    assert proc.returncode == 0
    assert "Remediation cancelled by user." in proc.stdout

    # Backup was created, but no update-access-key call executed
    assert (tmp_path / "snapshot_access_key.json").exists()
    log_file = tmp_path / "bin" / "aws_calls.log"
    assert log_file.exists()
    calls = log_file.read_text(encoding="utf-8")
    assert "update-access-key" not in calls


def test_runtime_user_confirmed_approval_success(tmp_path: Path) -> None:
    """Runtime test: User confirming approval ('y') completes remediation successfully."""
    finding = {"id": "f-rt-7", "rule_id": "IAM_ACCESS_KEY_OLD", "resource": "alice AKIAEXAMPLEKEYID"}
    script_data = generate_remediation_script_for_finding(finding=finding, account_id="123456789012")

    proc = run_script_in_test_env(
        script_content=script_data["script_content"],
        tmp_path=tmp_path,
        input_str="y\n",
    )

    assert proc.returncode == 0
    assert "Remediation completed successfully" in proc.stdout

    # Backup was created AND update-access-key call was executed
    assert (tmp_path / "snapshot_access_key.json").exists()
    log_file = tmp_path / "bin" / "aws_calls.log"
    assert log_file.exists()
    calls = log_file.read_text(encoding="utf-8")
    assert "update-access-key" in calls
