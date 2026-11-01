# Terraform Infrastructure for IAM Auditor (ECS Fargate + EventBridge)

This directory contains optional Infrastructure-as-Code (IaC) configuration to deploy the **IAM Auditor CLI** as a scheduled, serverless container task using AWS ECS Fargate and EventBridge.

## Architecture Overview

1. **EventBridge (CloudWatch Events)**: Triggers the container task according to a defined schedule (`cron(0 6 * * ? *)` by default, daily at 06:00 UTC).
2. **ECS Fargate Task**: Runs a transient instance of `iam-auditor:latest` (0.25 vCPU, 512 MB RAM) that executes an audit scan and exits cleanly.
3. **IAM Task Role**: Uses `SecurityAudit` AWS managed policy + STS `AssumeRole` capabilities. **No static access keys are created or stored.**
4. **Encrypted S3 Bucket**: Stores machine-readable audit report artifacts (JSON / SARIF) with default AES-256 server-side encryption and public access blocking.
5. **CloudWatch Logs**: Collects application execution logs with 30-day retention.

## Expected AWS Cost Analysis

Running IAM Auditor as an automated container task incurs minimal costs:
- **ECS Fargate (Daily 1-minute execution)**: ~30 minutes/month of 0.25 vCPU / 512MB RAM = **<$0.02 / month** (well within AWS Free Tier).
- **Encrypted S3 Bucket**: < 1 MB storage per month = **<$0.01 / month**.
- **CloudWatch Logs**: ~5 MB logs/month = **Free Tier**.
- **Total Estimated Cost**: **<$0.05 / month** (virtually zero).

## Security Safeguards

- **No Long-Lived Static Keys**: Authenticates using IAM Task Roles and AWS STS temporary session credentials.
- **Least Privilege**: Only requests `SecurityAudit` read-only permissions and S3 `PutObject` access for report export.
- **S3 Hardening**: Enforces SSE-S3 encryption and blocks all public ACLs and bucket policies.
- **Non-Destructive**: The scheduled task runs in audit mode and does not perform resource remediation.

## How to Deploy (Requires Approval)

> [!WARNING]
> Do not execute `terraform apply` without explicit user approval and verified credentials.

```bash
cd terraform
terraform init
terraform plan
terraform apply
```

## How to Teardown Resources

To clean up all AWS resources created by this Terraform module:

```bash
cd terraform
terraform destroy
```
