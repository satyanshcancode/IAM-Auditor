"""Export audit results to JSON, CSV, and SARIF formats."""

import csv
import json
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from iam_audit.core.models import AuditReport


def _to_jsonable(data: BaseModel | dict[str, Any]) -> Any:
    if isinstance(data, BaseModel):
        return data.model_dump(mode="json")
    return data


def export_json(data: BaseModel | dict[str, Any], path: Path) -> None:
    """Export any Pydantic model or dict to a JSON file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = _to_jsonable(data)

    def serialize(obj: Any) -> Any:
        if isinstance(obj, set):
            return sorted(obj)
        if isinstance(obj, BaseModel):
            return obj.model_dump(mode="json")
        raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable")

    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, default=serialize, ensure_ascii=False)


def export_csv(report: AuditReport, path: Path) -> None:
    """Export findings to a CSV file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(
            [
                "Finding ID",
                "Rule ID",
                "Category",
                "Severity",
                "Confidence",
                "Resource",
                "Resource Type",
                "Issue",
                "Impact",
                "Recommendation",
                "Compliance Mappings",
                "Collection Status",
            ]
        )
        for finding in report.findings:
            writer.writerow(
                [
                    finding.id,
                    finding.rule_id or finding.id,
                    finding.category,
                    finding.severity,
                    finding.confidence,
                    finding.resource,
                    finding.resource_type,
                    finding.issue,
                    finding.impact,
                    finding.recommendation,
                    "; ".join(finding.compliance_mappings),
                    finding.collection_status,
                ]
            )


def export_sarif(report: AuditReport, path: Path, tool_name: str = "iam-access-auditor") -> None:
    """Export findings to SARIF format for security tool integration."""
    path.parent.mkdir(parents=True, exist_ok=True)

    results = []
    for finding in report.findings:
        if finding.severity in ("CRITICAL", "HIGH"):
            level = "error"
        elif finding.severity in ("WARNING", "MEDIUM"):
            level = "warning"
        else:
            level = "note"

        results.append(
            {
                "ruleId": finding.rule_id or finding.id,
                "level": level,
                "message": {"text": f"{finding.issue} - {finding.impact}"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": finding.resource},
                            "region": {"startLine": 1},
                        }
                    }
                ],
            }
        )

    sarif = {
        "$schema": (
            "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/"
            "Schemata/sarif-schema-2.1.0.json"
        ),
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": tool_name,
                        "informationUri": "https://github.com/satyanshcancode/IAM-Auditor",
                        "version": "2.0.0",
                    }
                },
                "results": results,
            }
        ],
    }

    with open(path, "w", encoding="utf-8") as f:
        json.dump(sarif, f, indent=2, ensure_ascii=False)


def export_console_summary(report: AuditReport) -> str:
    """Return a console-friendly summary string."""
    lines = [
        "=" * 65,
        "           IAM SECURITY AUDIT SUMMARY",
        "=" * 65,
        "",
        f"Generated             : {report.generated_at}",
        f"Users                 : {report.total_users}",
        f"Groups                : {report.total_groups}",
        f"Roles                 : {report.total_roles}",
        "",
        f"Critical              : {report.critical_findings}",
        f"Warnings / High       : {report.warnings}",
        f"Privilege Escalations : {report.privilege_escalation_count}",
        f"Sensitive Wildcards   : {report.sensitive_wildcard_count}",
        f"Role Trust Issues     : {report.role_trust_issue_count}",
        f"MFA Issues            : {report.mfa_issues}",
        f"Old Access Keys       : {report.old_access_keys}",
        f"Unused Keys           : {report.unused_access_keys}",
        f"Inactive Users        : {report.inactive_users}",
        f"Inline Policies       : {report.inline_policies_count}",
        f"Overall Status        : {report.overall_status}",
        "",
    ]

    if report.attack_paths:
        lines.append("ATTACK PATH GRAPH CORRELATIONS")
        lines.append("-" * 65)
        for ap in report.attack_paths:
            lines.append(f"[{ap.severity}] {ap.path_id}: {ap.title}")
            lines.append(f"  Summary: {ap.risk_summary}")
            for step in ap.steps:
                lines.append(f"    Step {step.step_number}: {step.source_entity} --({step.action_or_edge})--> {step.target_entity}")
            lines.append(f"  Remediation: {ap.remediation}")
            lines.append("")

    if report.collection_errors:
        lines.append("COLLECTION WARNINGS")
        lines.append("-" * 65)
        for err in report.collection_errors:
            lines.append(f"[WARNING] {err.get('check')}: {err.get('message')}")
        lines.append("")

    if report.findings:
        lines.append("FINDINGS")
        lines.append("-" * 65)
        for finding in report.findings:
            lines.append(f"[{finding.severity}] {finding.id} ({finding.category}): {finding.issue}")
            lines.append(f"  Resource: {finding.resource}")
            lines.append(f"  Confidence: {finding.confidence}")
            lines.append(f"  Recommendation: {finding.recommendation}")
            if finding.compliance_mappings:
                lines.append(f"  Compliance: {', '.join(finding.compliance_mappings)}")
            lines.append("")

    lines.append("=" * 65)
    return "\n".join(lines)
