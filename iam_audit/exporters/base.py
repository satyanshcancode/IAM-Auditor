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
                "Severity",
                "Resource",
                "Resource Type",
                "Issue",
                "Impact",
                "Recommendation",
            ]
        )
        for finding in report.findings:
            writer.writerow(
                [
                    finding.id,
                    finding.severity,
                    finding.resource,
                    finding.resource_type,
                    finding.issue,
                    finding.impact,
                    finding.recommendation,
                ]
            )


def export_sarif(report: AuditReport, path: Path, tool_name: str = "iam-access-auditor") -> None:
    """Export findings to SARIF format for security tool integration."""
    path.parent.mkdir(parents=True, exist_ok=True)

    results = []
    for finding in report.findings:
        level = "error" if finding.severity == "CRITICAL" else "warning"
        results.append(
            {
                "ruleId": finding.id,
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
                        "informationUri": "https://github.com/yourusername/iam-access-auditor",
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
        f"Generated   : {report.generated_at}",
        f"Users       : {report.total_users}",
        f"Groups      : {report.total_groups}",
        f"Roles       : {report.total_roles}",
        "",
        f"Critical    : {report.critical_findings}",
        f"Warnings    : {report.warnings}",
        f"Status      : {report.overall_status}",
        "",
    ]

    if report.findings:
        lines.append("FINDINGS")
        lines.append("-" * 65)
        for finding in report.findings:
            lines.append(f"[{finding.severity}] {finding.id}: {finding.issue}")
            lines.append(f"  Resource: {finding.resource}")
            lines.append(f"  Recommendation: {finding.recommendation}")
            lines.append("")

    lines.append("=" * 65)
    return "\n".join(lines)
