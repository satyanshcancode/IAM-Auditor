"""Typer-based modern CLI for IAM Access Auditor."""

from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from iam_audit.core.engine import (
    build_remediation_script,
    check_permission,
    compare_two_users,
    get_user_analysis,
    list_inventory,
    run_access_advisor_audit,
    run_full_audit,
    run_organization_audit,
    search_by_permission,
)
from iam_audit.core.logging import setup_logging
from iam_audit.exporters.base import (
    export_console_summary,
    export_csv,
    export_json,
    export_sarif,
)

app = typer.Typer(
    name="iam-audit",
    help="AWS IAM Access Auditor & Permission Analyzer",
    add_completion=False,
)
console = Console()

VALID_FORMATS = {"console", "json", "csv", "sarif"}


@app.callback()
def main(
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable verbose logging"),
    log_file: Annotated[Path | None, typer.Option("--log-file", help="Path to log file")] = None,
) -> None:
    """IAM Access Auditor CLI."""
    level = 10 if verbose else 20  # DEBUG or INFO
    setup_logging(level=level, log_file=str(log_file) if log_file else None)


@app.command()
def audit(
    output: Annotated[Path | None, typer.Option("--output", "-o", help="Output file path")] = None,
    fmt: str = typer.Option(
        "console", "--format", "-f", help="Output format: console, json, csv, sarif"
    ),
    fail_on_findings: bool = typer.Option(
        False, "--fail-on-findings", help="Exit with non-zero exit code (2) if security findings are detected"
    ),
) -> None:
    """Run a full IAM security audit."""
    fmt = fmt.lower()
    if fmt not in VALID_FORMATS:
        console.print(f"[red]Unknown format '{fmt}'. Use console, json, csv, or sarif.[/red]")
        raise typer.Exit(2)

    if fmt != "console" and output is None:
        console.print("[red]--output is required when --format is not console.[/red]")
        raise typer.Exit(2)

    report = run_full_audit()

    if fmt == "json" and output is not None:
        export_json(report, output)
        console.print(f"[green]Report exported to {output}[/green]")
    elif fmt == "csv" and output is not None:
        export_csv(report, output)
        console.print(f"[green]Report exported to {output}[/green]")
    elif fmt == "sarif" and output is not None:
        export_sarif(report, output)
        console.print(f"[green]Report exported to {output}[/green]")
    else:
        console.print(export_console_summary(report))

    if fail_on_findings and len(report.findings) > 0:
        console.print(f"[yellow]Exiting with code 2 due to {len(report.findings)} security finding(s).[/yellow]")
        raise typer.Exit(2)


@app.command("demo")
def demo_cmd(
    output: Annotated[Path | None, typer.Option("--output", "-o", help="Save demo summary report to JSON file")] = None,
) -> None:
    """Run full offline portfolio demo scan."""
    from demo import run_portfolio_demo

    console.print("[cyan]Running IAM Auditor offline portfolio demo...[/cyan]")
    report = run_portfolio_demo()
    if output and report:
        export_json(report, output)
        console.print(f"[green]Demo report saved to {output}[/green]")


@app.command()
def inventory() -> None:
    """List IAM inventory (users, groups, roles)."""
    data = list_inventory()

    table = Table(title="IAM Inventory")
    table.add_column("Type", style="cyan")
    table.add_column("Count", style="magenta")
    table.add_column("Names", style="green")

    for entity_type, entities in data.items():
        names = [e.get("UserName", e.get("GroupName", e.get("RoleName", "N/A"))) for e in entities]
        extra = "..." if len(names) > 10 else ""
        table.add_row(
            entity_type.capitalize(),
            str(len(entities)),
            ", ".join(names[:10]) + extra,
        )

    console.print(table)


@app.command()
def permissions(
    username: str = typer.Argument(..., help="IAM username to analyze"),
    output: Annotated[Path | None, typer.Option("--output", "-o", help="Save to JSON file")] = None,
) -> None:
    """Analyze permissions for a specific user."""
    result = get_user_analysis(username)
    if result is None:
        console.print(f"[red]User '{username}' not found.[/red]")
        raise typer.Exit(1)

    table = Table(title=f"Permissions for {username}")
    table.add_column("Action", style="green")
    table.add_column("Type", style="cyan")

    for action in sorted(result.effective_actions):
        if action == "*":
            table.add_row(action, "[red]FULL ADMIN[/red]")
        elif action.endswith(":*"):
            table.add_row(action, "[yellow]FULL SERVICE[/yellow]")
        else:
            table.add_row(action, "[green]ALLOW[/green]")

    if result.denied_actions:
        for action in sorted(result.denied_actions):
            table.add_row(action, "[red]DENIED[/red]")

    console.print(table)

    if output:
        export_json(result, output)
        console.print(f"[green]Saved to {output}[/green]")


@app.command()
def check(
    username: str = typer.Argument(..., help="IAM username"),
    action: str = typer.Argument(..., help="Action to check (e.g., s3:GetObject)"),
) -> None:
    """Check if a user has a specific permission."""
    result = check_permission(username, action)
    if result.get("error"):
        console.print(f"[red]Error: {result['error']}[/red]")
        raise typer.Exit(1)

    if result["allowed"]:
        console.print(f"[green]{username} is ALLOWED to perform {action}[/green]")
    else:
        console.print(f"[red]{username} is DENIED from performing {action}[/red]")


@app.command()
def search(
    action: str = typer.Argument(..., help="Action to search for (e.g., s3:GetObject)"),
) -> None:
    """Search for users who have a specific permission."""
    matched = search_by_permission(action)

    if matched:
        console.print(f"[green]Found {len(matched)} user(s) with permission {action}:[/green]")
        for user in matched:
            console.print(f"  - {user}")
    else:
        console.print(f"[yellow]No users have permission {action}[/yellow]")


@app.command()
def compare(
    user1: str = typer.Argument(..., help="First username"),
    user2: str = typer.Argument(..., help="Second username"),
) -> None:
    """Compare permissions between two IAM users."""
    result = compare_two_users(user1, user2)
    if result is None:
        console.print("[red]One or both users not found.[/red]")
        raise typer.Exit(1)

    table = Table(title=f"Comparison: {user1} vs {user2}")
    table.add_column("Category", style="cyan")
    table.add_column("Count", style="magenta")

    table.add_row(f"Only {user1}", str(len(result.only_user1)))
    table.add_row(f"Only {user2}", str(len(result.only_user2)))
    table.add_row("Common", str(len(result.common)))

    if result.user1_admin:
        table.add_row(f"{user1} Admin?", "[red]YES - Full Administrator Access[/red]")
    if result.user2_admin:
        table.add_row(f"{user2} Admin?", "[red]YES - Full Administrator Access[/red]")

    console.print(table)

    if result.only_user1:
        console.print(f"\n[cyan]Permissions only {user1} has:[/cyan]")
        for p in result.only_user1[:20]:
            console.print(f"  - {p}")
        if len(result.only_user1) > 20:
            console.print(f"  ... and {len(result.only_user1) - 20} more")

    if result.only_user2:
        console.print(f"\n[cyan]Permissions only {user2} has:[/cyan]")
        for p in result.only_user2[:20]:
            console.print(f"  - {p}")
        if len(result.only_user2) > 20:
            console.print(f"  ... and {len(result.only_user2) - 20} more")


# Phase 3 Commands


@app.command("scan-org")
def scan_org(
    role_name: str = typer.Option("IAMAuditorRole", "--role-name", help="Cross-account audit role name"),
    account_ids: Annotated[list[str] | None, typer.Option("--account-id", "-a", help="Target Account IDs")] = None,
    external_id: Annotated[str | None, typer.Option("--external-id", help="STS External ID")] = None,
    max_workers: int = typer.Option(5, "--max-workers", help="Bounded thread pool workers (1-10)"),
    output: Annotated[Path | None, typer.Option("--output", "-o", help="Save report to JSON file")] = None,
) -> None:
    """Perform a multi-account organization audit scan."""
    console.print(f"[cyan]Initiating Multi-Account Audit (Role: {role_name}, Workers: {max_workers})...[/cyan]")
    org_report = run_organization_audit(
        role_name=role_name,
        account_ids=account_ids,
        external_id=external_id,
        max_workers=max_workers,
    )

    color = "green" if org_report.scan_status == "COMPLETE" else "yellow"
    console.print(f"[{color}]Scan Status: {org_report.scan_status}[/{color}]")
    console.print(f"Accounts Scanned: {org_report.successful_scans}/{org_report.total_accounts} Successful")
    console.print(f"Total Aggregated Findings: {len(org_report.aggregated_findings)}")

    if output:
        export_json(org_report, output)
        console.print(f"[green]Saved multi-account report to {output}[/green]")


@app.command("access-advisor")
def access_advisor_cmd(
    arn: str = typer.Argument(..., help="IAM User, Role, or Group ARN"),
    threshold_days: int = typer.Option(90, "--threshold-days", help="Inactivity threshold in days"),
    output: Annotated[Path | None, typer.Option("--output", "-o", help="Save report to JSON file")] = None,
) -> None:
    """Query service last accessed details and analyze unused services."""
    console.print(f"[cyan]Analyzing Service Last Accessed for {arn} (Threshold: {threshold_days} days)...[/cyan]")
    report = run_access_advisor_audit(arn=arn, threshold_days=threshold_days)

    console.print(f"[bold]Job Status:[/bold] {report.job_status}")
    console.print(f"[green]Active Services ({len(report.active_services)}):[/green] {', '.join(report.active_services[:10]) or 'None'}")
    console.print(f"[yellow]Inactive Services ({len(report.inactive_services)}):[/yellow] {', '.join(report.inactive_services[:10]) or 'None'}")

    if output:
        export_json(report, output)
        console.print(f"[green]Saved Access Advisor report to {output}[/green]")


@app.command("remediate")
def remediate_cmd(
    rule_id: str = typer.Option("IAM_ACCESS_KEY_OLD", "--rule-id", help="Rule ID to generate script for"),
    resource: str = typer.Option("testuser", "--resource", help="Target resource name"),
    account_id: str = typer.Option("123456789012", "--account-id", help="Target AWS Account ID"),
    output: Annotated[Path | None, typer.Option("--output", "-o", help="Save script to file (.sh)")] = None,
) -> None:
    """Generate safe, dry-run-supported remediation bash script artifact."""
    finding = {
        "id": "finding-1",
        "rule_id": rule_id,
        "resource": resource,
        "resource_type": "IAM User",
    }
    script_res = build_remediation_script(finding=finding, account_id=account_id)

    if output:
        output.write_text(script_res.script_content, encoding="utf-8")
        console.print(f"[green]Remediation script saved to {output}[/green]")
    else:
        console.print("\n[bold cyan]--- Generated Remediation Script ---[/bold cyan]")
        console.print(script_res.script_content)


if __name__ == "__main__":
    app()
