"""Typer-based modern CLI for IAM Access Auditor."""

from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from iam_audit.core.engine import (
    check_permission,
    compare_two_users,
    get_user_analysis,
    list_inventory,
    run_full_audit,
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

    if fmt == "json":
        assert output is not None
        export_json(report, output)
        console.print(f"[green]Report exported to {output}[/green]")
    elif fmt == "csv":
        assert output is not None
        export_csv(report, output)
        console.print(f"[green]Report exported to {output}[/green]")
    elif fmt == "sarif":
        assert output is not None
        export_sarif(report, output)
        console.print(f"[green]Report exported to {output}[/green]")
    else:
        console.print(export_console_summary(report))


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


if __name__ == "__main__":
    app()