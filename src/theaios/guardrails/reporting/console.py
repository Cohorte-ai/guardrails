"""Rich terminal output for policy inspection and evaluation results."""

from __future__ import annotations

from rich.console import Console
from rich.table import Table

from theaios.guardrails.types import Decision, PolicyConfig

console = Console()


def print_policy_summary(policy: PolicyConfig) -> None:
    """Print a formatted summary of a policy."""
    if policy.metadata.name:
        console.print(f"\n[bold]{policy.metadata.name}[/bold]")
    if policy.metadata.description:
        console.print(f"  {policy.metadata.description}")
    console.print(f"  Version: {policy.version}")
    if policy.metadata.author:
        console.print(f"  Author: {policy.metadata.author}")

    # Profiles
    if policy.profiles:
        console.print(f"\n[bold]Profiles[/bold] ({len(policy.profiles)})")
        table = Table(show_header=True, header_style="bold")
        table.add_column("Name")
        table.add_column("Extends")
        table.add_column("Default Tier")
        table.add_column("Allow")
        table.add_column("Deny")
        for name, profile in policy.profiles.items():
            table.add_row(
                name,
                profile.extends or "-",
                profile.default_tier,
                ", ".join(profile.allow) or "-",
                ", ".join(profile.deny) or "-",
            )
        console.print(table)

    # Rules
    if policy.rules:
        console.print(f"\n[bold]Rules[/bold] ({len(policy.rules)})")
        table = Table(show_header=True, header_style="bold")
        table.add_column("Name")
        table.add_column("Scope")
        table.add_column("Then")
        table.add_column("Severity")
        table.add_column("Enabled")
        table.add_column("Tags")
        for rule in policy.rules:
            severity_color = {
                "critical": "red",
                "high": "yellow",
                "medium": "cyan",
                "low": "dim",
            }.get(rule.severity, "white")
            table.add_row(
                rule.name,
                rule.scope,
                rule.then,
                f"[{severity_color}]{rule.severity}[/{severity_color}]",
                "[green]yes[/green]" if rule.enabled else "[red]no[/red]",
                ", ".join(rule.tags) or "-",
            )
        console.print(table)

    # Matchers
    if policy.matchers:
        console.print(f"\n[bold]Matchers[/bold] ({len(policy.matchers)})")
        table = Table(show_header=True, header_style="bold")
        table.add_column("Name")
        table.add_column("Type")
        table.add_column("Patterns")
        for name, matcher in policy.matchers.items():
            if isinstance(matcher.patterns, dict):
                count = str(len(matcher.patterns))
            elif isinstance(matcher.patterns, list):
                count = str(len(matcher.patterns))
            else:
                count = "0"
            table.add_row(name, matcher.type, f"{count} patterns")
        console.print(table)

    console.print()


def print_evaluation_result(decision: Decision) -> None:
    """Print a formatted evaluation result."""
    outcome_color = {
        "allow": "green",
        "deny": "red",
        "require_approval": "yellow",
        "redact": "cyan",
        "log": "dim",
    }.get(decision.outcome, "white")

    console.print(
        f"\n[bold {outcome_color}]{decision.outcome.upper()}[/bold {outcome_color}]",
        end="",
    )
    if decision.rule:
        console.print(f"  (rule: {decision.rule})", end="")
    if decision.dry_run:
        console.print("  [dim][DRY RUN][/dim]", end="")
    console.print()

    if decision.reason:
        console.print(f"  Reason: {decision.reason}")
    if decision.tier:
        console.print(f"  Tier: {decision.tier}")
    if decision.severity:
        console.print(f"  Severity: {decision.severity}")
    if decision.evaluation_time_ms > 0:
        console.print(f"  Evaluated in: {decision.evaluation_time_ms:.2f}ms")
    console.print()


def print_audit_summary(entries: list[dict[str, object]]) -> None:
    """Print a summary of audit log entries."""
    if not entries:
        console.print("[dim]No audit entries found.[/dim]")
        return

    console.print(f"\n[bold]Audit Log[/bold] ({len(entries)} entries)\n")

    table = Table(show_header=True, header_style="bold")
    table.add_column("Timestamp")
    table.add_column("Agent")
    table.add_column("Scope")
    table.add_column("Outcome")
    table.add_column("Rule")
    table.add_column("Severity")

    for entry in entries[-50:]:  # Show last 50
        outcome = str(entry.get("outcome", ""))
        outcome_color = {
            "allow": "green",
            "deny": "red",
            "require_approval": "yellow",
            "redact": "cyan",
        }.get(outcome, "white")

        ts = str(entry.get("timestamp", ""))
        # Truncate to seconds
        if "." in ts:
            ts = ts.split(".")[0]

        table.add_row(
            ts,
            str(entry.get("agent", "")),
            str(entry.get("scope", "")),
            f"[{outcome_color}]{outcome}[/{outcome_color}]",
            str(entry.get("rule", "-")),
            str(entry.get("severity", "-")),
        )
    console.print(table)
    console.print()
