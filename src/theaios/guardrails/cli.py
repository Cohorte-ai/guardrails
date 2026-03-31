"""Click-based CLI: guardrails validate, check, inspect, audit, version."""

from __future__ import annotations

import json
import sys

import click

from theaios import guardrails
from theaios.guardrails.audit import AuditLog
from theaios.guardrails.config import ConfigError, load_policy
from theaios.guardrails.engine import Engine
from theaios.guardrails.reporting import (
    export_audit_json,
    print_audit_summary,
    print_evaluation_result,
    print_policy_summary,
)
from theaios.guardrails.types import GuardEvent


@click.group()
def main() -> None:
    """theaios-guardrails — Declarative guardrails for AI agents."""


# ---------------------------------------------------------------------------
# guardrails version
# ---------------------------------------------------------------------------


@main.command()
def version() -> None:
    """Show version."""
    click.echo(f"guardrails {guardrails.__version__}")


# ---------------------------------------------------------------------------
# guardrails validate
# ---------------------------------------------------------------------------


@main.command()
@click.option("--config", "-c", "config_path", default="guardrails.yaml", help="Policy file path")
def validate(config_path: str) -> None:
    """Validate a policy file for errors."""
    try:
        policy = load_policy(config_path)
    except FileNotFoundError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)
    except ConfigError as e:
        click.echo("Validation failed:", err=True)
        for error in e.errors:
            click.echo(f"  - {error}", err=True)
        sys.exit(1)

    n_rules = len(policy.rules)
    n_profiles = len(policy.profiles)
    n_matchers = len(policy.matchers)
    click.echo(f"Policy is valid: {n_rules} rules, {n_profiles} profiles, {n_matchers} matchers")


# ---------------------------------------------------------------------------
# guardrails inspect
# ---------------------------------------------------------------------------


@main.command()
@click.option("--config", "-c", "config_path", default="guardrails.yaml", help="Policy file path")
@click.option("--tag", help="Filter rules by tag")
def inspect(config_path: str, tag: str | None) -> None:
    """Display policy rules, profiles, and matchers."""
    try:
        policy = load_policy(config_path)
    except (FileNotFoundError, ConfigError) as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)

    if tag:
        policy.rules = [r for r in policy.rules if tag in r.tags]

    print_policy_summary(policy)


# ---------------------------------------------------------------------------
# guardrails check
# ---------------------------------------------------------------------------


@main.command()
@click.option("--config", "-c", "config_path", default="guardrails.yaml", help="Policy file path")
@click.option("--event", "-e", "event_json", default=None, help="Event as JSON string")
@click.option(
    "--event-file",
    "-f",
    "event_file",
    default=None,
    type=click.Path(exists=True),
    help="Path to JSON file containing the event",
)
@click.option("--dry-run", is_flag=True, help="Evaluate without enforcement")
@click.option("--output", "-o", type=click.Choice(["console", "json"]), default="console")
def check(
    config_path: str, event_json: str | None, event_file: str | None, dry_run: bool, output: str
) -> None:
    """Evaluate a single event against the policy."""
    if not event_json and not event_file:
        click.echo("Error: either --event or --event-file is required", err=True)
        sys.exit(1)

    try:
        policy = load_policy(config_path)
    except (FileNotFoundError, ConfigError) as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)

    try:
        if event_file:
            with open(event_file) as f:
                raw = json.load(f)
        else:
            raw = json.loads(event_json)  # type: ignore[arg-type]
    except json.JSONDecodeError as e:
        click.echo(f"Invalid JSON: {e}", err=True)
        sys.exit(1)

    event = GuardEvent(
        scope=str(raw.get("scope", "")),
        agent=str(raw.get("agent", "")),
        data=raw.get("data", {}),
        session_id=raw.get("session_id"),
        source_agent=raw.get("source_agent"),
        target_agent=raw.get("target_agent"),
    )

    engine = Engine(policy, dry_run=dry_run)
    decision = engine.evaluate(event)

    if output == "json":
        result: dict[str, object] = {
            "outcome": decision.outcome,
            "rule": decision.rule,
            "reason": decision.reason,
            "tier": decision.tier,
            "severity": decision.severity,
            "dry_run": decision.dry_run,
            "evaluation_time_ms": round(decision.evaluation_time_ms, 3),
            "matched_rules": decision.matched_rules,
        }
        if decision.modifications:
            result["modifications"] = dict(decision.modifications)
        click.echo(json.dumps(result, indent=2))
    else:
        print_evaluation_result(decision)

    if decision.is_denied and not decision.dry_run:
        sys.exit(1)


# ---------------------------------------------------------------------------
# guardrails audit
# ---------------------------------------------------------------------------


@main.command()
@click.option("--config", "-c", "config_path", default="guardrails.yaml", help="Policy file path")
@click.option("--since", help="Show entries since this ISO timestamp")
@click.option("--agent", help="Filter by agent name")
@click.option("--outcome", help="Filter by outcome (allow, deny, require_approval, redact)")
@click.option("--rule", help="Filter by rule name")
@click.option("--limit", type=int, default=1000, help="Maximum entries to show")
@click.option("--output", "-o", type=click.Choice(["console", "json"]), default="console")
@click.option("--output-file", help="Write JSON output to file")
def audit(
    config_path: str,
    since: str | None,
    agent: str | None,
    outcome: str | None,
    rule: str | None,
    limit: int,
    output: str,
    output_file: str | None,
) -> None:
    """View the audit log."""
    log = AuditLog()
    entries = log.read(since=since, agent=agent, outcome=outcome, rule=rule, limit=limit)

    if output == "json" or output_file:
        if output_file:
            export_audit_json(entries, output_file)
            click.echo(f"Exported {len(entries)} entries to {output_file}")
        else:
            click.echo(json.dumps(entries, indent=2, default=str))
    else:
        print_audit_summary(entries)
