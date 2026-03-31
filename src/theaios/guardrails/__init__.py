"""theaios-guardrails — Declarative guardrails for AI agents."""

__version__ = "0.1.2"

from theaios.guardrails.adapters.decorator import ApprovalRequired, GuardDenied, guard
from theaios.guardrails.config import ConfigError, load_policy
from theaios.guardrails.engine import Engine
from theaios.guardrails.matchers import Matcher, get_matcher, list_matchers, register_matcher
from theaios.guardrails.types import (
    Decision,
    GuardEvent,
    MatcherConfig,
    Outcome,
    PolicyConfig,
    ProfileConfig,
    RuleConfig,
    Scope,
    Severity,
    Tier,
)


def evaluate(policy: PolicyConfig, event: GuardEvent, *, dry_run: bool = False) -> Decision:
    """Evaluate an event against a policy. Convenience function."""
    engine = Engine(policy, dry_run=dry_run)
    return engine.evaluate(event)


def check(
    policy_path: str = "guardrails.yaml",
    *,
    scope: str = "input",
    agent: str = "default",
    dry_run: bool = False,
    **data: object,
) -> Decision:
    """One-liner: load policy, build event from kwargs, evaluate."""
    policy = load_policy(policy_path)
    event = GuardEvent(scope=scope, agent=agent, data=dict(data))
    return evaluate(policy, event, dry_run=dry_run)


__all__ = [
    # Core
    "Engine",
    "load_policy",
    "evaluate",
    "check",
    "ConfigError",
    # Decorator & exceptions
    "guard",
    "GuardDenied",
    "ApprovalRequired",
    # Types
    "Decision",
    "GuardEvent",
    "PolicyConfig",
    "RuleConfig",
    "ProfileConfig",
    "MatcherConfig",
    "Outcome",
    "Scope",
    "Severity",
    "Tier",
    # Matchers
    "Matcher",
    "register_matcher",
    "get_matcher",
    "list_matchers",
]
