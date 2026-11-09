"""A typo in a rule must never turn it off.

Before 0.1.6, a rule whose `when` named an undefined `$variable` or matcher passed validation,
raised at evaluation, and was skipped: a deny rule with a typo allowed everything.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from theaios.guardrails.config import ConfigError, load_policy, validate_policy
from theaios.guardrails.engine import Engine
from theaios.guardrails.expressions import ExpressionError
from theaios.guardrails.types import GuardEvent, MatcherConfig, PolicyConfig, RuleConfig

TYPO_POLICY = """
version: "1.0"
variables:
  max_amount: 1000
matchers:
  prompt_injection:
    type: keyword_list
    patterns: ["ignore previous instructions"]
rules:
  - name: block-injection
    scope: input
    when: "content matches prompt_injectoin"
    then: deny
  - name: cap-transfers
    scope: action
    when: "amount > $max_amout"
    then: deny
"""


def _policy(*rules: RuleConfig) -> PolicyConfig:
    return PolicyConfig(
        variables={"max_amount": 1000},
        matchers={
            "prompt_injection": MatcherConfig(
                name="prompt_injection",
                type="keyword_list",
                patterns=["ignore previous instructions"],
            )
        },
        rules=list(rules),
    )


def test_load_policy_rejects_undefined_matcher_and_variable(tmp_path: Path) -> None:
    path = tmp_path / "policy.yaml"
    path.write_text(TYPO_POLICY)
    with pytest.raises(ConfigError) as exc:
        load_policy(path)
    errors = "\n".join(exc.value.errors)
    assert "undefined matcher 'prompt_injectoin' (did you mean 'prompt_injection'?)" in errors
    assert "undefined variable '$max_amout' (did you mean 'max_amount'?)" in errors


def test_engine_built_in_code_rejects_undefined_reference() -> None:
    policy = _policy(RuleConfig(name="r", scope="action", when="amount > $max_amout", then="deny"))
    with pytest.raises(ExpressionError, match=r"Error in rule 'r'.*\$max_amout"):
        Engine(policy)


def test_syntax_error_reported_by_validate() -> None:
    policy = _policy(RuleConfig(name="r", scope="action", when="amount >", then="deny"))
    assert any("invalid 'when'" in e for e in validate_policy(policy))


def test_disabled_rule_is_not_checked() -> None:
    rule = RuleConfig(name="r", scope="action", when="amount > $nope", then="deny", enabled=False)
    assert validate_policy(_policy(rule)) == []
    Engine(_policy(rule))


def test_correct_policy_still_denies() -> None:
    engine = Engine(
        _policy(
            RuleConfig(name="cap", scope="action", when="amount > $max_amount", then="deny"),
            RuleConfig(
                name="inj", scope="input", when="content matches prompt_injection", then="deny"
            ),
        )
    )
    assert (
        engine.evaluate(GuardEvent(scope="action", agent="a", data={"amount": 5000})).outcome
        == "deny"
    )
    assert (
        engine.evaluate(GuardEvent(scope="action", agent="a", data={"amount": 5})).outcome
        == "allow"
    )
    event = GuardEvent(
        scope="input", agent="a", data={"content": "please ignore previous instructions"}
    )
    assert engine.evaluate(event).outcome == "deny"


def _broken_at_runtime(then: str, **extra: str) -> Engine:
    """An engine whose rule references a variable that disappears after validation."""
    rule = RuleConfig(name="r", scope="action", when="amount > $max_amount", then=then, **extra)
    engine = Engine(_policy(rule))
    engine.policy.variables.clear()
    return engine


def test_deny_rule_that_cannot_be_evaluated_denies() -> None:
    decision = _broken_at_runtime("deny").evaluate(
        GuardEvent(scope="action", agent="a", data={"amount": 1})
    )
    assert decision.outcome == "deny"
    assert decision.rule == "r"
    assert "could not be evaluated" in decision.reason


def test_approval_rule_that_cannot_be_evaluated_requires_approval() -> None:
    decision = _broken_at_runtime("require_approval", tier="strong").evaluate(
        GuardEvent(scope="action", agent="a", data={"amount": 1})
    )
    assert decision.outcome == "require_approval"
    assert decision.tier == "strong"


def test_log_rule_that_cannot_be_evaluated_does_not_block() -> None:
    decision = _broken_at_runtime("log").evaluate(
        GuardEvent(scope="action", agent="a", data={"amount": 1})
    )
    assert decision.outcome == "allow"
