"""TrustGate integration for formal guardrail verification.

Optional dependency — requires ``theaios-trustgate>=0.2``.
Install with: ``pip install theaios-guardrails[trustgate]``
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from theaios.guardrails.config import load_policy
from theaios.guardrails.engine import Engine
from theaios.guardrails.types import GuardEvent


@dataclass
class VerificationResult:
    """Result of verifying guardrails against an attack set."""

    total_tests: int = 0
    passed: int = 0
    failed: int = 0
    catch_rate: float = 0.0
    failures: list[dict[str, object]] = field(default_factory=list)

    @property
    def all_passed(self) -> bool:
        return self.failed == 0


def verify(
    policy_path: str,
    attack_set_path: str,
) -> VerificationResult:
    """Verify guardrails against a set of test cases.

    The attack set is a JSON file with the format::

        [
            {
                "name": "basic-injection",
                "event": {"scope": "input", "agent": "any", "data": {"content": "..."}},
                "expected_outcome": "deny",
                "expected_rule": "block-prompt-injection"
            }
        ]
    """
    policy = load_policy(policy_path)
    engine = Engine(policy)

    attack_set_file = Path(attack_set_path)
    if not attack_set_file.exists():
        raise FileNotFoundError(f"Attack set not found: {attack_set_path}")

    tests = json.loads(attack_set_file.read_text(encoding="utf-8"))
    if not isinstance(tests, list):
        raise ValueError("Attack set must be a JSON array of test cases")

    result = VerificationResult(total_tests=len(tests))

    for test in tests:
        event_raw = test.get("event", {})
        event = GuardEvent(
            scope=str(event_raw.get("scope", "")),
            agent=str(event_raw.get("agent", "")),
            data=event_raw.get("data", {}),
            source_agent=event_raw.get("source_agent"),
            target_agent=event_raw.get("target_agent"),
        )

        decision = engine.evaluate(event)

        expected_outcome = test.get("expected_outcome")
        expected_rule = test.get("expected_rule")

        outcome_match = decision.outcome == expected_outcome
        rule_match = expected_rule is None or decision.rule == expected_rule

        if outcome_match and rule_match:
            result.passed += 1
        else:
            result.failed += 1
            result.failures.append(
                {
                    "test_name": test.get("name", "unnamed"),
                    "expected_outcome": expected_outcome,
                    "actual_outcome": decision.outcome,
                    "expected_rule": expected_rule,
                    "actual_rule": decision.rule,
                }
            )

    if result.total_tests > 0:
        result.catch_rate = result.passed / result.total_tests

    return result
