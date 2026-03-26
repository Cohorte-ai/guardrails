"""Tests for data models."""

from __future__ import annotations

from theaios.guardrails.types import (
    Decision,
    GuardEvent,
    Outcome,
    PolicyConfig,
    Scope,
    Severity,
    Tier,
)


class TestGuardEvent:
    def test_minimal_event(self) -> None:
        event = GuardEvent(scope="input", agent="test")
        assert event.scope == "input"
        assert event.agent == "test"
        assert event.data == {}
        assert event.timestamp is None
        assert event.session_id is None

    def test_full_event(self) -> None:
        event = GuardEvent(
            scope="cross_agent",
            agent="finance",
            data={"message": "revenue is $1M"},
            timestamp=1234567890.0,
            session_id="sess-123",
            source_agent="finance-agent",
            target_agent="sales-agent",
        )
        assert event.source_agent == "finance-agent"
        assert event.target_agent == "sales-agent"


class TestDecision:
    def test_allow(self) -> None:
        d = Decision(outcome="allow")
        assert d.is_allowed
        assert not d.is_denied
        assert not d.requires_approval

    def test_deny(self) -> None:
        d = Decision(outcome="deny", rule="test-rule", reason="blocked")
        assert d.is_denied
        assert not d.is_allowed
        assert d.rule == "test-rule"

    def test_require_approval(self) -> None:
        d = Decision(outcome="require_approval", tier="soft")
        assert d.requires_approval
        assert not d.is_denied
        assert d.tier == "soft"

    def test_log_is_allowed(self) -> None:
        d = Decision(outcome="log")
        assert d.is_allowed


class TestEnums:
    def test_outcome_values(self) -> None:
        assert Outcome.ALLOW.value == "allow"
        assert Outcome.DENY.value == "deny"
        assert Outcome.REQUIRE_APPROVAL.value == "require_approval"
        assert Outcome.REDACT.value == "redact"

    def test_scope_values(self) -> None:
        assert Scope.INPUT.value == "input"
        assert Scope.OUTPUT.value == "output"
        assert Scope.ACTION.value == "action"
        assert Scope.CROSS_AGENT.value == "cross_agent"

    def test_tier_values(self) -> None:
        assert Tier.AUTONOMOUS.value == "autonomous"
        assert Tier.SOFT.value == "soft"
        assert Tier.STRONG.value == "strong"

    def test_severity_values(self) -> None:
        assert Severity.CRITICAL.value == "critical"
        assert Severity.HIGH.value == "high"
        assert Severity.MEDIUM.value == "medium"
        assert Severity.LOW.value == "low"


class TestPolicyConfig:
    def test_defaults(self) -> None:
        policy = PolicyConfig()
        assert policy.version == "1.0"
        assert policy.rules == []
        assert policy.profiles == {}
        assert policy.matchers == {}
        assert policy.variables == {}
