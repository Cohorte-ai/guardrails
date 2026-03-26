"""Tests for PII matcher."""

from __future__ import annotations

from theaios.guardrails.matchers.pii import PIIMatcher
from theaios.guardrails.types import MatcherConfig


class TestPIIMatcher:
    def test_detect_ssn(self) -> None:
        m = PIIMatcher(MatcherConfig(name="pii", type="pii", patterns={}))
        assert m.match("SSN: 123-45-6789")
        assert not m.match("Phone: 555-1234")

    def test_detect_email(self) -> None:
        m = PIIMatcher(MatcherConfig(name="pii", type="pii", patterns={}))
        assert m.match("Contact: user@example.com")

    def test_detect_phone(self) -> None:
        m = PIIMatcher(MatcherConfig(name="pii", type="pii", patterns={}))
        assert m.match("Call 555-123-4567")

    def test_detect_credit_card(self) -> None:
        m = PIIMatcher(MatcherConfig(name="pii", type="pii", patterns={}))
        assert m.match("Card: 4111-1111-1111-1111")

    def test_no_pii(self) -> None:
        m = PIIMatcher(MatcherConfig(name="pii", type="pii", patterns={}))
        assert not m.match("The weather is nice today")

    def test_redact_ssn(self) -> None:
        m = PIIMatcher(MatcherConfig(name="pii", type="pii", patterns={}))
        result = m.redact("SSN: 123-45-6789")
        assert "[SSN]" in result
        assert "123-45-6789" not in result

    def test_redact_email(self) -> None:
        m = PIIMatcher(MatcherConfig(name="pii", type="pii", patterns={}))
        result = m.redact("Email: user@example.com")
        assert "[EMAIL]" in result
        assert "user@example.com" not in result

    def test_specific_pattern_check(self) -> None:
        m = PIIMatcher(MatcherConfig(name="pii", type="pii", patterns={}))
        assert m.match("123-45-6789", pattern_name="ssn")
        assert not m.match("123-45-6789", pattern_name="email")

    def test_custom_patterns_override(self) -> None:
        config = MatcherConfig(
            name="pii",
            type="pii",
            patterns={"custom_id": r"ID-\d{6}"},
        )
        m = PIIMatcher(config)
        assert m.match("Employee ID-123456")
        result = m.redact("Employee ID-123456")
        assert "[CUSTOM_ID]" in result

    def test_redact_specific_pattern(self) -> None:
        m = PIIMatcher(MatcherConfig(name="pii", type="pii", patterns={}))
        text = "SSN: 123-45-6789, Email: user@example.com"
        result = m.redact(text, pattern_name="ssn")
        assert "[SSN]" in result
        assert "user@example.com" in result  # Email not redacted
