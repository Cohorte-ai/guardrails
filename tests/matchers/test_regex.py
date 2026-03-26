"""Tests for regex matcher."""

from __future__ import annotations

from theaios.guardrails.matchers.regex import RegexMatcher
from theaios.guardrails.types import MatcherConfig


class TestRegexMatcher:
    def test_named_patterns_match(self) -> None:
        config = MatcherConfig(
            name="test",
            type="regex",
            patterns={"ssn": r"\b\d{3}-\d{2}-\d{4}\b"},
        )
        m = RegexMatcher(config)
        assert m.match("SSN is 123-45-6789")
        assert not m.match("no PII here")

    def test_unnamed_patterns_match(self) -> None:
        config = MatcherConfig(
            name="test",
            type="regex",
            patterns=[r"\d{3}-\d{2}-\d{4}", r"\b\w+@\w+\.\w+\b"],
        )
        m = RegexMatcher(config)
        assert m.match("SSN: 123-45-6789")
        assert m.match("email: test@example.com")
        assert not m.match("clean text")

    def test_case_insensitive(self) -> None:
        config = MatcherConfig(
            name="test",
            type="regex",
            patterns=[r"secret"],
            options={"case_insensitive": True},
        )
        m = RegexMatcher(config)
        assert m.match("SECRET info")

    def test_redact_named(self) -> None:
        config = MatcherConfig(
            name="test",
            type="regex",
            patterns={"ssn": r"\b\d{3}-\d{2}-\d{4}\b"},
        )
        m = RegexMatcher(config)
        result = m.redact("SSN is 123-45-6789")
        assert "[SSN]" in result
        assert "123-45-6789" not in result

    def test_redact_unnamed(self) -> None:
        config = MatcherConfig(
            name="test",
            type="regex",
            patterns=[r"\d{3}-\d{2}-\d{4}"],
        )
        m = RegexMatcher(config)
        result = m.redact("SSN is 123-45-6789")
        assert "[REDACTED]" in result

    def test_specific_pattern_match(self) -> None:
        config = MatcherConfig(
            name="test",
            type="regex",
            patterns={
                "ssn": r"\b\d{3}-\d{2}-\d{4}\b",
                "email": r"\b\w+@\w+\.\w+\b",
            },
        )
        m = RegexMatcher(config)
        assert m.match("test@example.com", pattern_name="email")
        assert not m.match("test@example.com", pattern_name="ssn")
