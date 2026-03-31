"""Regex-based matcher."""

from __future__ import annotations

import re

from theaios.guardrails.matchers import Matcher, register_matcher
from theaios.guardrails.types import MatcherConfig


@register_matcher("regex")
class RegexMatcher(Matcher):
    """Match text against compiled regular expressions.

    Patterns can be a dict (named patterns) or a list (unnamed patterns).
    Named patterns support targeted redaction.
    """

    # Maximum input length to prevent ReDoS on complex patterns.
    # Inputs longer than this are truncated before matching.
    _MAX_INPUT_LENGTH = 100_000

    def __init__(self, config: MatcherConfig) -> None:
        self._named: dict[str, re.Pattern[str]] = {}
        self._unnamed: list[re.Pattern[str]] = []

        flags = re.IGNORECASE if config.options.get("case_insensitive") else 0

        if isinstance(config.patterns, dict):
            for name, pattern in config.patterns.items():
                try:
                    self._named[name] = re.compile(pattern, flags)
                except re.error as exc:
                    raise ValueError(f"Invalid regex pattern '{name}': {exc}") from exc
        elif isinstance(config.patterns, list):
            for pattern in config.patterns:
                try:
                    self._unnamed.append(re.compile(pattern, flags))
                except re.error as exc:
                    raise ValueError(f"Invalid regex pattern: {exc}") from exc

    def match(self, text: str, pattern_name: str | None = None) -> bool:
        # Limit input length to prevent ReDoS on complex patterns
        if len(text) > self._MAX_INPUT_LENGTH:
            text = text[: self._MAX_INPUT_LENGTH]

        if pattern_name and pattern_name in self._named:
            return bool(self._named[pattern_name].search(text))

        for compiled in self._named.values():
            if compiled.search(text):
                return True
        for compiled in self._unnamed:
            if compiled.search(text):
                return True
        return False

    def redact(self, text: str, pattern_name: str | None = None) -> str:
        # Limit input length to prevent ReDoS on complex patterns
        if len(text) > self._MAX_INPUT_LENGTH:
            text = text[: self._MAX_INPUT_LENGTH]

        result = text
        if pattern_name and pattern_name in self._named:
            label = f"[{pattern_name.upper()}]"
            result = self._named[pattern_name].sub(label, result)
            return result

        for name, compiled in self._named.items():
            label = f"[{name.upper()}]"
            result = compiled.sub(label, result)
        for compiled in self._unnamed:
            result = compiled.sub("[REDACTED]", result)
        return result
