"""Keyword list matcher."""

from __future__ import annotations

from theaios.guardrails.matchers import Matcher, register_matcher
from theaios.guardrails.types import MatcherConfig


@register_matcher("keyword_list")
class KeywordMatcher(Matcher):
    """Match text against a list of keyword phrases.

    Performs substring matching — each keyword is checked against the text.
    Supports case-insensitive matching via the ``case_insensitive`` option.
    """

    def __init__(self, config: MatcherConfig) -> None:
        self._case_insensitive = bool(config.options.get("case_insensitive", False))

        keywords: list[str] = []
        if isinstance(config.patterns, list):
            keywords = config.patterns
        elif isinstance(config.patterns, dict):
            keywords = list(config.patterns.values())

        if self._case_insensitive:
            self._keywords = [k.lower() for k in keywords]
        else:
            self._keywords = list(keywords)

    def match(self, text: str, pattern_name: str | None = None) -> bool:
        check_text = text.lower() if self._case_insensitive else text
        return any(keyword in check_text for keyword in self._keywords)

    def redact(self, text: str, pattern_name: str | None = None) -> str:
        result = text
        for keyword in self._keywords:
            if self._case_insensitive:
                # Case-insensitive replacement
                idx = result.lower().find(keyword)
                while idx != -1:
                    result = result[:idx] + "[REDACTED]" + result[idx + len(keyword):]
                    idx = result.lower().find(keyword, idx + len("[REDACTED]"))
            else:
                result = result.replace(keyword, "[REDACTED]")
        return result
