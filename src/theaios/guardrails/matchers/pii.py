"""Built-in PII detection and redaction matcher."""

from __future__ import annotations

import re

from theaios.guardrails.matchers import Matcher, register_matcher
from theaios.guardrails.types import MatcherConfig

# Built-in PII patterns
_BUILTIN_PII: dict[str, tuple[str, str]] = {
    # name: (regex, redaction_label)
    "ssn": (r"\b\d{3}-\d{2}-\d{4}\b", "[SSN]"),
    "email": (r"\b[\w.-]+@[\w.-]+\.\w+\b", "[EMAIL]"),
    "phone": (r"\b\d{3}[\s.-]\d{3}[\s.-]\d{4}\b", "[PHONE]"),
    "credit_card": (r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b", "[CREDIT_CARD]"),
    "iban": (r"\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}[A-Z0-9]{0,3}\b", "[IBAN]"),
    "ipv4": (r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", "[IP_ADDRESS]"),
}


@register_matcher("pii")
class PIIMatcher(Matcher):
    """Detect and redact personally identifiable information.

    Uses built-in PII patterns and any additional patterns from config.
    Config patterns override built-in patterns with the same name.
    """

    def __init__(self, config: MatcherConfig) -> None:
        self._patterns: dict[str, tuple[re.Pattern[str], str]] = {}

        # Load built-in patterns
        for name, (pattern, label) in _BUILTIN_PII.items():
            self._patterns[name] = (re.compile(pattern), label)

        # Merge config patterns (override built-ins if same name)
        if isinstance(config.patterns, dict):
            for name, pattern in config.patterns.items():
                label = f"[{name.upper()}]"
                self._patterns[name] = (re.compile(str(pattern)), label)

    def match(self, text: str, pattern_name: str | None = None) -> bool:
        if pattern_name and pattern_name in self._patterns:
            compiled, _ = self._patterns[pattern_name]
            return bool(compiled.search(text))

        return any(compiled.search(text) for compiled, _ in self._patterns.values())

    def redact(self, text: str, pattern_name: str | None = None) -> str:
        result = text
        if pattern_name and pattern_name in self._patterns:
            compiled, label = self._patterns[pattern_name]
            result = compiled.sub(label, result)
            return result

        for compiled, label in self._patterns.values():
            result = compiled.sub(label, result)
        return result
