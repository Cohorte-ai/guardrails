"""Matcher base class, registry, and built-in matchers."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from theaios.guardrails.types import MatcherConfig


# ---------------------------------------------------------------------------
# Base class
# ---------------------------------------------------------------------------


class Matcher(ABC):
    """Base class for all matchers.

    A matcher checks whether text matches a set of patterns and can
    optionally redact matched content.
    """

    @abstractmethod
    def match(self, text: str, pattern_name: str | None = None) -> bool:
        """Return True if text matches any configured pattern.

        Parameters
        ----------
        text : str
            The text to check.
        pattern_name : str, optional
            If provided, only check this specific named pattern.
        """

    def redact(self, text: str, pattern_name: str | None = None) -> str:
        """Replace matched content with redaction placeholders.

        Default implementation returns text unchanged. Override in
        matchers that support redaction (e.g., PII, regex).
        """
        return text


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

_REGISTRY: dict[str, type[Matcher]] = {}


def register_matcher(name: str) -> Any:  # noqa: ANN401
    """Decorator to register a matcher class by name.

    Usage::

        @register_matcher("regex")
        class RegexMatcher(Matcher):
            ...
    """

    def decorator(cls: type[Matcher]) -> type[Matcher]:
        _REGISTRY[name] = cls
        return cls

    return decorator


def get_matcher(name: str, config: MatcherConfig) -> Matcher:
    """Instantiate a registered matcher by name with its config."""
    if name not in _REGISTRY:
        available = sorted(_REGISTRY.keys())
        raise KeyError(
            f"Unknown matcher type '{name}'. Available: {available}"
        )
    return _REGISTRY[name](config)  # type: ignore[call-arg]


def list_matchers() -> list[str]:
    """Return all registered matcher type names."""
    return sorted(_REGISTRY.keys())


# ---------------------------------------------------------------------------
# Eagerly import built-in matcher modules so decorators run.
# ---------------------------------------------------------------------------
import theaios.guardrails.matchers.keyword as _keyword  # noqa: E402, F401
import theaios.guardrails.matchers.pii as _pii  # noqa: E402, F401
import theaios.guardrails.matchers.regex as _regex  # noqa: E402, F401
