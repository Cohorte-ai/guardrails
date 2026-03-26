"""Tests for the matcher registry."""

from __future__ import annotations

import pytest

from theaios.guardrails.matchers import get_matcher, list_matchers
from theaios.guardrails.types import MatcherConfig


class TestMatcherRegistry:
    def test_builtin_matchers_registered(self) -> None:
        names = list_matchers()
        assert "regex" in names
        assert "keyword_list" in names
        assert "pii" in names

    def test_get_matcher(self) -> None:
        config = MatcherConfig(name="test", type="regex", patterns={"p": r"\d+"})
        matcher = get_matcher("regex", config)
        assert matcher.match("abc 123")

    def test_unknown_matcher(self) -> None:
        config = MatcherConfig(name="test", type="nonexistent")
        with pytest.raises(KeyError, match="Unknown matcher type"):
            get_matcher("nonexistent", config)
