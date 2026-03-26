"""Loader for user-defined custom matchers."""

from __future__ import annotations

import importlib

from theaios.guardrails.matchers import Matcher


def load_custom_matcher(dotted_path: str) -> type[Matcher]:
    """Import a custom Matcher class from a dotted Python path.

    Example: ``"myproject.matchers.ToxicityMatcher"``
    """
    parts = dotted_path.rsplit(".", 1)
    if len(parts) != 2:
        raise ImportError(
            f"Custom matcher path must be 'module.ClassName', got '{dotted_path}'"
        )
    module_path, class_name = parts
    module = importlib.import_module(module_path)
    cls = getattr(module, class_name)
    if not (isinstance(cls, type) and issubclass(cls, Matcher)):
        raise TypeError(
            f"'{dotted_path}' is not a Matcher subclass"
        )
    return cls
