"""Tests for agent profile resolution."""

from __future__ import annotations

import pytest

from theaios.guardrails.config import ConfigError
from theaios.guardrails.profiles import check_profile_permission, resolve_profile
from theaios.guardrails.types import ProfileConfig


class TestResolveProfile:
    def test_simple_profile(self) -> None:
        profiles = {
            "default": ProfileConfig(name="default", default_tier="autonomous"),
        }
        resolved = resolve_profile("default", profiles)
        assert resolved.name == "default"
        assert resolved.default_tier == "autonomous"
        assert resolved.chain == ["default"]

    def test_inheritance(self) -> None:
        profiles = {
            "default": ProfileConfig(
                name="default", default_tier="autonomous",
                allow=["read"],
            ),
            "sales": ProfileConfig(
                name="sales", extends="default",
                default_tier="autonomous",
                allow=["draft_email"],
                deny=["commit_pricing"],
            ),
        }
        resolved = resolve_profile("sales", profiles)
        assert "read" in resolved.allow
        assert "draft_email" in resolved.allow
        assert "commit_pricing" in resolved.deny
        assert resolved.chain == ["default", "sales"]

    def test_child_deny_overrides_parent_allow(self) -> None:
        profiles = {
            "base": ProfileConfig(name="base", allow=["action_x"]),
            "child": ProfileConfig(
                name="child", extends="base", deny=["action_x"],
            ),
        }
        resolved = resolve_profile("child", profiles)
        assert "action_x" in resolved.deny
        assert "action_x" not in resolved.allow

    def test_circular_inheritance_detected(self) -> None:
        profiles = {
            "a": ProfileConfig(name="a", extends="b"),
            "b": ProfileConfig(name="b", extends="a"),
        }
        with pytest.raises(ConfigError, match="Circular"):
            resolve_profile("a", profiles)

    def test_missing_profile(self) -> None:
        with pytest.raises(ConfigError, match="does not exist"):
            resolve_profile("missing", {})


class TestCheckProfilePermission:
    def test_denied_action(self) -> None:
        profiles = {
            "agent": ProfileConfig(name="agent", deny=["delete"]),
        }
        resolved = resolve_profile("agent", profiles)
        assert check_profile_permission(resolved, "delete") == "deny"

    def test_allowed_action(self) -> None:
        profiles = {
            "agent": ProfileConfig(name="agent", allow=["read"]),
        }
        resolved = resolve_profile("agent", profiles)
        assert check_profile_permission(resolved, "read") == "allow"

    def test_unspecified_action(self) -> None:
        profiles = {
            "agent": ProfileConfig(name="agent", allow=["read"]),
        }
        resolved = resolve_profile("agent", profiles)
        assert check_profile_permission(resolved, "write") is None
