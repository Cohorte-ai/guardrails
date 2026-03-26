"""Agent profile resolution with inheritance."""

from __future__ import annotations

from dataclasses import dataclass, field

from theaios.guardrails.config import ConfigError
from theaios.guardrails.types import ProfileConfig


@dataclass
class ResolvedProfile:
    """A fully resolved agent profile with inherited permissions."""

    name: str
    default_tier: str
    allow: set[str] = field(default_factory=set)
    deny: set[str] = field(default_factory=set)
    chain: list[str] = field(default_factory=list)


def resolve_profile(
    name: str,
    profiles: dict[str, ProfileConfig],
    _seen: set[str] | None = None,
) -> ResolvedProfile:
    """Resolve a profile by following the inheritance chain.

    Child profiles inherit allow/deny from parents. Child values take
    precedence (child deny overrides parent allow for the same action).
    """
    if _seen is None:
        _seen = set()

    if name in _seen:
        raise ConfigError(
            [f"Circular profile inheritance detected: {' -> '.join(_seen)} -> {name}"]
        )

    if name not in profiles:
        raise ConfigError([f"Profile '{name}' does not exist"])

    _seen.add(name)
    profile = profiles[name]

    # Base case: no parent
    if not profile.extends:
        return ResolvedProfile(
            name=name,
            default_tier=profile.default_tier,
            allow=set(profile.allow),
            deny=set(profile.deny),
            chain=[name],
        )

    # Recursive: resolve parent first
    parent = resolve_profile(profile.extends, profiles, _seen)

    # Merge: child overrides parent
    merged_allow = parent.allow | set(profile.allow)
    merged_deny = parent.deny | set(profile.deny)

    # Child deny takes precedence over parent allow
    merged_allow -= merged_deny

    return ResolvedProfile(
        name=name,
        default_tier=profile.default_tier,
        allow=merged_allow,
        deny=merged_deny,
        chain=parent.chain + [name],
    )


def check_profile_permission(
    profile: ResolvedProfile,
    action: str,
) -> str | None:
    """Check whether an action is allowed, denied, or unspecified by a profile.

    Returns "allow", "deny", or None (not explicitly listed).
    """
    if action in profile.deny:
        return "deny"
    if action in profile.allow:
        return "allow"
    return None
