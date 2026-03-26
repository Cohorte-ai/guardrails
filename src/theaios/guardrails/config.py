"""YAML policy loader and validation."""

from __future__ import annotations

from pathlib import Path

import yaml

from theaios.guardrails.types import (
    VALID_OUTCOMES,
    VALID_SCOPES,
    VALID_SEVERITIES,
    VALID_TIERS,
    MatcherConfig,
    PolicyConfig,
    PolicyMetadata,
    ProfileConfig,
    RateLimitConfig,
    RuleConfig,
)


class ConfigError(Exception):
    """Raised when a policy file is invalid."""

    def __init__(self, errors: list[str]) -> None:
        self.errors = errors
        super().__init__("Invalid policy:\n  " + "\n  ".join(errors))


def load_policy(path: str = "guardrails.yaml") -> PolicyConfig:
    """Load a YAML policy file, validate, and return typed config."""
    config_path = Path(path)
    if not config_path.exists():
        raise FileNotFoundError(f"Policy file not found: {path}")

    with open(config_path) as f:
        raw = yaml.safe_load(f)

    if not isinstance(raw, dict):
        raise ConfigError(["Policy file must be a YAML mapping"])

    config = _parse_policy(raw)

    errors = validate_policy(config)
    if errors:
        raise ConfigError(errors)

    return config


def _parse_policy(raw: dict[str, object]) -> PolicyConfig:
    """Parse raw YAML dict into typed PolicyConfig."""

    # Version
    version = str(raw.get("version", "1.0"))

    # Metadata
    meta_raw = raw.get("metadata", {})
    if not isinstance(meta_raw, dict):
        meta_raw = {}
    metadata = PolicyMetadata(
        name=str(meta_raw.get("name", "")),
        description=str(meta_raw.get("description", "")),
        author=str(meta_raw.get("author", "")),
    )

    # Variables
    variables_raw = raw.get("variables", {})
    variables: dict[str, object] = dict(variables_raw) if isinstance(variables_raw, dict) else {}

    # Profiles
    profiles: dict[str, ProfileConfig] = {}
    profiles_raw = raw.get("profiles", {})
    if isinstance(profiles_raw, dict):
        for name, praw in profiles_raw.items():
            if not isinstance(praw, dict):
                praw = {}
            profiles[str(name)] = ProfileConfig(
                name=str(name),
                extends=str(praw.get("extends", "")),
                default_tier=str(praw.get("default_tier", "autonomous")),
                allow=[str(a) for a in praw.get("allow", [])],
                deny=[str(d) for d in praw.get("deny", [])],
            )

    # Rules
    rules: list[RuleConfig] = []
    rules_raw = raw.get("rules", [])
    if isinstance(rules_raw, list):
        for rraw in rules_raw:
            if not isinstance(rraw, dict):
                continue
            rate_limit = None
            rl_raw = rraw.get("rate_limit")
            if isinstance(rl_raw, dict):
                rate_limit = RateLimitConfig(
                    max=int(rl_raw.get("max", 100)),
                    window=int(rl_raw.get("window", 60)),
                    key=str(rl_raw.get("key", "agent")),
                )
            tags_raw = rraw.get("tags", [])
            tags = [str(t) for t in tags_raw] if isinstance(tags_raw, list) else []
            patterns_raw = rraw.get("patterns", [])
            patterns = [str(p) for p in patterns_raw] if isinstance(patterns_raw, list) else []
            rules.append(
                RuleConfig(
                    name=str(rraw.get("name", "")),
                    scope=str(rraw.get("scope", "")),
                    then=str(rraw.get("then", "")),
                    description=str(rraw.get("description", "")),
                    when=str(rraw.get("when", "")),
                    reason=str(rraw.get("reason", "")),
                    severity=str(rraw.get("severity", "medium")),
                    tier=str(rraw.get("tier", "")),
                    enabled=bool(rraw.get("enabled", True)),
                    tags=tags,
                    patterns=patterns,
                    rate_limit=rate_limit,
                    from_agent=str(rraw.get("from", "")),
                    to_agent=str(rraw.get("to", "")),
                )
            )

    # Matchers
    matchers: dict[str, MatcherConfig] = {}
    matchers_raw = raw.get("matchers", {})
    if isinstance(matchers_raw, dict):
        for mname, mraw in matchers_raw.items():
            if not isinstance(mraw, dict):
                continue
            patterns_val = mraw.get("patterns", [])
            if isinstance(patterns_val, dict):
                patterns_parsed: dict[str, str] | list[str] = {
                    str(k): str(v) for k, v in patterns_val.items()
                }
            elif isinstance(patterns_val, list):
                patterns_parsed = [str(p) for p in patterns_val]
            else:
                patterns_parsed = []
            options_raw = mraw.get("options", {})
            options = dict(options_raw) if isinstance(options_raw, dict) else {}
            matchers[str(mname)] = MatcherConfig(
                name=str(mname),
                type=str(mraw.get("type", "")),
                patterns=patterns_parsed,
                options=options,
            )

    return PolicyConfig(
        version=version,
        metadata=metadata,
        variables=variables,
        profiles=profiles,
        rules=rules,
        matchers=matchers,
    )


def validate_policy(config: PolicyConfig) -> list[str]:
    """Return list of validation errors (empty = valid)."""
    errors: list[str] = []

    # Version
    if config.version not in ("1.0",):
        errors.append(f"Unsupported policy version: '{config.version}' (expected '1.0')")

    # Rules
    seen_names: set[str] = set()
    for i, rule in enumerate(config.rules):
        prefix = f"rules[{i}]"

        if not rule.name:
            errors.append(f"{prefix}: 'name' is required")
        elif rule.name in seen_names:
            errors.append(f"{prefix}: duplicate rule name '{rule.name}'")
        else:
            seen_names.add(rule.name)

        if not rule.scope:
            errors.append(f"{prefix} ({rule.name}): 'scope' is required")
        elif rule.scope not in VALID_SCOPES:
            errors.append(
                f"{prefix} ({rule.name}): invalid scope '{rule.scope}', "
                f"expected one of {sorted(VALID_SCOPES)}"
            )

        if not rule.then:
            errors.append(f"{prefix} ({rule.name}): 'then' is required")
        elif rule.then not in VALID_OUTCOMES:
            errors.append(
                f"{prefix} ({rule.name}): invalid outcome '{rule.then}', "
                f"expected one of {sorted(VALID_OUTCOMES)}"
            )

        if rule.severity and rule.severity not in VALID_SEVERITIES:
            errors.append(
                f"{prefix} ({rule.name}): invalid severity '{rule.severity}', "
                f"expected one of {sorted(VALID_SEVERITIES)}"
            )

        if rule.then == "require_approval" and rule.tier and rule.tier not in VALID_TIERS:
            errors.append(
                f"{prefix} ({rule.name}): invalid tier '{rule.tier}', "
                f"expected one of {sorted(VALID_TIERS)}"
            )

        if rule.scope == "cross_agent" and not rule.from_agent:
            errors.append(f"{prefix} ({rule.name}): cross_agent rules require 'from'")

        if rule.rate_limit is not None:
            if rule.rate_limit.max < 1:
                errors.append(f"{prefix} ({rule.name}): rate_limit.max must be >= 1")
            if rule.rate_limit.window < 1:
                errors.append(f"{prefix} ({rule.name}): rate_limit.window must be >= 1")

        # Check matcher references in when clause
        if rule.when:
            for matcher_name in config.matchers:
                pass  # existence check is done at engine init time with compiled expressions

    # Profiles
    for name, profile in config.profiles.items():
        if profile.extends and profile.extends not in config.profiles:
            errors.append(f"profiles.{name}: extends '{profile.extends}' does not exist")
        if profile.default_tier not in VALID_TIERS:
            errors.append(
                f"profiles.{name}: invalid default_tier '{profile.default_tier}', "
                f"expected one of {sorted(VALID_TIERS)}"
            )

    # Matchers
    valid_matcher_types = {"regex", "keyword_list", "pii", "custom"}
    for name, matcher in config.matchers.items():
        if not matcher.type:
            errors.append(f"matchers.{name}: 'type' is required")
        elif matcher.type not in valid_matcher_types:
            errors.append(
                f"matchers.{name}: invalid type '{matcher.type}', "
                f"expected one of {sorted(valid_matcher_types)}"
            )

    return errors
