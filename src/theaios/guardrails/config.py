"""YAML policy loader and validation."""

from __future__ import annotations

import difflib
from collections.abc import Iterable
from pathlib import Path

import yaml
from theaios.core.expressions import ExpressionError, compile_expression, references

from theaios.guardrails.matchers import get_matcher, list_matchers
from theaios.guardrails.matchers.pii import BUILTIN_PII_NAMES
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

    if not config_path.is_file():
        raise ConfigError([f"{path} is not a file"])
    try:
        with open(config_path, encoding="utf-8") as f:
            raw = yaml.safe_load(f)
    except yaml.YAMLError as exc:
        mark = getattr(exc, "problem_mark", None)
        where = f"{path}:{mark.line + 1}" if mark is not None else path
        problem = getattr(exc, "problem", None) or str(exc)
        raise ConfigError([f"{where}: YAML syntax error: {problem}"]) from None
    except UnicodeDecodeError:
        raise ConfigError([f"{path} is not UTF-8 text"]) from None

    if not isinstance(raw, dict):
        raise ConfigError(["Policy file must be a YAML mapping"])

    errors = shape_errors(raw)
    if errors:
        raise ConfigError(errors)

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


_TOP_KEYS = {"version", "metadata", "variables", "profiles", "rules", "matchers"}
_RULE_KEYS = {
    "name",
    "scope",
    "then",
    "description",
    "when",
    "reason",
    "severity",
    "tier",
    "enabled",
    "tags",
    "patterns",
    "rate_limit",
    "from",
    "to",
}
_PROFILE_KEYS = {"extends", "default_tier", "allow", "deny"}
_MATCHER_KEYS = {"type", "patterns", "options"}
_RATE_LIMIT_KEYS = {"max", "window", "key"}
# Options the built-in matcher types read; custom matcher types may read any option.
_BUILTIN_OPTIONS = {
    "regex": {"case_insensitive"},
    "keyword_list": {"case_insensitive"},
    "pii": set(),
}


def _unknown_keys(where: str, raw: dict[object, object], allowed: set[str]) -> list[str]:
    return [
        f"{where}: unknown key '{key}'{_did_you_mean(str(key), allowed)}"
        for key in raw
        if key not in allowed
    ]


def shape_errors(raw: dict[object, object]) -> list[str]:
    """Structural problems in a raw policy mapping that parsing would otherwise hide: unknown
    keys (a typo such as ``rule:`` or ``enabeld:``), a section of the wrong type (a mapping
    where a list is expected), conditions that are not strings, flags that are not booleans.
    Each of these used to load silently and change what the policy does."""
    errors = _unknown_keys("policy", raw, _TOP_KEYS)
    for key in ("metadata", "variables", "profiles", "matchers"):
        if key in raw and raw[key] is not None and not isinstance(raw[key], dict):
            errors.append(f"'{key}' must be a mapping, got {type(raw[key]).__name__}")
    rules = raw.get("rules")
    if rules is not None and not isinstance(rules, list):
        errors.append(
            f"'rules' must be a list of rules (each starting with '-'), got {type(rules).__name__}"
        )
        rules = []
    for i, rule in enumerate(rules or []):
        where = f"rules[{i}]"
        if not isinstance(rule, dict):
            errors.append(f"{where}: must be a mapping, got {type(rule).__name__}")
            continue
        if "name" in rule:
            where = f"rules[{i}] ({rule['name']})"
            if not isinstance(rule["name"], str):
                errors.append(f"{where}: 'name' must be a string (quote it)")
        errors += _unknown_keys(where, rule, _RULE_KEYS)
        for key in (
            "name",
            "scope",
            "then",
            "when",
            "reason",
            "description",
            "severity",
            "tier",
            "from",
            "to",
        ):
            if key in rule and key != "name" and not isinstance(rule[key], str):
                errors.append(f"{where}: '{key}' must be a string, got {type(rule[key]).__name__}")
        if "enabled" in rule and not isinstance(rule["enabled"], bool):
            errors.append(f"{where}: 'enabled' must be true or false (unquoted)")
        for key in ("patterns", "tags"):
            if key in rule and not (
                isinstance(rule[key], list) and all(isinstance(x, str) for x in rule[key])
            ):
                errors.append(f"{where}: '{key}' must be a list of strings")
        rate = rule.get("rate_limit")
        if rate is not None:
            if not isinstance(rate, dict):
                errors.append(f"{where}: 'rate_limit' must be a mapping")
            else:
                errors += _unknown_keys(f"{where}.rate_limit", rate, _RATE_LIMIT_KEYS)
                for key in ("max", "window"):
                    if key in rate and (
                        isinstance(rate[key], bool) or not isinstance(rate[key], int)
                    ):
                        errors.append(f"{where}.rate_limit: '{key}' must be an integer")
    profiles = raw.get("profiles")
    for name, profile in profiles.items() if isinstance(profiles, dict) else []:
        if not isinstance(profile, dict):
            errors.append(f"profiles.{name}: must be a mapping")
            continue
        errors += _unknown_keys(f"profiles.{name}", profile, _PROFILE_KEYS)
        for key in ("allow", "deny"):
            if key in profile and not (
                isinstance(profile[key], list) and all(isinstance(x, str) for x in profile[key])
            ):
                errors.append(f"profiles.{name}: '{key}' must be a list of action names")
    matchers = raw.get("matchers")
    for name, matcher in matchers.items() if isinstance(matchers, dict) else []:
        if not isinstance(matcher, dict):
            errors.append(f"matchers.{name}: must be a mapping")
            continue
        errors += _unknown_keys(f"matchers.{name}", matcher, _MATCHER_KEYS)
        patterns = matcher.get("patterns")
        if patterns is not None and not (
            (isinstance(patterns, list) and all(isinstance(x, str) for x in patterns))
            or (isinstance(patterns, dict) and all(isinstance(x, str) for x in patterns.values()))
        ):
            errors.append(
                f"matchers.{name}: 'patterns' must be a list of strings or a mapping of "
                "name: pattern"
            )
        options = matcher.get("options")
        if options is not None:
            if not isinstance(options, dict):
                errors.append(f"matchers.{name}: 'options' must be a mapping")
            elif matcher.get("type") in _BUILTIN_OPTIONS:
                errors += _unknown_keys(
                    f"matchers.{name}.options", options, _BUILTIN_OPTIONS[str(matcher["type"])]
                )
    return errors


# Keys from a neighbouring library or a common guess, mapped to the right key here. Checked
# before fuzzy matching, which can suggest something harmful (`condition` -> `description`
# would leave a rule with no condition, matching everything).
_ALIASES = {
    "condition": "when",
    "if": "when",
    "outcome": "then",
    "from_agent": "from",
    "to_agent": "to",
    "pattern": "patterns",
}


def _did_you_mean(name: str, known: Iterable[str]) -> str:
    options = list(known)
    if _ALIASES.get(name) in options:
        return f" (did you mean '{_ALIASES[name]}'?)"
    close = difflib.get_close_matches(name, options, n=1)
    return f" (did you mean '{close[0]}'?)" if close else ""


def _redact_pattern_names(config: PolicyConfig) -> set[str] | None:
    """Names a redact rule may list: matcher names and the named patterns inside built-in
    matchers. None when a custom matcher type is used, since its pattern names are unknown."""
    names = set(config.matchers)
    for matcher in config.matchers.values():
        if matcher.type not in ("regex", "pii", "keyword_list"):
            return None
        if isinstance(matcher.patterns, dict):
            names |= set(matcher.patterns)
        if matcher.type == "pii":
            names |= set(BUILTIN_PII_NAMES)
    return names


def redact_patterns(rule: RuleConfig) -> list[str]:
    """What a redact rule redacts with: its ``patterns``, else the matchers its ``when`` uses."""
    if rule.patterns:
        return list(rule.patterns)
    try:
        return sorted(references(compile_expression(rule.when)).matchers)
    except ExpressionError:
        return []


def rule_reference_errors(rule: RuleConfig, config: PolicyConfig) -> list[str]:
    """Problems in a rule's ``when``: a syntax error, or a ``$variable`` or matcher that the
    policy does not define."""
    try:
        refs = references(compile_expression(rule.when))
    except ExpressionError as exc:
        return [f"invalid 'when': {exc}"]
    errors = [
        f"'when' uses undefined variable '${name}'{_did_you_mean(name, config.variables)}"
        for name in sorted(refs.variables - set(config.variables))
    ]
    errors += [
        f"'when' uses undefined matcher '{name}'{_did_you_mean(name, config.matchers)}"
        for name in sorted(refs.matchers - set(config.matchers))
    ]
    return errors


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

        if not isinstance(rule.when, str):
            errors.append(f"{prefix} ({rule.name}): 'when' must be a string")
            continue
        if not isinstance(rule.enabled, bool):
            errors.append(f"{prefix} ({rule.name}): 'enabled' must be a boolean")
            continue

        # Every $variable and matcher a condition names must be defined. Otherwise the rule
        # could never fire: a typo in a deny rule would silently allow everything.
        if rule.enabled and rule.when:
            errors.extend(
                f"{prefix} ({rule.name}): {e}" for e in rule_reference_errors(rule, config)
            )

        # A redact rule needs something to redact with: its own patterns, or the matchers its
        # condition uses. Without either it matched and changed nothing.
        if rule.enabled and rule.then == "redact" and rule.patterns:
            known = _redact_pattern_names(config)
            for pname in rule.patterns:
                if known is not None and pname not in known:
                    errors.append(
                        f"{prefix} ({rule.name}): redact pattern '{pname}' is not a matcher or "
                        f"a named pattern in one{_did_you_mean(pname, known)}"
                    )
        if rule.enabled and rule.then == "redact" and not redact_patterns(rule):
            errors.append(
                f"{prefix} ({rule.name}): redact rule has nothing to redact with; add "
                "'patterns' (matcher or pattern names) or use 'matches <matcher>' in 'when'"
            )

    # Profiles
    for name, profile in config.profiles.items():
        if profile.extends and profile.extends not in config.profiles:
            errors.append(f"profiles.{name}: extends '{profile.extends}' does not exist")
        if profile.default_tier not in VALID_TIERS:
            errors.append(
                f"profiles.{name}: invalid default_tier '{profile.default_tier}', "
                f"expected one of {sorted(VALID_TIERS)}"
            )

    # Matchers: the type must be registered (built-in, or a custom type registered with
    # @register_matcher before loading), and the matcher must build (e.g. its regexes compile).
    valid_matcher_types = set(list_matchers())
    for name, matcher in config.matchers.items():
        if not matcher.type:
            errors.append(f"matchers.{name}: 'type' is required")
        elif matcher.type not in valid_matcher_types:
            errors.append(
                f"matchers.{name}: unknown type '{matcher.type}'"
                f"{_did_you_mean(matcher.type, valid_matcher_types)}, expected one of "
                f"{sorted(valid_matcher_types)} or a type registered with @register_matcher "
                "before loading"
            )
        else:
            if matcher.type in ("regex", "keyword_list") and not matcher.patterns:
                errors.append(f"matchers.{name}: 'patterns' is empty, so it never matches")
            try:
                get_matcher(matcher.type, matcher)
            except Exception as exc:  # noqa: BLE001 - any build failure is a config error
                errors.append(f"matchers.{name}: {exc}")

    return errors
