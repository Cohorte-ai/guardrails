"""Regression tests for the 0.1.6 pre-release usability test.

Each test is a mistake a tester made that used to load as a valid policy and change what the
policy does, usually allowing what it was written to block.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from theaios.guardrails.config import ConfigError, load_policy
from theaios.guardrails.engine import Engine
from theaios.guardrails.matchers import Matcher, register_matcher
from theaios.guardrails.types import GuardEvent, MatcherConfig, PolicyConfig, RuleConfig

BASE = """
version: "1.0"
variables:
  max_transfer: 5000
matchers:
  pii:
    type: pii
  injection:
    type: keyword_list
    patterns: ["ignore previous instructions"]
"""


def _load(tmp_path: Path, body: str) -> PolicyConfig:
    path = tmp_path / "policy.yaml"
    path.write_text(BASE + body)
    return load_policy(str(path))


def _errors(tmp_path: Path, body: str) -> str:
    with pytest.raises(ConfigError) as exc:
        _load(tmp_path, body)
    return "\n".join(exc.value.errors)


CAP = """
rules:
  - name: cap
    scope: action
    when: "amount > $max_transfer"
    then: deny
"""


def _action(engine: Engine, **data: object) -> str:
    return engine.evaluate(GuardEvent(scope="action", agent="a", data=data)).outcome


# --- Shape: typos and wrong types that used to load silently ---------------------------


def test_misspelled_rules_section_is_rejected(tmp_path: Path) -> None:
    assert "unknown key 'rule' (did you mean 'rules'?)" in _errors(
        tmp_path, CAP.replace("rules:", "rule:")
    )


def test_rules_as_mapping_is_rejected(tmp_path: Path) -> None:
    body = "rules:\n  cap: {scope: action, when: 'amount > 1', then: deny}\n"
    assert "'rules' must be a list" in _errors(tmp_path, body)


def test_unknown_rule_key_is_rejected(tmp_path: Path) -> None:
    errors = _errors(tmp_path, CAP.replace("when:", "condition:"))
    assert "rules[0] (cap): unknown key 'condition'" in errors
    errors = _errors(tmp_path, CAP + "    enabeld: false\n")
    assert "unknown key 'enabeld' (did you mean 'enabled'?)" in errors


def test_quoted_enabled_is_rejected(tmp_path: Path) -> None:
    assert "'enabled' must be true or false" in _errors(tmp_path, CAP + '    enabled: "false"\n')


def test_non_string_condition_is_rejected(tmp_path: Path) -> None:
    body = CAP.replace('when: "amount > $max_transfer"', "when: 42")
    assert "'when' must be a string" in _errors(tmp_path, body)


def test_unquoted_boolean_name_is_rejected(tmp_path: Path) -> None:
    assert "'name' must be a string" in _errors(tmp_path, CAP.replace("name: cap", "name: off"))


def test_keyword_patterns_as_string_is_rejected(tmp_path: Path) -> None:
    body = BASE.replace('patterns: ["ignore previous instructions"]', 'patterns: "ignore previous"')
    path = tmp_path / "p.yaml"
    path.write_text(body + CAP)
    with pytest.raises(ConfigError, match="'patterns' must be a list"):
        load_policy(str(path))


def test_matcher_option_typo_is_rejected(tmp_path: Path) -> None:
    body = BASE.replace(
        'patterns: ["ignore previous instructions"]',
        'patterns: ["x"]\n    options: {case_insesitive: true}',
    )
    path = tmp_path / "p.yaml"
    path.write_text(body + CAP)
    with pytest.raises(ConfigError, match="unknown key 'case_insesitive'"):
        load_policy(str(path))


def test_invalid_regex_fails_validation_not_engine(tmp_path: Path) -> None:
    body = "  bad:\n    type: regex\n    patterns: {x: '([a-z'}\n" + CAP
    assert "matchers.bad: Invalid regex pattern 'x'" in _errors(tmp_path, body)


def test_not_a_policy_file_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "mkdocs.yml"
    path.write_text("site_name: Docs\nnav:\n  - Home: index.md\n")
    with pytest.raises(ConfigError, match="unknown key 'site_name'"):
        load_policy(str(path))


def test_yaml_syntax_error_is_a_config_error_with_line(tmp_path: Path) -> None:
    path = tmp_path / "p.yaml"
    path.write_text('version: "1.0"\nrules:\n  - name: x\n    when: "a == "b""\n')
    with pytest.raises(ConfigError, match=r"p\.yaml:4: YAML syntax error"):
        load_policy(str(path))


def test_directory_is_a_config_error(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="is not a file"):
        load_policy(str(tmp_path))


# --- Policies built in Python get the same checks --------------------------------------


@pytest.mark.parametrize(
    "rule",
    [
        RuleConfig(name="r", scope="action", when="amount > 1", then="block"),
        RuleConfig(name="r", scope="actions", when="amount > 1", then="deny"),
        RuleConfig(name="r", scope="action", when="amount > 1", then="deny", severity="urgent"),
    ],
)
def test_python_built_policy_is_validated(rule: RuleConfig) -> None:
    with pytest.raises(ConfigError):
        Engine(PolicyConfig(rules=[rule]))


# --- Redaction ---------------------------------------------------------------------------


def test_redact_rule_without_patterns_uses_its_matcher(tmp_path: Path) -> None:
    policy = _load(
        tmp_path,
        "rules:\n  - name: redact-pii\n    scope: output\n    when: content matches pii\n"
        "    then: redact\n",
    )
    decision = Engine(policy).evaluate(
        GuardEvent(scope="output", agent="a", data={"content": "SSN is 123-45-6789"})
    )
    assert decision.outcome == "redact"
    assert decision.modifications is not None
    assert "123-45-6789" not in decision.modifications["content"]


def test_redact_rule_with_nothing_to_redact_with_is_rejected(tmp_path: Path) -> None:
    body = "rules:\n  - name: r\n    scope: output\n    when: 'len > 3'\n    then: redact\n"
    assert "redact rule has nothing to redact with" in _errors(tmp_path, body)


# --- Custom matcher types (documented) now validate --------------------------------------


@register_matcher("ux_test_toxicity")
class _Toxicity(Matcher):
    def __init__(self, config: MatcherConfig) -> None:
        self._words = set(config.patterns if isinstance(config.patterns, list) else [])

    def match(self, text: str, pattern_name: str | None = None) -> bool:
        return bool(set(text.lower().split()) & self._words)


def test_registered_custom_matcher_type_loads(tmp_path: Path) -> None:
    body = (
        "  tox:\n    type: ux_test_toxicity\n    patterns: [hate]\n"
        "rules:\n  - name: t\n    scope: input\n    when: content matches tox\n    then: deny\n"
    )
    engine = Engine(_load(tmp_path, body))
    event = GuardEvent(scope="input", agent="a", data={"content": "i hate this"})
    assert engine.evaluate(event).outcome == "deny"


# --- Numbers that arrive as strings (theaios-core 0.1.1) ---------------------------------


def test_string_amount_cannot_bypass_a_cap(tmp_path: Path) -> None:
    engine = Engine(_load(tmp_path, CAP))
    assert _action(engine, amount="10000") == "deny"
    assert _action(engine, amount="600") == "allow"
    assert _action(engine, amount=10000) == "deny"


def test_unparseable_amount_fails_closed(tmp_path: Path) -> None:
    engine = Engine(_load(tmp_path, CAP))
    decision = engine.evaluate(GuardEvent(scope="action", agent="a", data={"amount": "10,000"}))
    assert decision.outcome == "deny"
    assert "could not be evaluated" in decision.reason
