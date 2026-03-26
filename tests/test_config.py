"""Tests for YAML policy loading and validation."""

from __future__ import annotations

from pathlib import Path

import pytest

from theaios.guardrails.config import ConfigError, load_policy, validate_policy
from theaios.guardrails.types import PolicyConfig, RuleConfig


class TestLoadPolicy:
    def test_load_valid_yaml(self, basic_yaml: Path) -> None:
        policy = load_policy(str(basic_yaml))
        assert policy.version == "1.0"
        assert policy.metadata.name == "test-policy"
        assert len(policy.rules) == 2
        assert "prompt_injection" in policy.matchers
        assert "sales-agent" in policy.profiles

    def test_file_not_found(self) -> None:
        with pytest.raises(FileNotFoundError):
            load_policy("nonexistent.yaml")

    def test_invalid_yaml(self, tmp_path: Path) -> None:
        p = tmp_path / "bad.yaml"
        p.write_text("not a mapping")
        with pytest.raises(ConfigError, match="YAML mapping"):
            load_policy(str(p))

    def test_variables_loaded(self, basic_yaml: Path) -> None:
        policy = load_policy(str(basic_yaml))
        assert policy.variables["company_domain"] == "acme.com"

    def test_profiles_loaded(self, basic_yaml: Path) -> None:
        policy = load_policy(str(basic_yaml))
        sales = policy.profiles["sales-agent"]
        assert sales.extends == "default"
        assert "read_crm" in sales.allow
        assert "commit_pricing" in sales.deny

    def test_matchers_loaded(self, basic_yaml: Path) -> None:
        policy = load_policy(str(basic_yaml))
        m = policy.matchers["prompt_injection"]
        assert m.type == "keyword_list"
        assert isinstance(m.patterns, list)
        assert len(m.patterns) == 2

    def test_tags_loaded(self, basic_yaml: Path) -> None:
        policy = load_policy(str(basic_yaml))
        assert "security" in policy.rules[0].tags


class TestValidatePolicy:
    def test_valid_policy(self, basic_yaml: Path) -> None:
        policy = load_policy(str(basic_yaml))
        errors = validate_policy(policy)
        assert errors == []

    def test_missing_rule_name(self) -> None:
        policy = PolicyConfig(rules=[RuleConfig(name="", scope="input", then="deny")])
        errors = validate_policy(policy)
        assert any("name" in e for e in errors)

    def test_duplicate_rule_names(self) -> None:
        policy = PolicyConfig(rules=[
            RuleConfig(name="r1", scope="input", then="deny"),
            RuleConfig(name="r1", scope="output", then="deny"),
        ])
        errors = validate_policy(policy)
        assert any("duplicate" in e for e in errors)

    def test_invalid_scope(self) -> None:
        policy = PolicyConfig(rules=[RuleConfig(name="r1", scope="invalid", then="deny")])
        errors = validate_policy(policy)
        assert any("scope" in e for e in errors)

    def test_invalid_outcome(self) -> None:
        policy = PolicyConfig(rules=[RuleConfig(name="r1", scope="input", then="explode")])
        errors = validate_policy(policy)
        assert any("outcome" in e for e in errors)

    def test_invalid_severity(self) -> None:
        policy = PolicyConfig(rules=[
            RuleConfig(name="r1", scope="input", then="deny", severity="ultra")
        ])
        errors = validate_policy(policy)
        assert any("severity" in e for e in errors)

    def test_cross_agent_missing_from(self) -> None:
        policy = PolicyConfig(rules=[
            RuleConfig(name="r1", scope="cross_agent", then="deny")
        ])
        errors = validate_policy(policy)
        assert any("from" in e for e in errors)

    def test_invalid_version(self) -> None:
        policy = PolicyConfig(version="2.0")
        errors = validate_policy(policy)
        assert any("version" in e for e in errors)
