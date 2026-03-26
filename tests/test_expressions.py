"""Tests for the expression language parser and evaluator."""

from __future__ import annotations

import pytest

from theaios.guardrails.expressions import (
    ExpressionError,
    compile_expression,
    evaluate,
    tokenize,
)


class TestTokenizer:
    def test_simple_comparison(self) -> None:
        tokens = tokenize('action == "send_email"')
        types = [t.type for t in tokens]
        assert "IDENT" in types
        assert "EQ" in types
        assert "STRING" in types

    def test_keywords(self) -> None:
        tokens = tokenize("a and b or not c")
        types = [t.type for t in tokens[:-1]]  # exclude EOF
        assert types == ["IDENT", "AND", "IDENT", "OR", "NOT", "IDENT"]

    def test_variable(self) -> None:
        tokens = tokenize("$company_domain")
        assert tokens[0].type == "DOLLAR"
        assert tokens[1].type == "IDENT"

    def test_invalid_character(self) -> None:
        with pytest.raises(ExpressionError, match="Unexpected character"):
            tokenize("a @ b")


class TestParser:
    def test_simple_equality(self) -> None:
        ast = compile_expression('action == "send_email"')
        assert ast is not None

    def test_boolean_logic(self) -> None:
        ast = compile_expression('a == "x" and b == "y"')
        assert ast is not None

    def test_nested_field(self) -> None:
        ast = compile_expression("recipient.domain")
        assert ast is not None

    def test_not_in(self) -> None:
        ast = compile_expression('x not in ["a", "b"]')
        assert ast is not None

    def test_empty_expression(self) -> None:
        ast = compile_expression("")
        result = evaluate(ast, {})
        assert result is True

    def test_parentheses(self) -> None:
        ast = compile_expression('(a == "x" or b == "y") and c == "z"')
        assert ast is not None

    def test_list_literal(self) -> None:
        ast = compile_expression('x in ["a", "b", "c"]')
        assert ast is not None

    def test_unexpected_token(self) -> None:
        with pytest.raises(ExpressionError):
            compile_expression('a == "x" } extra')


class TestEvaluator:
    def test_string_equality(self) -> None:
        ast = compile_expression('action == "send_email"')
        assert evaluate(ast, {"action": "send_email"}) is True
        assert evaluate(ast, {"action": "read"}) is False

    def test_string_inequality(self) -> None:
        ast = compile_expression('domain != "acme.com"')
        assert evaluate(ast, {"domain": "external.com"}) is True
        assert evaluate(ast, {"domain": "acme.com"}) is False

    def test_nested_field_access(self) -> None:
        ast = compile_expression('recipient.domain == "acme.com"')
        ctx = {"recipient": {"domain": "acme.com"}}
        assert evaluate(ast, ctx) is True

    def test_missing_field_returns_none(self) -> None:
        ast = compile_expression("missing.field == null")
        assert evaluate(ast, {}) is True

    def test_variable_substitution(self) -> None:
        ast = compile_expression("domain != $company_domain")
        assert evaluate(ast, {"domain": "ext.com"}, variables={"company_domain": "acme.com"})
        assert not evaluate(ast, {"domain": "acme.com"}, variables={"company_domain": "acme.com"})

    def test_undefined_variable(self) -> None:
        ast = compile_expression("x == $undefined")
        with pytest.raises(ExpressionError, match="Undefined variable"):
            evaluate(ast, {"x": 1})

    def test_and_operator(self) -> None:
        ast = compile_expression('a == "x" and b == "y"')
        assert evaluate(ast, {"a": "x", "b": "y"}) is True
        assert evaluate(ast, {"a": "x", "b": "z"}) is False

    def test_or_operator(self) -> None:
        ast = compile_expression('a == "x" or b == "y"')
        assert evaluate(ast, {"a": "x", "b": "z"}) is True
        assert evaluate(ast, {"a": "z", "b": "y"}) is True
        assert evaluate(ast, {"a": "z", "b": "z"}) is False

    def test_not_operator(self) -> None:
        ast = compile_expression('not a == "x"')
        assert evaluate(ast, {"a": "y"}) is True
        assert evaluate(ast, {"a": "x"}) is False

    def test_in_list(self) -> None:
        ast = compile_expression('x in ["a", "b", "c"]')
        assert evaluate(ast, {"x": "b"}) is True
        assert evaluate(ast, {"x": "d"}) is False

    def test_not_in_list(self) -> None:
        ast = compile_expression('x not in ["a", "b"]')
        assert evaluate(ast, {"x": "c"}) is True
        assert evaluate(ast, {"x": "a"}) is False

    def test_in_variable_list(self) -> None:
        ast = compile_expression("domain in $sensitive_domains")
        variables = {"sensitive_domains": ["finance", "legal", "hr"]}
        assert evaluate(ast, {"domain": "finance"}, variables=variables) is True
        assert evaluate(ast, {"domain": "sales"}, variables=variables) is False

    def test_contains(self) -> None:
        ast = compile_expression('content contains "secret"')
        assert evaluate(ast, {"content": "this is a secret message"}) is True
        assert evaluate(ast, {"content": "nothing here"}) is False

    def test_starts_with(self) -> None:
        ast = compile_expression('path starts_with "finance/"')
        assert evaluate(ast, {"path": "finance/reports"}) is True
        assert evaluate(ast, {"path": "sales/data"}) is False

    def test_ends_with(self) -> None:
        ast = compile_expression('file ends_with ".csv"')
        assert evaluate(ast, {"file": "data.csv"}) is True
        assert evaluate(ast, {"file": "data.json"}) is False

    def test_numeric_comparison(self) -> None:
        ast = compile_expression("amount > 1000")
        assert evaluate(ast, {"amount": 1500}) is True
        assert evaluate(ast, {"amount": 500}) is False

    def test_boolean_literal(self) -> None:
        ast = compile_expression("enabled == true")
        assert evaluate(ast, {"enabled": True}) is True

    def test_matches_with_matcher(self) -> None:
        class FakeMatcher:
            def match(self, text: str, pattern_name: str | None = None) -> bool:
                return "injection" in text.lower()

        ast = compile_expression("content matches prompt_injection")
        matchers = {"prompt_injection": FakeMatcher()}
        assert evaluate(ast, {"content": "injection attempt"}, matchers=matchers) is True
        assert evaluate(ast, {"content": "normal text"}, matchers=matchers) is False

    def test_matches_unknown_matcher(self) -> None:
        ast = compile_expression("content matches nonexistent")
        with pytest.raises(ExpressionError, match="Unknown matcher"):
            evaluate(ast, {"content": "text"})

    def test_complex_expression(self) -> None:
        ast = compile_expression(
            'action == "send_email" and recipient.domain != $company_domain '
            'and not recipient.domain in $internal_domains'
        )
        ctx = {
            "action": "send_email",
            "recipient": {"domain": "external.com"},
        }
        variables = {
            "company_domain": "acme.com",
            "internal_domains": ["acme.com", "acme.co.uk"],
        }
        assert evaluate(ast, ctx, variables=variables) is True

    def test_parenthesized_or(self) -> None:
        ast = compile_expression('(a == "x" or a == "y") and b == "z"')
        assert evaluate(ast, {"a": "x", "b": "z"}) is True
        assert evaluate(ast, {"a": "y", "b": "z"}) is True
        assert evaluate(ast, {"a": "x", "b": "w"}) is False

    def test_short_circuit_and(self) -> None:
        """AND should short-circuit: if left is False, right is not evaluated."""
        ast = compile_expression("false and $undefined_var")
        # Should not raise ExpressionError for undefined var
        result = evaluate(ast, {})
        assert result is False

    def test_short_circuit_or(self) -> None:
        """OR should short-circuit: if left is True, right is not evaluated."""
        ast = compile_expression("true or $undefined_var")
        result = evaluate(ast, {})
        assert result is True
