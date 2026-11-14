"""GuardrailsCallback must stop what a rule denies (LangChain swallows callback errors otherwise)."""

from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("langchain_core")

from langchain_core.tools import tool  # noqa: E402

from theaios.guardrails.adapters.decorator import ApprovalRequired, GuardDenied  # noqa: E402
from theaios.guardrails.adapters.langchain import GuardrailsCallback  # noqa: E402

POLICY = """
version: "1.0"
rules:
  - name: no-refunds
    scope: tool_call
    when: tool_name == "refund"
    then: deny
    reason: no refunds
  - name: big-exports
    scope: tool_call
    when: tool_name == "export"
    then: require_approval
    tier: soft
"""

RAN: list[str] = []


@tool
def refund(order: str) -> str:
    """Refund an order."""
    RAN.append(f"refund:{order}")
    return "refunded"


@tool
def export(table: str) -> str:
    """Export a table."""
    RAN.append(f"export:{table}")
    return "exported"


@tool
def lookup(order: str) -> str:
    """Look up an order."""
    RAN.append(f"lookup:{order}")
    return "found"


def _cb(tmp_path: Path) -> GuardrailsCallback:
    (tmp_path / "p.yaml").write_text(POLICY)
    return GuardrailsCallback(str(tmp_path / "p.yaml"), agent="assistant")


def test_a_denied_tool_call_does_not_run(tmp_path: Path) -> None:
    RAN.clear()
    with pytest.raises(GuardDenied):
        refund.invoke({"order": "o1"}, config={"callbacks": [_cb(tmp_path)]})
    assert RAN == []


def test_an_approval_requirement_stops_the_call(tmp_path: Path) -> None:
    RAN.clear()
    with pytest.raises(ApprovalRequired):
        export.invoke({"table": "users"}, config={"callbacks": [_cb(tmp_path)]})
    assert RAN == []


def test_an_allowed_tool_call_runs(tmp_path: Path) -> None:
    RAN.clear()
    assert lookup.invoke({"order": "o1"}, config={"callbacks": [_cb(tmp_path)]}) == "found"
    assert RAN == ["lookup:o1"]


def test_the_callback_asks_langchain_to_raise() -> None:
    assert GuardrailsCallback.raise_error is True


ARGS_POLICY = """
version: "1.0"
profiles:
  support:
    deny: [wire_money]
rules:
  - name: big-refunds
    scope: tool_call
    when: tool_name == "refund" and arguments.amount > 100
    then: deny
    reason: refunds over 100 need a person
"""


@tool
def refund_amount(order: str, amount: int) -> str:
    """Refund an amount."""
    RAN.append(f"refund:{order}:{amount}")
    return "refunded"


refund_amount.name = "refund"


@tool
def wire_money(to: str) -> str:
    """Wire money."""
    RAN.append(f"wire:{to}")
    return "wired"


def _args_cb(tmp_path: Path, agent: str = "support") -> GuardrailsCallback:
    (tmp_path / "a.yaml").write_text(ARGS_POLICY)
    return GuardrailsCallback(str(tmp_path / "a.yaml"), agent=agent)


def test_rules_see_the_tool_arguments(tmp_path: Path) -> None:
    RAN.clear()
    with pytest.raises(GuardDenied):
        refund_amount.invoke(
            {"order": "o1", "amount": 500}, config={"callbacks": [_args_cb(tmp_path)]}
        )
    assert refund_amount.invoke(
        {"order": "o2", "amount": 5}, config={"callbacks": [_args_cb(tmp_path)]}
    )
    assert RAN == ["refund:o2:5"]


def test_profile_deny_lists_apply_to_tool_calls(tmp_path: Path) -> None:
    RAN.clear()
    with pytest.raises(GuardDenied):
        wire_money.invoke({"to": "x"}, config={"callbacks": [_args_cb(tmp_path)]})
    assert RAN == []
    assert wire_money.invoke({"to": "y"}, config={"callbacks": [_args_cb(tmp_path, agent="ops")]})
    assert RAN == ["wire:y"]
