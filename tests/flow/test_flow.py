"""Flow control: effects, durable taint, frozen proposals, typed denials."""

from __future__ import annotations

import json
import threading
from pathlib import Path

import pytest
from theaios.core.audit import main as verify_main

from theaios.guardrails.config import ConfigError, load_policy
from theaios.guardrails.flow import (
    Code,
    Effect,
    FileStore,
    FlowBlocked,
    FlowGuard,
    Label,
    ProposalError,
    StoreCorrupted,
    Verdict,
)

POLICY = """
version: "1.0"
tools:
  read_inbox: {effect: read, returns: [untrusted, sensitive]}
  search_web: {effect: read, returns: untrusted}
  read_crm: {effect: read, returns: sensitive}
  read_calendar: {effect: read}
  update_ticket: {effect: write}
  send_email: {effect: send}
  "crm_*": {effect: read, returns: sensitive}
  crm_export: {effect: send}
rules:
  - name: no-wire-transfers
    scope: action
    when: action == "wire_transfer"
    then: deny
    reason: wire transfers are never done by agents
  - name: big-tickets
    scope: action
    when: action == "update_ticket" and priority == "p0"
    then: require_approval
    tier: soft
"""


def _guard(tmp_path: Path, extra: str = "", **kw: object) -> FlowGuard:
    path = tmp_path / "policy.yaml"
    path.write_text(POLICY + extra)
    return FlowGuard(load_policy(str(path)), **kw)  # type: ignore[arg-type]


# --- Admission --------------------------------------------------------------------------


def test_clean_session_allows_everything_declared(tmp_path: Path) -> None:
    g = _guard(tmp_path)
    for tool in ("send_email", "update_ticket", "read_crm"):
        assert g.admit("s", tool, {"to": "a@b.c"}).verdict is Verdict.ALLOW


def test_untrusted_content_blocks_writes_and_sends_not_reads(tmp_path: Path) -> None:
    g = _guard(tmp_path)
    g.observe("s", "search_web")
    assert g.admit("s", "read_calendar").allowed
    write = g.admit("s", "update_ticket", {"id": 1})
    send = g.admit("s", "send_email", {"to": "x@evil.test"})
    assert write.verdict is Verdict.REQUIRE_APPROVAL
    assert write.codes == [Code.UNTRUSTED_TO_WRITE]
    assert send.codes == [Code.UNTRUSTED_TO_SEND]
    assert send.reasons[0].provenance[0].tool == "search_web"
    assert "search_web" in send.reasons[0].message


def test_sensitive_data_blocks_sends_only(tmp_path: Path) -> None:
    g = _guard(tmp_path)
    g.observe("s", "read_crm")
    assert g.admit("s", "update_ticket").allowed
    assert g.admit("s", "send_email").codes == [Code.SENSITIVE_TO_SEND]


def test_inbox_is_both_untrusted_and_sensitive(tmp_path: Path) -> None:
    g = _guard(tmp_path)
    assert g.observe("s", "read_inbox") == [Label.SENSITIVE, Label.UNTRUSTED]
    assert set(g.admit("s", "send_email").codes) == {
        Code.UNTRUSTED_TO_SEND,
        Code.SENSITIVE_TO_SEND,
    }


def test_taint_is_per_session(tmp_path: Path) -> None:
    g = _guard(tmp_path)
    g.observe("a", "search_web")
    assert not g.admit("a", "send_email").allowed
    assert g.admit("b", "send_email").allowed


def test_taint_lasts_until_cleared_by_a_person(tmp_path: Path) -> None:
    g = _guard(tmp_path)
    g.observe("s", "search_web")
    for _ in range(3):
        assert not g.admit("s", "send_email").allowed
    with pytest.raises(ValueError):
        g.clear("s", by="", reason="")
    g.clear("s", by="alice", reason="new task")
    assert g.admit("s", "send_email").allowed


def test_undeclared_tool_is_a_send_with_untrusted_results(tmp_path: Path) -> None:
    g = _guard(tmp_path)
    assert g.admit("s", "post_to_slack").allowed  # nothing to leak yet
    assert g.observe("s", "fetch_url") == [Label.UNTRUSTED]
    blocked = g.admit("s", "post_to_slack")
    assert blocked.effect is Effect.SEND
    assert "undeclared" in blocked.reasons[0].message


def test_undeclared_deny(tmp_path: Path) -> None:
    g = _guard(tmp_path, "flow:\n  undeclared: deny\n")
    a = g.admit("s", "post_to_slack")
    assert a.verdict is Verdict.DENY and a.codes == [Code.UNDECLARED_TOOL]


def test_exact_declaration_beats_glob(tmp_path: Path) -> None:
    g = _guard(tmp_path)
    spec = g.spec("crm_lookup")
    assert spec is not None and spec.effect is Effect.READ
    export = g.spec("crm_export")
    assert export is not None and export.effect is Effect.SEND


def test_rule_deny_wins(tmp_path: Path) -> None:
    g = _guard(tmp_path)  # wire_transfer is undeclared; the rule's deny must still win
    a = g.admit("s", "wire_transfer", {"amount": 10})
    assert a.verdict is Verdict.DENY and a.codes == [Code.RULE_DENY]
    assert "never done by agents" in a.reasons[0].message


def test_rule_approval_and_flow_combine_with_the_highest_tier(tmp_path: Path) -> None:
    g = _guard(tmp_path)
    clean = g.admit("s", "update_ticket", {"priority": "p0"})
    assert clean.codes == [Code.RULE_APPROVAL]
    assert clean.proposal is not None and clean.proposal.tier == "soft"
    g.observe("s", "search_web")
    both = g.admit("s", "update_ticket", {"priority": "p0"})
    assert both.codes == [Code.RULE_APPROVAL, Code.UNTRUSTED_TO_WRITE]
    assert both.proposal is not None and both.proposal.tier == "strong"


def test_on_block_deny(tmp_path: Path) -> None:
    g = _guard(tmp_path, "flow:\n  on_block: deny\n")
    g.observe("s", "read_crm")
    a = g.admit("s", "send_email")
    assert a.verdict is Verdict.DENY and a.proposal is None


def test_args_cannot_spoof_the_action(tmp_path: Path) -> None:
    g = _guard(tmp_path)
    a = g.admit("s", "wire_transfer", {"action": "read_calendar"})
    assert a.verdict is Verdict.DENY


# --- Proposals --------------------------------------------------------------------------


def _blocked(g: FlowGuard) -> str:
    g.observe("s", "read_inbox")
    a = g.admit("s", "send_email", {"to": "boss@corp.test", "body": "summary"})
    assert a.proposal is not None
    return a.proposal.id


def test_approved_proposal_runs_once_with_the_frozen_args(tmp_path: Path) -> None:
    g = _guard(tmp_path)
    pid = _blocked(g)
    sent: list[dict[str, object]] = []
    with pytest.raises(ProposalError, match="pending, not approved"):
        g.execute(pid, {"send_email": lambda **kw: sent.append(kw)})
    g.decide(pid, approve=True, by="alice")
    g.execute(pid, {"send_email": lambda **kw: sent.append(kw)})
    assert sent == [{"to": "boss@corp.test", "body": "summary"}]
    with pytest.raises(ProposalError, match="executed"):
        g.execute(pid, {"send_email": lambda **kw: sent.append(kw)})


def test_execute_runs_only_the_approved_tool_with_the_approved_args(tmp_path: Path) -> None:
    g = _guard(tmp_path)
    pid = _blocked(g)
    g.decide(pid, approve=True, by="alice")
    wired: list[object] = []
    with pytest.raises(ProposalError, match="'send_email', which is not in the tools"):
        g.execute(pid, {"wire_money": lambda **kw: wired.append(kw)})
    assert wired == []
    proposal = g.proposal(pid)
    assert proposal is not None
    proposal.args["to"] = "attacker@evil.test"  # tampering with the stored proposal
    with pytest.raises(ProposalError, match="stored arguments were altered"):
        g.execute(pid, {"send_email": lambda **kw: None})


def test_decided_once_and_rejected_never_runs(tmp_path: Path) -> None:
    g = _guard(tmp_path)
    pid = _blocked(g)
    g.decide(pid, approve=False, by="alice", note="looks injected")
    with pytest.raises(ProposalError, match="already rejected"):
        g.decide(pid, approve=True, by="mallory")
    with pytest.raises(ProposalError, match="rejected, not approved"):
        g.execute(pid, {"send_email": lambda **kw: None})
    with pytest.raises(ValueError):
        g.decide(_blocked(g), approve=True, by="")


def test_execute_is_at_most_once_under_concurrency(tmp_path: Path) -> None:
    g = _guard(tmp_path)
    pid = _blocked(g)
    g.decide(pid, approve=True, by="alice")
    runs: list[int] = []
    errors: list[Exception] = []

    def worker() -> None:
        try:
            g.execute(pid, {"send_email": lambda **kw: runs.append(1)})
        except ProposalError as exc:
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(runs) == 1 and len(errors) == 7


def test_pending_lists_undecided_proposals(tmp_path: Path) -> None:
    g = _guard(tmp_path)
    pid = _blocked(g)
    assert [p.id for p in g.pending("s")] == [pid]
    g.decide(pid, approve=True, by="alice")
    assert g.pending("s") == []


# --- Call wrapper -----------------------------------------------------------------------


def test_call_runs_observes_and_raises_when_blocked(tmp_path: Path) -> None:
    g = _guard(tmp_path)
    assert g.call("s", "search_web", lambda q: f"results for {q}", {"q": "pricing"}) == (
        "results for pricing"
    )
    assert g.labels("s") == {Label.UNTRUSTED}
    with pytest.raises(FlowBlocked) as exc:
        g.call("s", "send_email", lambda **kw: None, {"to": "x@evil.test"})
    assert exc.value.admission.proposal is not None
    assert "waiting for approval" in str(exc.value)


def test_tool_decorator(tmp_path: Path) -> None:
    g = _guard(tmp_path)
    current = {"session": "s1"}

    @g.tool("send_email", session=lambda: current["session"])
    def send(to: str) -> str:
        return f"sent to {to}"

    assert send(to="a@b.c") == "sent to a@b.c"
    g.observe("s1", "read_crm")
    with pytest.raises(FlowBlocked):
        send(to="a@b.c")
    current["session"] = "s2"
    assert send(to="a@b.c") == "sent to a@b.c"


# --- Durable state ----------------------------------------------------------------------


def test_file_store_survives_restart_and_is_tamper_evident(tmp_path: Path) -> None:
    log = tmp_path / "flow.jsonl"
    g = _guard(tmp_path, store=FileStore(log))
    pid = _blocked(g)
    g.decide(pid, approve=True, by="alice")

    g.store.close()
    restarted = _guard(tmp_path, store=FileStore(log))
    assert restarted.labels("s") == {Label.UNTRUSTED, Label.SENSITIVE}
    proposal = restarted.store.get_proposal(pid)
    assert proposal is not None and proposal.status == "approved"
    assert proposal.reasons[0].provenance[0].tool == "read_inbox"
    assert verify_main(["verify", str(log)]) == 0
    restarted.store.close()

    lines = log.read_text().splitlines()
    first = json.loads(lines[0])
    first["tool"] = "read_calendar"  # rewrite history: pretend the inbox was never read
    lines[0] = json.dumps(first)
    log.write_text("\n".join(lines) + "\n")
    assert verify_main(["verify", str(log)]) == 1
    with pytest.raises(StoreCorrupted, match="entry 1 does not match the hash chain"):
        FileStore(log)


# --- Policy file ------------------------------------------------------------------------


def test_policy_shape_errors_in_tools_and_flow(tmp_path: Path) -> None:
    path = tmp_path / "bad.yaml"
    path.write_text('version: "1.0"\ntools:\n  x: {effct: read}\nflow:\n  undeclard: deny\n')
    with pytest.raises(ConfigError) as exc:
        load_policy(str(path))
    errors = "\n".join(exc.value.errors)
    assert "tools.x: unknown key 'effct' (did you mean 'effect'?)" in errors
    assert "flow: unknown key 'undeclard' (did you mean 'undeclared'?)" in errors


def test_policy_value_errors_in_tools_and_flow(tmp_path: Path) -> None:
    path = tmp_path / "bad.yaml"
    path.write_text(
        'version: "1.0"\ntools:\n  send_email: {effect: sned, returns: [untrustd]}\n'
        "flow:\n  on_block: maybe\n"
    )
    with pytest.raises(ConfigError) as exc:
        load_policy(str(path))
    errors = "\n".join(exc.value.errors)
    assert "'effect' must be one of" in errors and "(did you mean 'send'?)" in errors
    assert "unknown label 'untrustd'" in errors
    assert "flow.on_block must be" in errors


def test_policy_without_tools_is_unchanged(tmp_path: Path) -> None:
    path = tmp_path / "old.yaml"
    path.write_text('version: "1.0"\nrules: []\n')
    policy = load_policy(str(path))
    assert policy.tools == {} and policy.flow.on_block == "require_approval"
