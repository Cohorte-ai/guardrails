"""Tests for the audit logger."""

from __future__ import annotations

from pathlib import Path

from theaios.guardrails.audit import AuditLog
from theaios.guardrails.types import Decision, GuardEvent


class TestAuditLog:
    def test_write_and_read(self, tmp_path: Path) -> None:
        log = AuditLog(str(tmp_path / "audit.jsonl"))
        event = GuardEvent(scope="input", agent="test", data={"content": "hello"})
        decision = Decision(outcome="allow")

        log.write(event, decision)
        entries = log.read()
        assert len(entries) == 1
        assert entries[0]["agent"] == "test"
        assert entries[0]["outcome"] == "allow"

    def test_filter_by_agent(self, tmp_path: Path) -> None:
        log = AuditLog(str(tmp_path / "audit.jsonl"))
        log.write(
            GuardEvent(scope="input", agent="agent-a", data={}),
            Decision(outcome="allow"),
        )
        log.write(
            GuardEvent(scope="input", agent="agent-b", data={}),
            Decision(outcome="deny"),
        )

        entries = log.read(agent="agent-b")
        assert len(entries) == 1
        assert entries[0]["agent"] == "agent-b"

    def test_filter_by_outcome(self, tmp_path: Path) -> None:
        log = AuditLog(str(tmp_path / "audit.jsonl"))
        log.write(
            GuardEvent(scope="input", agent="test", data={}),
            Decision(outcome="allow"),
        )
        log.write(
            GuardEvent(scope="input", agent="test", data={}),
            Decision(outcome="deny", rule="r1"),
        )

        entries = log.read(outcome="deny")
        assert len(entries) == 1
        assert entries[0]["outcome"] == "deny"

    def test_clear(self, tmp_path: Path) -> None:
        log = AuditLog(str(tmp_path / "audit.jsonl"))
        log.write(
            GuardEvent(scope="input", agent="test", data={}),
            Decision(outcome="allow"),
        )
        assert len(log.read()) == 1
        log.clear()
        assert len(log.read()) == 0

    def test_empty_log(self, tmp_path: Path) -> None:
        log = AuditLog(str(tmp_path / "nonexistent.jsonl"))
        assert log.read() == []

    def test_includes_policy_metadata(self, tmp_path: Path) -> None:
        from theaios.guardrails.types import PolicyConfig, PolicyMetadata

        log = AuditLog(str(tmp_path / "audit.jsonl"))
        policy = PolicyConfig(metadata=PolicyMetadata(name="test-policy"), version="1.0")
        log.write(
            GuardEvent(scope="input", agent="test", data={}),
            Decision(outcome="allow"),
            policy=policy,
        )
        entries = log.read()
        assert entries[0]["policy_name"] == "test-policy"
