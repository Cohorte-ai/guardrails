"""JSONL audit log writer and reader."""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

from theaios.guardrails.types import Decision, GuardEvent, PolicyConfig


class AuditLog:
    """Append-only JSONL audit log.

    Writes one JSON object per line. Every evaluation is logged,
    including ALLOWs — critical for compliance auditing.
    """

    def __init__(self, path: str = ".guardrails_audit/audit.jsonl") -> None:
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)

    @property
    def path(self) -> Path:
        return self._path

    def write(
        self,
        event: GuardEvent,
        decision: Decision,
        policy: PolicyConfig | None = None,
    ) -> None:
        """Write an audit log entry."""
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_id": str(uuid.uuid4()),
            "agent": event.agent,
            "scope": event.scope,
            "outcome": decision.outcome,
            "rule": decision.rule,
            "tier": decision.tier,
            "severity": decision.severity,
            "reason": decision.reason,
            "dry_run": decision.dry_run,
            "session_id": event.session_id,
            "evaluation_time_ms": round(decision.evaluation_time_ms, 3),
            "matched_rules": decision.matched_rules,
        }

        if policy:
            entry["policy_name"] = policy.metadata.name
            entry["policy_version"] = policy.version

        with open(self._path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, default=str) + "\n")

    def read(
        self,
        *,
        since: str | None = None,
        agent: str | None = None,
        outcome: str | None = None,
        rule: str | None = None,
        limit: int = 1000,
    ) -> list[dict[str, object]]:
        """Read audit log entries with optional filters."""
        if not self._path.exists():
            return []

        entries: list[dict[str, object]] = []
        with open(self._path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue

                if since and entry.get("timestamp", "") < since:
                    continue
                if agent and entry.get("agent") != agent:
                    continue
                if outcome and entry.get("outcome") != outcome:
                    continue
                if rule and entry.get("rule") != rule:
                    continue

                entries.append(entry)
                if len(entries) >= limit:
                    break

        return entries

    def clear(self) -> None:
        """Clear all audit log entries."""
        if self._path.exists():
            self._path.unlink()
