"""Where flow state lives: the labels a session has accumulated, and proposals.

State is a log of events (label observed, proposal created, decided, executed, session
cleared). The in-memory store keeps the events in a list; the file store appends them to a
hash-chained JSONL file (theaios-core), so state survives a restart and any edit to the
history is detectable with ``python -m theaios.core.audit verify``.
"""

from __future__ import annotations

import threading
from typing import Any, cast
from dataclasses import asdict
from pathlib import Path

from theaios.core.audit import JsonlLog

from theaios.guardrails.flow.types import Denial, Label, Proposal, Provenance


class MemoryStore:
    """Flow state in memory. Lost when the process exits."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._labels: dict[str, list[Provenance]] = {}
        self._proposals: dict[str, Proposal] = {}

    # Labels ----------------------------------------------------------------------------

    def add_label(self, session_id: str, prov: Provenance) -> None:
        with self._lock:
            self._record({"type": "label", "session": session_id, **_prov_dict(prov)})
            self._labels.setdefault(session_id, []).append(prov)

    def provenance(self, session_id: str) -> list[Provenance]:
        with self._lock:
            return list(self._labels.get(session_id, []))

    def clear(self, session_id: str, by: str, reason: str) -> None:
        with self._lock:
            self._record({"type": "clear", "session": session_id, "by": by, "reason": reason})
            self._labels.pop(session_id, None)

    # Proposals -------------------------------------------------------------------------

    def save_proposal(self, proposal: Proposal) -> None:
        with self._lock:
            self._record({"type": "proposal", **_proposal_dict(proposal)})
            self._proposals[proposal.id] = proposal

    def get_proposal(self, proposal_id: str) -> Proposal | None:
        with self._lock:
            return self._proposals.get(proposal_id)

    def proposals(self, session_id: str | None = None) -> list[Proposal]:
        with self._lock:
            return [
                p
                for p in self._proposals.values()
                if session_id is None or p.session_id == session_id
            ]

    def update_proposal(self, proposal: Proposal) -> None:
        with self._lock:
            self._record(
                {
                    "type": "proposal_status",
                    "id": proposal.id,
                    "status": proposal.status,
                    "decided_by": proposal.decided_by,
                    "decided_at": proposal.decided_at,
                    "note": proposal.note,
                }
            )
            self._proposals[proposal.id] = proposal

    @property
    def lock(self) -> threading.RLock:
        return self._lock

    def _record(self, event: dict[str, object]) -> None:  # noqa: B027 - hook for subclasses
        pass


class FileStore(MemoryStore):
    """Flow state in an append-only, hash-chained JSONL file. Reloaded on start."""

    def __init__(self, path: str | Path) -> None:
        super().__init__()
        self._log = JsonlLog(path, chain=True)
        self._replaying = True
        for entry in self._log.entries():
            self._apply(dict(entry))
        self._replaying = False

    @property
    def path(self) -> Path:
        return self._log.path

    def _record(self, event: dict[str, object]) -> None:
        if not self._replaying:
            self._log.append(event)

    def _apply(self, e: dict[str, object]) -> None:
        kind = e.get("type")
        if kind == "label":
            prov = Provenance(
                tool=str(e["tool"]),
                label=Label(str(e["label"])),
                call_id=str(e["call_id"]),
                at=float(e["at"]),  # type: ignore[arg-type]
            )
            self._labels.setdefault(str(e["session"]), []).append(prov)
        elif kind == "clear":
            self._labels.pop(str(e["session"]), None)
        elif kind == "proposal":
            self._proposals[str(e["id"])] = _proposal_from(e)
        elif kind == "proposal_status":
            p = self._proposals.get(str(e["id"]))
            if p is not None:
                p.status = str(e["status"])
                p.decided_by = e.get("decided_by")  # type: ignore[assignment]
                p.decided_at = e.get("decided_at")  # type: ignore[assignment]
                p.note = str(e.get("note") or "")


def _prov_dict(prov: Provenance) -> dict[str, object]:
    return {"tool": prov.tool, "label": prov.label.value, "call_id": prov.call_id, "at": prov.at}


def _proposal_dict(p: Proposal) -> dict[str, object]:
    d = asdict(p)
    d["reasons"] = [
        {
            "code": r.code.value,
            "message": r.message,
            "provenance": [_prov_dict(x) for x in r.provenance],
        }
        for r in p.reasons
    ]
    return d


def _proposal_from(e: dict[str, object]) -> Proposal:
    from theaios.guardrails.flow.types import Code

    reasons = [
        Denial(
            code=Code(str(r["code"])),
            message=str(r["message"]),
            provenance=[
                Provenance(
                    tool=str(x["tool"]),
                    label=Label(str(x["label"])),
                    call_id=str(x["call_id"]),
                    at=float(x["at"]),
                )
                for x in r.get("provenance", [])
            ],
        )
        for r in cast("list[dict[str, Any]]", e.get("reasons") or [])
    ]
    return Proposal(
        id=str(e["id"]),
        session_id=str(e["session_id"]),
        tool=str(e["tool"]),
        args=dict(e["args"]),  # type: ignore[call-overload]
        digest=str(e["digest"]),
        reasons=reasons,
        tier=str(e["tier"]),
        created_at=float(e["created_at"]),  # type: ignore[arg-type]
        status=str(e["status"]),
        decided_by=e.get("decided_by"),  # type: ignore[arg-type]
        decided_at=e.get("decided_at"),  # type: ignore[arg-type]
        note=str(e.get("note") or ""),
    )
