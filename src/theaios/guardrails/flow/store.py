"""Where flow state lives: the labels a session has accumulated, and proposals.

State is a log of events (label observed, proposal created, decided, executed, session
cleared). The in-memory store keeps them in a list; the file store appends them to a
hash-chained JSONL file (theaios-core), so state survives a restart and edits are detectable.

A hash chain alone cannot see its own end being cut off: deleting the last lines leaves a
valid, shorter chain. The file store therefore keeps an anchor next to the log
(``<file>.head``: the number of entries and the last hash), rewritten after every append, and
checks it on open. It also holds an exclusive lock (``<file>.lock``) while open, so two stores
cannot write the same history.
"""

from __future__ import annotations

import json
import os
import threading
from collections.abc import Iterator
from dataclasses import asdict
from pathlib import Path
from typing import IO, Any, cast

from theaios.core.audit import JsonlLog, verify_chain

from theaios.guardrails.flow.types import Code, Denial, Label, Proposal, Provenance

try:  # POSIX
    import fcntl
except ImportError:  # pragma: no cover - Windows: in-process protection only
    fcntl = None  # type: ignore[assignment]


class StoreCorrupted(Exception):
    """The file store's history does not verify: it was edited, truncated, or a write was
    interrupted. The message says which, and what to do."""


class StoreInUse(Exception):
    """Another store has this file open (in this process or another one)."""


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

    def close(self) -> None:  # noqa: B027 - nothing to release in memory
        pass

    def _record(self, event: dict[str, object]) -> None:  # noqa: B027 - hook for subclasses
        pass


def _head_path(path: Path) -> Path:
    return path.with_name(path.name + ".head")


def _lock_path(path: Path) -> Path:
    return path.with_name(path.name + ".lock")


def _entries(path: Path) -> Iterator[dict[str, Any]]:
    with open(path, encoding="utf-8") as f:
        for line in f:
            if line.strip():
                yield json.loads(line)


def _is_json(line: str) -> bool:
    try:
        json.loads(line)
    except ValueError:
        return False
    return True


def check_store(path: str | Path) -> tuple[bool, str]:
    """Verify a flow-state file: its hash chain, and its anchor against truncation.

    Returns ``(ok, message)``. The message says what is wrong and what to do; it is the same
    check ``FileStore`` runs when it opens the file, and ``guardrails flow-verify`` prints it.
    """
    p = Path(path)
    head_p = _head_path(p)
    if not p.exists() and not head_p.exists():
        return False, f"{p}: no such flow-state file"
    if not p.exists():
        return False, (
            f"{p} is missing but its anchor {head_p.name} exists: the history was deleted. "
            "Restore it from backup; starting a new file drops every label and pending "
            "proposal."
        )
    intact, count = verify_chain(p)
    if not intact:
        lines = p.read_text(encoding="utf-8").splitlines()
        content = [line for line in lines if line.strip()]
        last_torn = bool(content) and count == len(content) - 1 and not _is_json(content[-1])
        if last_torn:
            return False, (
                f"{p}: the last line is incomplete (a write was interrupted, for example by a "
                f"crash). The {count} entries before it verify. Remove only that last line "
                "to resume."
            )
        return False, (
            f"{p}: entry {count + 1} does not match the hash chain (it was edited, inserted, "
            f"reordered or corrupted); the {count} entries before it verify. Do not resume "
            "from this file: restore it from backup and investigate."
        )
    if not head_p.exists():
        if count == 0:
            return True, f"{p}: empty, no anchor (new store)"
        return False, (
            f"{p}: {count} entries but no anchor ({head_p.name}). If you moved or copied the "
            "file, bring its .head file with it."
        )
    try:
        head = json.loads(head_p.read_text(encoding="utf-8"))
        expected, expected_hash = int(head["entries"]), str(head["hash"])
    except (ValueError, KeyError, TypeError):
        return False, f"{head_p}: the anchor is unreadable; restore it from backup"
    if count < expected:
        return False, (
            f"{p}: {count} entries, but the anchor records {expected}: the last "
            f"{expected - count} entries were deleted (truncation, log rotation, or tampering). "
            "Do not resume from this file: deleted entries can hold labels or executions."
        )
    if expected:
        at = next((e for i, e in enumerate(_entries(p), start=1) if i == expected), {})
        if at.get("hash") != expected_hash:
            return False, (
                f"{p}: entry {expected} differs from the one the anchor recorded: the history "
                "was rewritten. Restore it from backup and investigate."
            )
    extra = count - expected
    note = f" ({extra} entries written after the last anchor update)" if extra else ""
    return True, f"{p}: intact, {count} entries{note}"


_OPEN: set[str] = set()


class FileStore(MemoryStore):
    """Flow state in an append-only, hash-chained JSONL file, reloaded on start.

    The file and its ``.head`` anchor are created readable by the owner only (0600): they
    hold the arguments of proposed calls. One store per file: a second open raises
    ``StoreInUse`` until the first is closed. Use it as a context manager or call ``close()``.
    """

    def __init__(self, path: str | Path) -> None:
        super().__init__()
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        self._path = p
        self._lock_file: IO[str] | None = None
        self._acquire_lock()
        try:
            if p.exists() or _head_path(p).exists():
                ok, message = check_store(p)
                if not ok:
                    raise StoreCorrupted(message)
            else:
                _create_private(p)
            self._log = JsonlLog(p, chain=True)
            self._count = 0
            self._last_hash = ""
            self._replaying = True
            for entry in self._log.entries():
                self._apply(dict(entry))
                self._count += 1
                self._last_hash = str(entry.get("hash", ""))
            self._replaying = False
            self._write_head()
        except BaseException:
            self.close()
            raise

    @property
    def path(self) -> Path:
        return self._path

    def __enter__(self) -> FileStore:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def __del__(self) -> None:  # release the lock if the store is dropped without close()
        try:
            self.close()
        except Exception:  # noqa: BLE001, S110 - never raise from a finalizer
            pass

    def close(self) -> None:
        f, self._lock_file = getattr(self, "_lock_file", None), None
        if f is not None:
            _OPEN.discard(str(self._path.resolve()))
            f.close()

    def _acquire_lock(self) -> None:
        key = str(self._path.resolve())
        if key in _OPEN:
            raise StoreInUse(f"{self._path} is already open in this process; close it first")
        f = open(_lock_path(self._path), "a", encoding="utf-8")  # noqa: SIM115 - held while open
        if fcntl is not None:
            try:
                fcntl.flock(f.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                f.close()
                raise StoreInUse(f"{self._path} is open in another process") from None
        _OPEN.add(key)
        self._lock_file = f

    def _record(self, event: dict[str, object]) -> None:
        if self._replaying:
            return
        if self._lock_file is None:
            raise StoreInUse(f"{self._path}: this store is closed")
        written = self._log.append(event)
        self._count += 1
        self._last_hash = str(written.get("hash", ""))
        self._write_head()

    def _write_head(self) -> None:
        head = _head_path(self._path)
        tmp = head.with_name(head.name + ".tmp")
        _create_private(tmp)
        tmp.write_text(json.dumps({"entries": self._count, "hash": self._last_hash}), "utf-8")
        os.replace(tmp, head)

    def _apply(self, e: dict[str, object]) -> None:
        kind = e.get("type")
        if kind == "label":
            prov = Provenance(
                tool=str(e["tool"]),
                label=Label(str(e["label"])),
                call_id=str(e["call_id"]),
                at=float(cast(float, e["at"])),
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
                p.decided_by = cast("str | None", e.get("decided_by"))
                p.decided_at = cast("float | None", e.get("decided_at"))
                p.note = str(e.get("note") or "")


def _create_private(path: Path) -> None:
    """Create the file if missing, readable and writable by the owner only."""
    fd = os.open(path, os.O_CREAT | os.O_WRONLY, 0o600)
    os.close(fd)
    os.chmod(path, 0o600)


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
        args=dict(cast("dict[str, object]", e["args"])),
        digest=str(e["digest"]),
        reasons=reasons,
        tier=str(e["tier"]),
        created_at=float(cast(float, e["created_at"])),
        status=str(e["status"]),
        decided_by=cast("str | None", e.get("decided_by")),
        decided_at=cast("float | None", e.get("decided_at")),
        note=str(e.get("note") or ""),
    )
