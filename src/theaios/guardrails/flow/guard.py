"""Flow control: decide at dispatch whether a tool call may run, given what the session has seen.

The rule it enforces (the "lethal trifecta" made structural): once a session has read
content someone else wrote (UNTRUSTED), it may not write or send without a person's approval;
once it has read private data (SENSITIVE), it may not send without a person's approval. The
labels come from the tools' declarations, not from inspecting content, so a prompt injection
cannot talk its way past them. Approval is per action: a person approves one frozen call,
which code then executes exactly as proposed; the session stays tainted.
"""

from __future__ import annotations

import copy
import fnmatch
import functools
import hashlib
import inspect
import json
import time
import uuid
from collections.abc import Callable, Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from theaios.guardrails.flow.store import MemoryStore
from theaios.guardrails.flow.types import (
    Admission,
    Code,
    Denial,
    Effect,
    FlowBlocked,
    FlowConfig,
    Label,
    Proposal,
    ProposalError,
    Provenance,
    ToolSpec,
    Verdict,
)
from theaios.guardrails.types import Decision, GuardEvent

if TYPE_CHECKING:
    from theaios.guardrails.engine import Engine
    from theaios.guardrails.types import PolicyConfig

T = TypeVar("T")

_TIER_RANK = {"autonomous": 0, "soft": 1, "strong": 2}
_EFFECT_RANK = {Effect.READ: 0, Effect.WRITE: 1, Effect.SEND: 2}
MAX_ARGS_BYTES = 1_000_000


def args_digest(tool: str, args: Mapping[str, object]) -> str:
    """SHA-256 of the tool name and arguments in canonical JSON. Arguments must be JSON
    (strings, numbers, booleans, null, lists, string-keyed objects); anything else raises
    ``ValueError``, because its contents could change without changing the digest."""
    if not isinstance(args, Mapping):
        raise ValueError(f"arguments of '{tool}' must be a mapping of parameter names to values")
    _check_keys(tool, args)
    try:
        canonical = json.dumps(
            {"tool": tool, "args": dict(args)},
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
    except (TypeError, ValueError, RecursionError) as exc:
        raise ValueError(
            f"arguments of '{tool}' must be plain JSON values (got {exc}); convert objects "
            "to dicts or strings before admitting the call"
        ) from None
    data = canonical.encode("utf-8")
    if len(data) > MAX_ARGS_BYTES:
        raise ValueError(
            f"arguments of '{tool}' are {len(data):,} bytes; the limit is {MAX_ARGS_BYTES:,} "
            "(pass a reference, such as a file id, instead of the content)"
        )
    return hashlib.sha256(data).hexdigest()


def _check_keys(tool: str, value: object, depth: int = 0) -> None:
    """Objects must have string keys: JSON would silently turn 1 and True into "1" and "true",
    so two different calls could share a digest."""
    if depth > 100:
        raise ValueError(f"arguments of '{tool}' are nested more than 100 levels deep")
    if isinstance(value, Mapping):
        for k, v in value.items():
            if not isinstance(k, str):
                raise ValueError(
                    f"arguments of '{tool}' must be plain JSON values: key {k!r} is not a string"
                )
            _check_keys(tool, v, depth + 1)
    elif isinstance(value, (list, tuple)):
        for v in value:
            _check_keys(tool, v, depth + 1)


class FlowGuard:
    """Admission control for tool calls, with durable taint and frozen proposals.

    Create one guard per process (or per store) and keep it: taint lives in its store, so a
    guard created per request with the default in-memory store forgets what was read.

    Parameters
    ----------
    policy : PolicyConfig
        A policy with a ``tools:`` section (and optionally ``flow:``). Its rules and profiles
        also apply: each call is evaluated as an ``action`` event and as a ``tool_call``
        event first.
    store : MemoryStore, optional
        Where labels and proposals live. Default: in memory. Use ``FileStore(path)`` to keep
        state across restarts in a hash-chained, anchored log.
    engine : Engine, optional
        The rule engine to consult. Default: ``Engine(policy)``.
    """

    def __init__(
        self,
        policy: PolicyConfig,
        *,
        store: MemoryStore | None = None,
        engine: Engine | None = None,
    ) -> None:
        from theaios.guardrails.engine import Engine as _Engine

        self._policy = policy
        self._config: FlowConfig = policy.flow
        self._tools: dict[str, ToolSpec] = dict(policy.tools)
        self._store = store if store is not None else MemoryStore()
        self._engine = engine if engine is not None else _Engine(policy)

    @property
    def store(self) -> MemoryStore:
        return self._store

    # Declarations ----------------------------------------------------------------------

    def spec(self, tool: str) -> ToolSpec | None:
        """The declaration that applies to a tool. An exact name wins. Otherwise every
        matching glob counts, conservatively: the most restrictive effect and all their
        labels, so the order of the globs in the file never matters."""
        if tool in self._tools:
            return self._tools[tool]
        matching = [
            spec
            for pattern, spec in self._tools.items()
            if any(c in pattern for c in "*?[") and fnmatch.fnmatchcase(tool, pattern)
        ]
        if not matching:
            return None
        if len(matching) == 1:
            return matching[0]
        effect = max((s.effect for s in matching), key=lambda e: _EFFECT_RANK[e])
        returns = frozenset().union(*(s.returns for s in matching))
        names = " + ".join(s.name for s in matching)
        return ToolSpec(name=names, effect=effect, returns=returns)

    def _effective(self, tool: str) -> tuple[ToolSpec, bool]:
        spec = self.spec(tool)
        if spec is not None:
            return spec, True
        return ToolSpec(name=tool, effect=Effect.SEND, returns=frozenset({Label.UNTRUSTED})), False

    # Session state ---------------------------------------------------------------------

    def labels(self, session_id: str) -> frozenset[Label]:
        return frozenset(p.label for p in self._store.provenance(session_id))

    def observe(self, session_id: str, tool: str, *, call_id: str | None = None) -> list[Label]:
        """Record that a tool call ran in the session, whatever its result (including an
        error: its message can carry the same content). ``call``, the ``tool`` decorator and
        ``execute`` do it for you. Returns the labels added."""
        spec, _ = self._effective(tool)
        cid = call_id or uuid.uuid4().hex[:12]
        now = time.time()
        added = sorted(spec.returns, key=lambda label: label.value)
        for label in added:
            self._store.add_label(session_id, Provenance(tool, label, cid, now))
        return added

    def clear(self, session_id: str, *, by: str, reason: str) -> None:
        """Forget a session's labels (for example at the start of a new task). Recorded with
        who did it and why. Pending proposals stay pending: a person still decides them."""
        if not by.strip() or not reason.strip():
            raise ValueError("clear() needs who is clearing the session and why")
        self._store.clear(session_id, by, reason)

    # Admission -------------------------------------------------------------------------

    def admit(
        self,
        session_id: str,
        tool: str,
        args: Mapping[str, object] | None = None,
        *,
        agent: str = "default",
    ) -> Admission:
        """May this call run now? ALLOW, REQUIRE_APPROVAL (with a proposal), or DENY.

        ``agent`` is passed to your rules and profiles; taint is per ``session_id`` only."""
        args = dict(args or {})
        digest = args_digest(tool, args)  # also refuses arguments that are not plain JSON
        spec, declared = self._effective(tool)
        labels = self.labels(session_id)

        if not declared and self._config.undeclared == "deny":
            return Admission(
                Verdict.DENY,
                tool,
                spec.effect,
                [
                    Denial(
                        Code.UNDECLARED_TOOL,
                        f"'{tool}' is not declared in the policy's tools section",
                    )
                ],
                labels=labels,
            )

        # Rules and profiles first, on both documented event shapes: an explicit deny wins.
        decisions = [
            self._engine.evaluate(
                GuardEvent(
                    scope="action",
                    agent=agent,
                    data={**args, "action": tool},
                    session_id=session_id,
                )
            ),
            self._engine.evaluate(
                GuardEvent(
                    scope="tool_call",
                    agent=agent,
                    data={"tool_name": tool, "arguments": args},
                    session_id=session_id,
                )
            ),
        ]
        denied = next((d for d in decisions if d.is_denied), None)
        if denied is not None:
            return Admission(
                Verdict.DENY,
                tool,
                spec.effect,
                [Denial(Code.RULE_DENY, denied.reason or f"denied by rule '{denied.rule}'")],
                labels=labels,
            )

        reasons: list[Denial] = []
        tier = "autonomous"
        for d in decisions:
            if d.requires_approval:
                reasons.append(Denial(Code.RULE_APPROVAL, _approval_message(d)))
                tier = _max_tier(tier, d.tier or "soft")

        flow_reasons = self._flow_reasons(session_id, tool, spec, declared)
        if flow_reasons and self._config.on_block == "deny":
            return Admission(Verdict.DENY, tool, spec.effect, flow_reasons, labels=labels)
        if flow_reasons:
            reasons += flow_reasons
            tier = _max_tier(tier, self._config.approval_tier)

        if not reasons:
            return Admission(Verdict.ALLOW, tool, spec.effect, labels=labels)

        # The same call for the same reasons, still waiting in this session: answer with its
        # proposal instead of queueing a duplicate a person could approve twice. If the reasons
        # changed (the session read something since), a new proposal states them.
        with self._store.lock:
            for existing in self._store.proposals(session_id):
                if (
                    existing.digest == digest
                    and existing.status == "pending"
                    and existing.tier == tier
                    and [r.code for r in existing.reasons] == [r.code for r in reasons]
                ):
                    return Admission(
                        Verdict.REQUIRE_APPROVAL,
                        tool,
                        spec.effect,
                        existing.reasons,
                        existing,
                        labels=labels,
                    )
            # An older pending proposal for the same call states outdated reasons: retire it,
            # so the same call cannot be approved and run twice.
            for existing in self._store.proposals(session_id):
                if existing.digest == digest and existing.status == "pending":
                    existing.status = "superseded"
                    existing.note = "superseded: the reasons changed"
                    self._store.update_proposal(existing)
            return self._new_proposal(
                session_id, tool, args, digest, reasons, tier, spec.effect, labels
            )

    def _new_proposal(
        self,
        session_id: str,
        tool: str,
        args: dict[str, object],
        digest: str,
        reasons: list[Denial],
        tier: str,
        effect: Effect,
        labels: frozenset[Label],
    ) -> Admission:
        proposal = Proposal(
            id=uuid.uuid4().hex,
            session_id=session_id,
            tool=tool,
            args=json.loads(json.dumps(args)),  # a deep copy: later changes cannot leak in
            digest=digest,
            reasons=reasons,
            tier=tier,
            created_at=time.time(),
        )
        self._store.save_proposal(proposal)
        return Admission(Verdict.REQUIRE_APPROVAL, tool, effect, reasons, proposal, labels=labels)

    def _flow_reasons(
        self, session_id: str, tool: str, spec: ToolSpec, declared: bool
    ) -> list[Denial]:
        if spec.effect is Effect.READ:
            return []
        provenance = self._store.provenance(session_id)
        untrusted = [p for p in provenance if p.label is Label.UNTRUSTED]
        sensitive = [p for p in provenance if p.label is Label.SENSITIVE]
        note = "" if declared else f" ('{tool}' is undeclared, so it is treated as a send)"
        reasons: list[Denial] = []
        if untrusted:
            sources = _names(untrusted)
            if spec.effect is Effect.WRITE:
                reasons.append(
                    Denial(
                        Code.UNTRUSTED_TO_WRITE,
                        f"the session read untrusted content ({sources}); a write needs approval",
                        untrusted,
                    )
                )
            else:
                reasons.append(
                    Denial(
                        Code.UNTRUSTED_TO_SEND,
                        f"the session read untrusted content ({sources}); a send needs "
                        f"approval{note}",
                        untrusted,
                    )
                )
        if sensitive and spec.effect is Effect.SEND:
            reasons.append(
                Denial(
                    Code.SENSITIVE_TO_SEND,
                    f"the session read sensitive data ({_names(sensitive)}); a send needs "
                    f"approval{note}",
                    sensitive,
                )
            )
        return reasons

    # Proposals -------------------------------------------------------------------------

    def proposal(self, proposal_id: str) -> Proposal | None:
        """A copy of a proposal by id, whatever its status."""
        p = self._store.get_proposal(proposal_id)
        return copy.deepcopy(p) if p is not None else None

    def pending(self, session_id: str | None = None) -> list[Proposal]:
        """Copies of the proposals waiting for a decision."""
        return [
            copy.deepcopy(p) for p in self._store.proposals(session_id) if p.status == "pending"
        ]

    def decide(self, proposal_id: str, *, approve: bool, by: str, note: str = "") -> Proposal:
        """A person approves or rejects a proposal. Once: a decided proposal cannot be
        decided again."""
        if not by.strip():
            raise ValueError("decide() needs who decided")
        with self._store.lock:
            p = self._store.get_proposal(proposal_id)
            if p is None:
                raise ProposalError(f"unknown proposal {proposal_id}")
            if p.status != "pending":
                raise ProposalError(f"proposal {proposal_id} was already {p.status}")
            p.status = "approved" if approve else "rejected"
            p.decided_by, p.decided_at, p.note = by, time.time(), note
            self._store.update_proposal(p)
            return copy.deepcopy(p)

    def execute(self, proposal_id: str, tools: Mapping[str, Callable[..., T]]) -> T:
        """Run an approved proposal: the function registered under the approved tool name in
        ``tools``, called with exactly the proposed arguments, at most once. The call is
        observed into the session like any other, even if it raises."""
        if not isinstance(tools, Mapping):
            raise TypeError(
                "execute() takes a mapping of tool names to functions, e.g. "
                "{'send_email': send_email}, so only the approved tool can run"
            )
        with self._store.lock:
            p = self._store.get_proposal(proposal_id)
            if p is None:
                raise ProposalError(f"unknown proposal {proposal_id}")
            if p.status != "approved":
                raise ProposalError(f"proposal {proposal_id} is {p.status}, not approved")
            fn = tools.get(p.tool)
            # A function decorated with @guard.tool would admit itself again: run the original.
            fn = getattr(fn, "_flow_original", fn)
            if fn is None:
                raise ProposalError(
                    f"proposal {proposal_id} is for '{p.tool}', which is not in the tools "
                    "you passed"
                )
            if args_digest(p.tool, p.args) != p.digest:
                raise ProposalError(f"proposal {proposal_id}: stored arguments were altered")
            # Marked before running: at most once, even if the call fails.
            p.status = "executed"
            self._store.update_proposal(p)
        try:
            return fn(**json.loads(json.dumps(p.args)))
        finally:
            self.observe(p.session_id, p.tool, call_id=p.id)

    # Convenience -----------------------------------------------------------------------

    def call(
        self,
        session_id: str,
        tool: str,
        fn: Callable[..., T],
        args: Mapping[str, object] | None = None,
        *,
        agent: str = "default",
    ) -> T:
        """Admit, run ``fn(**args)``, observe (also when ``fn`` raises). Raises
        ``FlowBlocked`` (with the admission and, when approval is possible, its proposal)
        instead of running a blocked call."""
        call_args = dict(args or {})
        admission = self.admit(session_id, tool, call_args, agent=agent)
        if not admission.allowed:
            raise FlowBlocked(admission)
        try:
            return fn(**call_args)
        finally:
            self.observe(session_id, tool)

    def tool(
        self, name: str | None = None, *, session: Callable[[], str], agent: str = "default"
    ) -> Callable[[Callable[..., T]], Callable[..., T]]:
        """Decorator: ``@guard.tool("send_email", session=lambda: current_session_id)``.
        Positional and keyword arguments are both accepted; the call goes through
        :meth:`call` with them bound to the function's parameter names."""

        def wrap(fn: Callable[..., T]) -> Callable[..., T]:
            tool_name = name or fn.__name__
            signature = inspect.signature(fn)
            variadic = [
                p.name
                for p in signature.parameters.values()
                if p.kind in (p.VAR_POSITIONAL, p.VAR_KEYWORD)
            ]
            if variadic:
                raise TypeError(
                    f"@guard.tool needs named parameters: '{tool_name}' takes "
                    f"{', '.join('*' + v for v in variadic)}, which an approved call could not "
                    "replay exactly"
                )

            @functools.wraps(fn)
            def wrapper(*a: Any, **kw: Any) -> T:
                bound = signature.bind(*a, **kw)
                return self.call(session(), tool_name, fn, dict(bound.arguments), agent=agent)

            wrapper._flow_original = fn  # type: ignore[attr-defined]
            return wrapper

        return wrap


def _approval_message(d: Decision) -> str:
    return d.reason or f"rule '{d.rule}' requires approval"


def _names(prov: list[Provenance]) -> str:
    seen: list[str] = []
    for p in prov:
        if p.tool not in seen:
            seen.append(p.tool)
    return ", ".join(seen)


def _max_tier(a: str, b: str) -> str:
    return a if _TIER_RANK.get(a, 0) >= _TIER_RANK.get(b, 0) else b
