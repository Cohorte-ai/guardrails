"""Flow control: decide at dispatch whether a tool call may run, given what the session has seen.

The rule it enforces (the "lethal trifecta" made structural): once a session has read
content someone else wrote (UNTRUSTED), it may not write or send without a person's approval;
once it has read private data (SENSITIVE), it may not send without a person's approval. The
labels come from the tools' declarations, not from inspecting content, so a prompt injection
cannot talk its way past them. Approval is per action: a person approves one frozen call,
which code then executes exactly as proposed; the session stays tainted.
"""

from __future__ import annotations

import fnmatch
import hashlib
import json
import time
import uuid
from collections.abc import Callable
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
from theaios.guardrails.types import GuardEvent

if TYPE_CHECKING:
    from theaios.guardrails.engine import Engine
    from theaios.guardrails.types import PolicyConfig

T = TypeVar("T")

_TIER_RANK = {"autonomous": 0, "soft": 1, "strong": 2}


def args_digest(tool: str, args: dict[str, object]) -> str:
    """SHA-256 of the tool name and arguments in canonical JSON."""
    canonical = json.dumps(
        {"tool": tool, "args": args}, sort_keys=True, separators=(",", ":"), default=str
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class FlowGuard:
    """Admission control for tool calls, with durable taint and frozen proposals.

    Parameters
    ----------
    policy : PolicyConfig
        A policy with a ``tools:`` section (and optionally ``flow:``). Its rules and profiles
        also apply: each call is evaluated as an ``action`` event first.
    store : MemoryStore, optional
        Where labels and proposals live. Default: in memory. Use ``FileStore(path)`` to keep
        state across restarts in a hash-chained log.
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
        """The declaration for a tool: exact name first, then the first matching glob."""
        if tool in self._tools:
            return self._tools[tool]
        for pattern, spec in self._tools.items():
            if any(c in pattern for c in "*?[") and fnmatch.fnmatchcase(tool, pattern):
                return spec
        return None

    def _effective(self, tool: str) -> tuple[ToolSpec, bool]:
        spec = self.spec(tool)
        if spec is not None:
            return spec, True
        return ToolSpec(name=tool, effect=Effect.SEND, returns=frozenset({Label.UNTRUSTED})), False

    # Session state ---------------------------------------------------------------------

    def labels(self, session_id: str) -> frozenset[Label]:
        return frozenset(p.label for p in self._store.provenance(session_id))

    def observe(self, session_id: str, tool: str, *, call_id: str | None = None) -> list[Label]:
        """Record that a tool call returned into the session. Call it after every tool call
        (``call`` and ``execute`` do it for you). Returns the labels added."""
        spec, _ = self._effective(tool)
        cid = call_id or uuid.uuid4().hex[:12]
        now = time.time()
        added = sorted(spec.returns, key=lambda label: label.value)
        for label in added:
            self._store.add_label(session_id, Provenance(tool, label, cid, now))
        return added

    def clear(self, session_id: str, *, by: str, reason: str) -> None:
        """Forget a session's labels (for example at the start of a new task). Recorded with
        who did it and why."""
        if not by or not reason:
            raise ValueError("clear() needs who is clearing the session and why")
        self._store.clear(session_id, by, reason)

    # Admission -------------------------------------------------------------------------

    def admit(
        self,
        session_id: str,
        tool: str,
        args: dict[str, object] | None = None,
        *,
        agent: str = "default",
    ) -> Admission:
        """May this call run now? ALLOW, REQUIRE_APPROVAL (with a proposal), or DENY."""
        args = dict(args or {})
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

        # Rules and profiles first: an explicit deny wins over everything.
        decision = self._engine.evaluate(
            GuardEvent(
                scope="action",
                agent=agent,
                data={**args, "action": tool},
                session_id=session_id,
            )
        )
        if decision.is_denied:
            return Admission(
                Verdict.DENY,
                tool,
                spec.effect,
                [
                    Denial(
                        Code.RULE_DENY,
                        decision.reason or f"denied by rule '{decision.rule}'",
                    )
                ],
                labels=labels,
            )

        reasons: list[Denial] = []
        tier = "autonomous"
        if decision.requires_approval:
            reasons.append(
                Denial(
                    Code.RULE_APPROVAL,
                    decision.reason or f"rule '{decision.rule}' requires approval",
                )
            )
            tier = decision.tier or "soft"

        flow_reasons = self._flow_reasons(session_id, tool, spec, declared)
        if flow_reasons and self._config.on_block == "deny":
            return Admission(Verdict.DENY, tool, spec.effect, flow_reasons, labels=labels)
        if flow_reasons:
            reasons += flow_reasons
            tier = _max_tier(tier, self._config.approval_tier)

        if not reasons:
            return Admission(Verdict.ALLOW, tool, spec.effect, labels=labels)

        proposal = Proposal(
            id=uuid.uuid4().hex,
            session_id=session_id,
            tool=tool,
            args=args,
            digest=args_digest(tool, args),
            reasons=reasons,
            tier=tier,
            created_at=time.time(),
        )
        self._store.save_proposal(proposal)
        return Admission(
            Verdict.REQUIRE_APPROVAL, tool, spec.effect, reasons, proposal, labels=labels
        )

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

    def pending(self, session_id: str | None = None) -> list[Proposal]:
        return [p for p in self._store.proposals(session_id) if p.status == "pending"]

    def decide(self, proposal_id: str, *, approve: bool, by: str, note: str = "") -> Proposal:
        """A person approves or rejects a proposal. Once: a decided proposal cannot be
        decided again."""
        if not by:
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
            return p

    def execute(
        self,
        proposal_id: str,
        fn: Callable[..., T],
        args: dict[str, object] | None = None,
    ) -> T:
        """Run an approved proposal: ``fn(**args)`` with exactly the proposed arguments, at
        most once. Passing ``args`` that differ from the proposal is refused. The result is
        observed into the session like any tool call."""
        with self._store.lock:
            p = self._store.get_proposal(proposal_id)
            if p is None:
                raise ProposalError(f"unknown proposal {proposal_id}")
            if p.status != "approved":
                raise ProposalError(f"proposal {proposal_id} is {p.status}, not approved")
            call_args = dict(p.args) if args is None else dict(args)
            if args_digest(p.tool, call_args) != p.digest:
                raise ProposalError(
                    f"arguments differ from what was approved for proposal {proposal_id}"
                )
            # Marked before running: at most once, even if the call fails.
            p.status = "executed"
            self._store.update_proposal(p)
        result = fn(**call_args)
        self.observe(p.session_id, p.tool, call_id=p.id)
        return result

    # Convenience -----------------------------------------------------------------------

    def call(
        self,
        session_id: str,
        tool: str,
        fn: Callable[..., T],
        *,
        agent: str = "default",
        **args: Any,
    ) -> T:
        """Admit, run, observe. Raises ``FlowBlocked`` (with the admission and, when
        approval is possible, its proposal) instead of running a blocked call."""
        admission = self.admit(session_id, tool, args, agent=agent)
        if not admission.allowed:
            raise FlowBlocked(admission)
        result = fn(**args)
        self.observe(session_id, tool)
        return result

    def tool(
        self, name: str | None = None, *, session: Callable[[], str]
    ) -> Callable[[Callable[..., T]], Callable[..., T]]:
        """Decorator: ``@guard.tool("send_email", session=lambda: current_session_id)``.
        Calls go through :meth:`call`; arguments must be passed by keyword."""

        def wrap(fn: Callable[..., T]) -> Callable[..., T]:
            tool_name = name or fn.__name__

            def wrapper(**kwargs: Any) -> T:
                return self.call(session(), tool_name, fn, **kwargs)

            wrapper.__name__ = getattr(fn, "__name__", tool_name)
            wrapper.__doc__ = fn.__doc__
            return wrapper

        return wrap


def _names(prov: list[Provenance]) -> str:
    seen: list[str] = []
    for p in prov:
        if p.tool not in seen:
            seen.append(p.tool)
    return ", ".join(seen)


def _max_tier(a: str, b: str) -> str:
    return a if _TIER_RANK.get(a, 0) >= _TIER_RANK.get(b, 0) else b
