"""Flow control for LangChain 1.x agents (``create_agent``) and Deep Agents, as middleware.

Requires ``langchain>=1.0`` and ``langgraph>=1.0``: ``pip install "theaios-guardrails[langchain-agent]"``.

Every tool call the model makes goes through :meth:`FlowGuard.admit` before it runs:

- **allowed**: the tool runs and the call is observed into the session (taint);
- **denied**: the tool does not run; the model gets an error ``ToolMessage`` with the reason
  (the run continues), and the structured decision rides in its ``artifact``;
- **approval required**: the run pauses with a LangGraph ``interrupt`` carrying the frozen
  proposal; resume with ``Command(resume={"proposal_id": ..., "approve": True, "by":
  "alice"})``. An approved call runs exactly as proposed, once; a rejected one does not run.

The session is the LangGraph ``thread_id`` (approval needs a checkpointer anyway). The agent is
``agent=`` or the agent name the application gave the graph (``create_agent(name=...)``). The
model chooses the tool and its arguments, which are checked; it never chooses the session or
the agent.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from typing import Any

from theaios.guardrails.flow.guard import FlowGuard
from theaios.guardrails.flow.types import Admission, Proposal, ProposalError, Verdict

try:
    from langchain.agents.middleware import AgentMiddleware, ToolCallRequest
    from langchain_core.messages import ToolMessage
    from langgraph.errors import GraphBubbleUp
    from langgraph.types import Command, interrupt
except ImportError as e:  # pragma: no cover - exercised only without the extra
    raise ImportError(
        "The LangChain agent middleware needs langchain>=1.0 and langgraph>=1.0. "
        'Install with: pip install "theaios-guardrails[langchain-agent]"'
    ) from e

APPROVAL_TYPE = "theaios.approval"
COMPONENT = "guardrails"

Handler = Callable[[ToolCallRequest], "ToolMessage | Command[Any]"]
AsyncHandler = Callable[[ToolCallRequest], Awaitable["ToolMessage | Command[Any]"]]


class FlowMiddleware(AgentMiddleware):  # type: ignore[type-arg, unused-ignore]
    """Admit every tool call through a :class:`FlowGuard`.

    Parameters
    ----------
    guard : FlowGuard
        The guard (one per process; its store holds taint and proposals).
    agent : str, optional
        The agent name passed to your rules and profiles. Default: the graph's name
        (``create_agent(name=...)``, Deep Agents sub-agent names), else ``"default"``.
    session : callable, optional
        ``session(request) -> str``. Default: the LangGraph ``thread_id``. A call without a
        session is refused: taint and approval are per session.
    """

    def __init__(
        self,
        guard: FlowGuard,
        *,
        agent: str | None = None,
        session: Callable[[ToolCallRequest], str] | None = None,
    ) -> None:
        super().__init__()
        if not isinstance(guard, FlowGuard):
            raise TypeError("FlowMiddleware needs a FlowGuard")
        self._guard = guard
        self._agent = agent
        self._session = session

    # LangChain calls one or the other depending on how the agent is invoked.

    def wrap_tool_call(
        self, request: ToolCallRequest, handler: Handler
    ) -> ToolMessage | Command[Any]:
        ready = self._before(request)
        if isinstance(ready, ToolMessage):
            return ready
        try:
            result = handler(request)
        except GraphBubbleUp:  # paused inside the tool (or LangGraph control flow): not done
            raise
        except BaseException:
            self._after(ready, ran=True)
            raise
        self._after(ready, ran=not _refused_inside(result))
        return result

    async def awrap_tool_call(
        self, request: ToolCallRequest, handler: AsyncHandler
    ) -> ToolMessage | Command[Any]:
        ready = self._before(request)
        if isinstance(ready, ToolMessage):
            return ready
        try:
            result = await handler(request)
        except GraphBubbleUp:
            raise
        except BaseException:
            self._after(ready, ran=True)
            raise
        self._after(ready, ran=not _refused_inside(result))
        return result

    # ------------------------------------------------------------------------------------

    def _after(self, ready: _Ready, *, ran: bool) -> None:
        """Record the outcome: a call that ran is observed (taint) and its proposal executed;
        a call another check refused inside did not run (not observed, proposal superseded)."""
        if ran:
            self._guard.observe(ready.session, ready.tool, call_id=ready.call_id or None)
        if ready.proposal_id:
            note = "" if ran else "approved, but refused by another check before it ran"
            self._guard.finish(ready.proposal_id, ran=ran, note=note)

    def _before(self, request: ToolCallRequest) -> ToolMessage | _Ready:
        """Admit the call. Returns a refusal to give the model, or what to record once the
        tool ran. May pause the run for approval (``interrupt``)."""
        call = request.tool_call
        tool, args, call_id = str(call["name"]), call.get("args") or {}, str(call.get("id") or "")
        session = self._session_of(request)
        if not session:
            return _refusal(
                call,
                "no session: run the agent with a thread_id (config={'configurable': "
                "{'thread_id': ...}})",
                codes=["no_session"],
            )
        if not isinstance(args, Mapping):
            return _refusal(call, "tool arguments must be an object", codes=["bad_arguments"])
        args = dict(args)

        # The run paused inside this very call after it was approved and claimed (a
        # sub-agent asked a person too): it resumes, it does not need a second approval.
        if call_id:
            claimed = self._guard.executing(session, call_id)
            if claimed is not None:
                if claimed.tool != tool or claimed.args != args:
                    return _refusal(
                        call,
                        f"proposal {claimed.id} is executing for other arguments",
                        codes=["proposal"],
                    )
                # LangGraph matches resume values to interrupt() calls by order: take this
                # call's slot again (it returns the decision already given, without pausing),
                # or an interrupt inside the tool would receive our decision as its own.
                resumed = interrupt(self._ask(claimed, session, request))
                if _check_decision(resumed, claimed.id) or not resumed["approve"]:
                    self._guard.finish(claimed.id, ran=False, note="the resumed decision changed")
                    return _refusal(
                        call,
                        f"proposal {claimed.id}: the resumed run does not carry its approval",
                        codes=["bad_decision"],
                    )
                return _Ready(session, tool, call_id, claimed.id)

        try:
            admission = self._guard.admit(session, tool, args, agent=self._agent_of(request))
        except (TypeError, ValueError) as exc:  # arguments that are not plain JSON
            return _refusal(call, f"arguments refused: {exc}", codes=["bad_arguments"])

        if admission.verdict is Verdict.ALLOW:
            return _Ready(session, tool, call_id, None)
        if admission.verdict is Verdict.DENY or admission.proposal is None:
            return _refusal(call, _reasons_text(admission), admission=admission)

        # Approval. LangGraph runs this node again on resume, so everything above runs twice:
        # admit() answers with the same pending proposal, and interrupt() then returns the
        # decision instead of pausing.
        proposal = admission.proposal
        decision = interrupt(self._ask(proposal, session, request))
        problem = _check_decision(decision, proposal.id)
        if problem:
            # The run moves on without this call: nobody waits for this proposal any more.
            self._guard.retire(proposal.id, note=f"the run moved on: {problem}")
            return _refusal(call, problem, admission=admission, codes=["bad_decision"])
        assert isinstance(decision, Mapping)
        by, note = decision["by"], str(decision.get("note") or "")
        try:
            if not decision["approve"]:
                # A "no" always means no, and is recorded, even over an approval made elsewhere.
                current = self._guard.proposal(proposal.id)
                if current is not None and current.status in ("pending", "approved"):
                    self._guard.withdraw(proposal.id, by=by, note=note)
                suffix = f": {note}" if note else ""
                return _refusal(
                    call,
                    f"proposal {proposal.id} rejected by {by}{suffix}",
                    admission=admission,
                    codes=["rejected"],
                )
            current = self._guard.proposal(proposal.id)
            if current is not None and current.status == "pending":
                current = self._guard.decide(proposal.id, approve=True, by=by, note=note)
            if current is None or current.status != "approved":
                status = current.status if current is not None else "unknown"
                who = f" by {current.decided_by}" if current and current.decided_by else ""
                why = f": {current.note}" if current and current.note else ""
                return _refusal(
                    call,
                    f"proposal {proposal.id} {status}{who}{why}",
                    admission=admission,
                    codes=[status],
                )
            self._guard.claim(proposal.id, tool, args, call_id=call_id or None)
        except ProposalError as exc:
            return _refusal(call, str(exc), admission=admission, codes=["proposal"])
        return _Ready(session, tool, call_id, proposal.id if call_id else None)

    def _ask(self, proposal: Proposal, session: str, request: ToolCallRequest) -> dict[str, object]:
        """The interrupt payload: everything a person (or an approval UI) needs."""
        return {
            "type": APPROVAL_TYPE,
            "component": COMPONENT,
            "proposal_id": proposal.id,
            "session": session,
            "agent": self._agent_of(request),
            "tool": proposal.tool,
            "args": proposal.args,
            "tier": proposal.tier,
            "reasons": [{"code": r.code.value, "message": r.message} for r in proposal.reasons],
        }

    def _session_of(self, request: ToolCallRequest) -> str:
        if self._session is not None:
            return str(self._session(request) or "")
        config = getattr(request.runtime, "config", None) or {}
        thread = (config.get("configurable") or {}).get("thread_id")
        return str(thread) if thread else ""

    def _agent_of(self, request: ToolCallRequest) -> str:
        if self._agent:
            return self._agent
        config = getattr(request.runtime, "config", None) or {}
        name = (config.get("metadata") or {}).get("lc_agent_name")
        return str(name) if name else "default"


@dataclass(frozen=True)
class _Ready:
    """A call cleared to run, and what to record once it did."""

    session: str
    tool: str
    call_id: str
    proposal_id: str | None


def _refused_inside(result: object) -> bool:
    """Did another theaios check inside this one refuse the call (so the tool did not run)?"""
    if not (isinstance(result, ToolMessage) and result.status == "error"):
        return False
    artifact = result.artifact if isinstance(result.artifact, Mapping) else {}
    detail = artifact.get("theaios")
    return isinstance(detail, Mapping) and detail.get("component") != COMPONENT


def _check_decision(decision: object, proposal_id: str) -> str:
    """Why a resume value is not a usable decision for this proposal ('' if it is)."""
    if not isinstance(decision, Mapping):
        return (
            "the run was resumed without a decision: resume with {'proposal_id': ..., "
            "'approve': True|False, 'by': '<who>'}"
        )
    if decision.get("proposal_id") != proposal_id:
        named = decision.get("proposal_id")
        return (
            f"the decision is for proposal {named!r}, but this call waits for proposal "
            f"{proposal_id}"
        )
    if type(decision.get("approve")) is not bool:
        return "the decision's 'approve' must be true or false"
    by = decision.get("by")
    if not isinstance(by, str) or not by.strip():
        return "the decision must say who decided ('by')"
    return ""


def _reasons_text(admission: Admission) -> str:
    return "; ".join(r.message for r in admission.reasons) or "denied by policy"


def _refusal(
    call: Mapping[str, Any],
    message: str,
    *,
    admission: Admission | None = None,
    codes: list[str] | None = None,
) -> ToolMessage:
    """What the model sees instead of the tool's result; the decision rides in ``artifact``."""
    detail: dict[str, object] = {
        "component": COMPONENT,
        "verdict": "deny",
        "codes": codes
        if codes is not None
        else [c.value for c in (admission.codes if admission else [])],
        "reason": message,
    }
    if admission is not None and admission.proposal is not None:
        detail["proposal_id"] = admission.proposal.id
    return ToolMessage(
        content=f"Blocked by guardrails: {message}",
        name=str(call.get("name") or ""),
        tool_call_id=str(call.get("id") or ""),
        status="error",
        artifact={"theaios": detail},
    )
