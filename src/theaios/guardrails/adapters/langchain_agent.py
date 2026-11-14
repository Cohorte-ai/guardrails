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
from typing import Any

from theaios.guardrails.flow.guard import FlowGuard
from theaios.guardrails.flow.types import Admission, ProposalError, Verdict

try:
    from langchain.agents.middleware import AgentMiddleware, ToolCallRequest
    from langchain_core.messages import ToolMessage
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
        session, tool, call_id = ready
        try:
            return handler(request)
        finally:
            self._guard.observe(session, tool, call_id=call_id)

    async def awrap_tool_call(
        self, request: ToolCallRequest, handler: AsyncHandler
    ) -> ToolMessage | Command[Any]:
        ready = self._before(request)
        if isinstance(ready, ToolMessage):
            return ready
        session, tool, call_id = ready
        try:
            return await handler(request)
        finally:
            self._guard.observe(session, tool, call_id=call_id)

    # ------------------------------------------------------------------------------------

    def _before(self, request: ToolCallRequest) -> ToolMessage | tuple[str, str, str]:
        """Admit the call. Returns a refusal to give the model, or (session, tool, call id)
        when the tool may run now. May pause the run for approval (``interrupt``)."""
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
        try:
            admission = self._guard.admit(session, tool, dict(args), agent=self._agent_of(request))
        except (TypeError, ValueError) as exc:  # arguments that are not plain JSON
            return _refusal(call, f"arguments refused: {exc}", codes=["bad_arguments"])

        if admission.verdict is Verdict.ALLOW:
            return session, tool, call_id
        if admission.verdict is Verdict.DENY or admission.proposal is None:
            return _refusal(call, _reasons_text(admission), admission=admission)

        # Approval. LangGraph runs this node again on resume, so everything above runs twice:
        # admit() answers with the same pending proposal, and interrupt() then returns the
        # decision instead of pausing.
        proposal = admission.proposal
        decision = interrupt(
            {
                "type": APPROVAL_TYPE,
                "component": COMPONENT,
                "proposal_id": proposal.id,
                "session": session,
                "tool": tool,
                "args": proposal.args,
                "tier": proposal.tier,
                "reasons": [{"code": r.code.value, "message": r.message} for r in proposal.reasons],
            }
        )
        problem = _check_decision(decision, proposal.id)
        if problem:
            return _refusal(call, problem, admission=admission, codes=["bad_decision"])
        assert isinstance(decision, Mapping)
        current = self._guard.proposal(proposal.id)
        if not decision["approve"]:
            # A "no" always means no, even if the proposal was approved elsewhere meanwhile.
            if current is not None and current.status == "pending":
                current = self._guard.decide(
                    proposal.id,
                    approve=False,
                    by=decision["by"],
                    note=str(decision.get("note") or ""),
                )
            note = f": {decision.get('note')}" if decision.get("note") else ""
            return _refusal(
                call,
                f"proposal {proposal.id} rejected by {decision['by']}{note}",
                admission=admission,
                codes=["rejected"],
            )
        try:
            if current is not None and current.status == "pending":
                current = self._guard.decide(
                    proposal.id,
                    approve=decision["approve"],
                    by=decision["by"],
                    note=str(decision.get("note") or ""),
                )
            if current is None or current.status != "approved":
                status = current.status if current is not None else "unknown"
                who = f" by {current.decided_by}" if current and current.decided_by else ""
                note = f": {current.note}" if current and current.note else ""
                return _refusal(
                    call,
                    f"proposal {proposal.id} {status}{who}{note}",
                    admission=admission,
                    codes=[status],
                )
            self._guard.claim(proposal.id, tool, dict(args))
        except ProposalError as exc:
            return _refusal(call, str(exc), admission=admission, codes=["proposal"])
        return session, tool, call_id

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


def _check_decision(decision: object, proposal_id: str) -> str:
    """Why a resume value is not a usable decision for this proposal ('' if it is)."""
    if not isinstance(decision, Mapping):
        return (
            "the run was resumed without a decision: resume with {'proposal_id': ..., "
            "'approve': True|False, 'by': '<who>'}"
        )
    if decision.get("proposal_id") != proposal_id:
        return f"the decision does not name proposal {proposal_id}"
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
