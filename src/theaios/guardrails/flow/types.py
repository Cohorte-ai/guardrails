"""Types for flow control: tool effects, content labels, admissions, typed denials, proposals."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from theaios.guardrails.types import Effect as Effect
from theaios.guardrails.types import FlowConfig as FlowConfig
from theaios.guardrails.types import Label as Label
from theaios.guardrails.types import ToolSpec as ToolSpec


class Verdict(str, Enum):
    ALLOW = "allow"
    REQUIRE_APPROVAL = "require_approval"
    DENY = "deny"


class Code(str, Enum):
    """Machine-readable reason for a decision that is not a plain allow."""

    UNDECLARED_TOOL = "undeclared_tool"
    UNTRUSTED_TO_WRITE = "untrusted_to_write"
    UNTRUSTED_TO_SEND = "untrusted_to_send"
    SENSITIVE_TO_SEND = "sensitive_to_send"
    RULE_DENY = "rule_deny"
    RULE_APPROVAL = "rule_approval"


@dataclass(frozen=True)
class Provenance:
    """A tool call that put a label into the session."""

    tool: str
    label: Label
    call_id: str
    at: float


@dataclass
class Denial:
    """Why an action was not simply allowed: a code for programs, a sentence for people,
    and the tool calls that caused it."""

    code: Code
    message: str
    provenance: list[Provenance] = field(default_factory=list)


@dataclass
class Proposal:
    """An action frozen for a person to decide. It can be decided once and executed once,
    and only with exactly the arguments that were proposed."""

    id: str
    session_id: str
    tool: str
    args: dict[str, object]
    digest: str
    reasons: list[Denial]
    tier: str
    created_at: float
    status: str = "pending"  # pending | approved | rejected | executed
    decided_by: str | None = None
    decided_at: float | None = None
    note: str = ""


@dataclass
class Admission:
    """The answer to "may this tool call run now?"."""

    verdict: Verdict
    tool: str
    effect: Effect
    reasons: list[Denial] = field(default_factory=list)
    proposal: Proposal | None = None
    labels: frozenset[Label] = frozenset()

    @property
    def allowed(self) -> bool:
        return self.verdict is Verdict.ALLOW

    @property
    def codes(self) -> list[Code]:
        return [r.code for r in self.reasons]


class FlowBlocked(Exception):
    """Raised by guarded tools when an action is denied or waits for approval."""

    def __init__(self, admission: Admission) -> None:
        self.admission = admission
        what = (
            f"waiting for approval (proposal {admission.proposal.id})"
            if admission.proposal is not None
            else "denied"
        )
        reasons = "; ".join(r.message for r in admission.reasons) or "policy"
        super().__init__(f"{admission.tool}: {what}: {reasons}")


class ProposalError(Exception):
    """A proposal cannot be decided or executed (unknown, already decided, not approved,
    already executed, or the arguments changed)."""
