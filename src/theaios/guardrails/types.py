"""Shared data models for the Guardrails engine."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Outcome(Enum):
    """Possible outcomes of a guardrail evaluation."""

    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"
    REDACT = "redact"
    LOG = "log"


class Tier(Enum):
    """Approval tier for require_approval outcomes."""

    AUTONOMOUS = "autonomous"
    SOFT = "soft"
    STRONG = "strong"


class Severity(Enum):
    """Rule severity levels, ordered from lowest to highest."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Scope(Enum):
    """Event scopes that rules can match against."""

    INPUT = "input"
    OUTPUT = "output"
    ACTION = "action"
    TOOL_CALL = "tool_call"
    CROSS_AGENT = "cross_agent"


VALID_SCOPES = {s.value for s in Scope}
VALID_OUTCOMES = {o.value for o in Outcome}
VALID_TIERS = {t.value for t in Tier}
VALID_SEVERITIES = {s.value for s in Severity}

SEVERITY_ORDER: dict[str, int] = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
}


# ---------------------------------------------------------------------------
# Event & Decision (runtime)
# ---------------------------------------------------------------------------


@dataclass
class GuardEvent:
    """An event to evaluate against guardrail rules.

    Represents something happening in the agentic system: an input prompt,
    an output response, a tool call, an action, or cross-agent communication.
    """

    scope: str
    agent: str
    data: dict[str, object] = field(default_factory=dict)
    timestamp: float | None = None
    session_id: str | None = None
    source_agent: str | None = None
    target_agent: str | None = None


@dataclass
class Decision:
    """Result of evaluating an event against guardrail rules."""

    outcome: str
    rule: str | None = None
    reason: str | None = None
    tier: str | None = None
    severity: str | None = None
    modifications: dict[str, str] | None = None
    metadata: dict[str, object] = field(default_factory=dict)
    dry_run: bool = False
    evaluation_time_ms: float = 0.0
    matched_rules: list[str] = field(default_factory=list)

    @property
    def is_allowed(self) -> bool:
        """True if the outcome is allow or log."""
        return self.outcome in ("allow", "log")

    @property
    def is_denied(self) -> bool:
        """True if the outcome is deny."""
        return self.outcome == "deny"

    @property
    def requires_approval(self) -> bool:
        """True if the outcome requires human approval."""
        return self.outcome == "require_approval"


# ---------------------------------------------------------------------------
# Policy configuration (parsed from YAML)
# ---------------------------------------------------------------------------


@dataclass
class RateLimitConfig:
    """Rate limiting configuration for a rule."""

    max: int
    window: int  # seconds
    key: str = "agent"


@dataclass
class RuleConfig:
    """A single guardrail rule."""

    name: str
    scope: str
    then: str
    description: str = ""
    when: str = ""
    reason: str = ""
    severity: str = "medium"
    tier: str = ""
    enabled: bool = True
    tags: list[str] = field(default_factory=list)
    patterns: list[str] = field(default_factory=list)
    rate_limit: RateLimitConfig | None = None
    from_agent: str = ""
    to_agent: str = ""


@dataclass
class ProfileConfig:
    """An agent permission profile."""

    name: str
    extends: str = ""
    default_tier: str = "autonomous"
    allow: list[str] = field(default_factory=list)
    deny: list[str] = field(default_factory=list)


@dataclass
class MatcherConfig:
    """Configuration for a named matcher."""

    name: str
    type: str
    patterns: dict[str, str] | list[str] = field(default_factory=list)
    options: dict[str, object] = field(default_factory=dict)


@dataclass
class PolicyMetadata:
    """Policy-level metadata."""

    name: str = ""
    description: str = ""
    author: str = ""


@dataclass
class PolicyConfig:
    """Top-level policy configuration — maps 1:1 to guardrails.yaml."""

    version: str = "1.0"
    metadata: PolicyMetadata = field(default_factory=PolicyMetadata)
    variables: dict[str, object] = field(default_factory=dict)
    profiles: dict[str, ProfileConfig] = field(default_factory=dict)
    rules: list[RuleConfig] = field(default_factory=list)
    matchers: dict[str, MatcherConfig] = field(default_factory=dict)
