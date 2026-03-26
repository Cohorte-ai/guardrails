"""Guardrails evaluation engine.

Evaluates events against a policy's rules, profiles, and matchers.
Returns a Decision for every event (including ALLOW — for audit completeness).
"""

from __future__ import annotations

import asyncio
import time

from theaios.guardrails.expressions import (
    ASTNode,
    ExpressionError,
    MatcherProtocol,
    compile_expression,
    evaluate as eval_expr,
)
from theaios.guardrails.matchers import Matcher, get_matcher
from theaios.guardrails.profiles import ResolvedProfile, check_profile_permission, resolve_profile
from theaios.guardrails.rate_limit import RateLimiter
from theaios.guardrails.types import (
    SEVERITY_ORDER,
    Decision,
    GuardEvent,
    PolicyConfig,
    RuleConfig,
)


class Engine:
    """Guardrails evaluation engine.

    Parameters
    ----------
    policy : PolicyConfig
        A parsed policy from ``load_policy()``.
    dry_run : bool
        If True, evaluate rules but mark decisions as non-enforcing.
    """

    def __init__(self, policy: PolicyConfig, *, dry_run: bool = False) -> None:
        self._policy = policy
        self._dry_run = dry_run
        self._rate_limiter = RateLimiter()

        # Compile all rule expressions
        self._compiled_rules: list[tuple[RuleConfig, ASTNode]] = []
        for rule in policy.rules:
            if not rule.enabled:
                continue
            try:
                ast = compile_expression(rule.when)
            except ExpressionError as e:
                raise ExpressionError(
                    f"Error in rule '{rule.name}': {e}",
                ) from e
            self._compiled_rules.append((rule, ast))

        # Sort by severity (critical first), preserving declaration order within same severity
        self._compiled_rules.sort(
            key=lambda pair: SEVERITY_ORDER.get(pair[0].severity, 99)
        )

        # Instantiate matchers
        self._matchers: dict[str, Matcher] = {}
        for name, matcher_config in policy.matchers.items():
            self._matchers[name] = get_matcher(matcher_config.type, matcher_config)

        # Resolve profiles
        self._profiles: dict[str, ResolvedProfile] = {}
        for name in policy.profiles:
            self._profiles[name] = resolve_profile(name, policy.profiles)

    @property
    def policy(self) -> PolicyConfig:
        """The loaded policy configuration."""
        return self._policy

    def evaluate(self, event: GuardEvent) -> Decision:
        """Evaluate an event against the policy. Returns a Decision."""
        start = time.perf_counter()

        # 1. Resolve agent profile
        profile = self._profiles.get(event.agent)

        # 2. Check profile deny list for action events
        if profile and event.scope == "action":
            action_name = event.data.get("action")
            if isinstance(action_name, str):
                perm = check_profile_permission(profile, action_name)
                if perm == "deny":
                    elapsed = (time.perf_counter() - start) * 1000
                    return Decision(
                        outcome="deny",
                        rule=None,
                        reason=f"Action '{action_name}' denied by profile '{profile.name}'",
                        severity="high",
                        dry_run=self._dry_run,
                        evaluation_time_ms=elapsed,
                    )

        # 3. Build evaluation context
        context = dict(event.data)
        context["_agent"] = event.agent
        context["_scope"] = event.scope
        context["_session_id"] = event.session_id

        # Wrap matchers for the expression evaluator
        matcher_adapters: dict[str, MatcherProtocol] = {
            name: _MatcherAdapter(matcher) for name, matcher in self._matchers.items()
        }

        # 4. Evaluate rules
        deny_decision: Decision | None = None
        approval_decision: Decision | None = None
        redact_decisions: list[Decision] = []
        matched_rules: list[str] = []

        for rule, ast in self._compiled_rules:
            # Filter by scope
            if rule.scope != event.scope:
                continue

            # Filter cross-agent rules by from/to
            if rule.scope == "cross_agent":
                if rule.from_agent and rule.from_agent != event.source_agent:
                    continue
                if rule.to_agent and rule.to_agent != event.target_agent:
                    continue

            # Check rate limits
            if rule.rate_limit is not None:
                rl_key = self._rate_limit_key(event, rule)
                if not self._rate_limiter.check(rl_key, rule.rate_limit):
                    elapsed = (time.perf_counter() - start) * 1000
                    return Decision(
                        outcome="deny",
                        rule=rule.name,
                        reason=rule.reason or "Rate limit exceeded",
                        severity=rule.severity,
                        dry_run=self._dry_run,
                        evaluation_time_ms=elapsed,
                        matched_rules=[rule.name],
                    )
                # Record usage if rule has rate_limit but no `when` condition
                if not rule.when:
                    self._rate_limiter.record(rl_key, rule.rate_limit)
                    continue

            # Evaluate condition
            try:
                result = eval_expr(
                    ast,
                    context=context,
                    variables=self._policy.variables,
                    matchers=matcher_adapters,
                )
            except ExpressionError:
                continue  # Skip rules with evaluation errors

            if not result:
                continue

            # Rule matched
            matched_rules.append(rule.name)

            # Record rate limit usage on match
            if rule.rate_limit is not None:
                rl_key = self._rate_limit_key(event, rule)
                self._rate_limiter.record(rl_key, rule.rate_limit)

            if rule.then == "deny" and deny_decision is None:
                deny_decision = Decision(
                    outcome="deny",
                    rule=rule.name,
                    reason=rule.reason,
                    severity=rule.severity,
                    dry_run=self._dry_run,
                )

            elif rule.then == "require_approval":
                tier = rule.tier or (profile.default_tier if profile else "soft")
                if approval_decision is None or _tier_rank(tier) > _tier_rank(
                    approval_decision.tier or "autonomous"
                ):
                    approval_decision = Decision(
                        outcome="require_approval",
                        rule=rule.name,
                        reason=rule.reason,
                        tier=tier,
                        severity=rule.severity,
                        dry_run=self._dry_run,
                    )

            elif rule.then == "redact":
                redact_decisions.append(Decision(
                    outcome="redact",
                    rule=rule.name,
                    reason=rule.reason,
                    severity=rule.severity,
                    dry_run=self._dry_run,
                    metadata={"patterns": rule.patterns},
                ))

        elapsed = (time.perf_counter() - start) * 1000

        # 5. Determine final decision (deny > require_approval > redact > allow)
        if deny_decision is not None:
            deny_decision.evaluation_time_ms = elapsed
            deny_decision.matched_rules = matched_rules
            return deny_decision

        if approval_decision is not None:
            approval_decision.evaluation_time_ms = elapsed
            approval_decision.matched_rules = matched_rules
            return approval_decision

        if redact_decisions:
            # Merge all redact decisions
            all_patterns: list[str] = []
            for rd in redact_decisions:
                pats = rd.metadata.get("patterns")
                if isinstance(pats, list):
                    all_patterns.extend(str(p) for p in pats)
            first = redact_decisions[0]
            first.evaluation_time_ms = elapsed
            first.matched_rules = matched_rules
            first.modifications = self._apply_redactions(event, all_patterns)
            return first

        # Default: allow
        return Decision(
            outcome="allow",
            dry_run=self._dry_run,
            evaluation_time_ms=elapsed,
            matched_rules=matched_rules,
        )

    async def evaluate_async(self, event: GuardEvent) -> Decision:
        """Async version of evaluate. Same logic, awaitable for framework adapters."""
        return await asyncio.to_thread(self.evaluate, event)

    def _rate_limit_key(self, event: GuardEvent, rule: RuleConfig) -> str:
        """Build a rate limit key from the event and rule config."""
        if rule.rate_limit is None:
            return ""
        key_field = rule.rate_limit.key
        if key_field == "agent":
            return f"{rule.name}:{event.agent}"
        if key_field == "session":
            return f"{rule.name}:{event.session_id or 'unknown'}"
        # Custom key field from event data
        key_value = event.data.get(key_field, "unknown")
        return f"{rule.name}:{key_value}"

    def _apply_redactions(
        self, event: GuardEvent, pattern_names: list[str],
    ) -> dict[str, str] | None:
        """Apply redactions to event content fields using named matchers."""
        content = event.data.get("content")
        if not isinstance(content, str):
            return None

        redacted = content
        for pname in pattern_names:
            if pname in self._matchers:
                # Pattern name is a matcher name — use the whole matcher
                redacted = self._matchers[pname].redact(redacted)
            else:
                # Pattern name might be a sub-pattern within a matcher
                # (e.g., "ssn" within the "pii" matcher)
                for matcher in self._matchers.values():
                    redacted = matcher.redact(redacted, pattern_name=pname)

        if redacted != content:
            return {"content": redacted}
        return None


class _MatcherAdapter:
    """Adapts a Matcher to the MatcherProtocol expected by the expression evaluator."""

    def __init__(self, matcher: Matcher) -> None:
        self._matcher = matcher

    def match(self, text: str, pattern_name: str | None = None) -> bool:
        return self._matcher.match(text, pattern_name)


def _tier_rank(tier: str) -> int:
    """Return numeric rank for approval tiers (higher = more restrictive)."""
    return {"autonomous": 0, "soft": 1, "strong": 2}.get(tier, 0)
