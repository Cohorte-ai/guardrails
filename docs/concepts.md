# Concepts

How theaios-guardrails works under the hood.

---

## The Event Model

Everything in guardrails starts with an **event** — something happening in your agentic system that needs to be evaluated.

```python
GuardEvent(
    scope="action",                    # What kind of event
    agent="sales-agent",               # Which agent
    data={                             # Arbitrary event data
        "action": "send_email",
        "recipient": {"domain": "external.com"},
    },
    session_id="sess-123",             # Optional: for rate limiting
    source_agent="finance-agent",      # Optional: for cross-agent rules
    target_agent="sales-agent",        # Optional: for cross-agent rules
)
```

The `data` dict is freeform — you put whatever fields your rules need. The engine doesn't prescribe a schema. Your rules reference fields with dot notation (`recipient.domain`), and missing fields resolve to `null`.

### Event Scopes

| Scope | When to use | Typical data fields |
|-------|------------|-------------------|
| `input` | A prompt or message going into an agent | `content` |
| `output` | A response coming out of an agent | `content` |
| `action` | An agent performing an action | `action` + action-specific fields |
| `tool_call` | An agent calling a tool | `tool_name`, `arguments` |
| `cross_agent` | One agent talking to another | `message` |

---

## The Three-Tier Approval Model

Guardrails uses a three-tier model for actions that need human oversight:

| Tier | Name | What it means | Example |
|------|------|--------------|---------|
| 1 | **Autonomous** | Agent proceeds without asking | Reading CRM data, searching knowledge base |
| 2 | **Soft approval** | User confirms in the agent UI ("Approve / Reject") | Sending external emails, scheduling meetings |
| 3 | **Strong approval** | Out-of-band verification (email code, 2FA, manager sign-off) | Financial transactions, contract modifications, data exports |

The tier is set per rule:

```yaml
- name: external-email
  then: require_approval
  tier: soft              # Tier 2: user confirms in UI

- name: financial-write
  then: require_approval
  tier: strong            # Tier 3: out-of-band verification
```

When multiple `require_approval` rules match the same event, the **highest tier wins**. Strong beats soft beats autonomous.

---

## Decision Precedence

When multiple rules match a single event, the engine follows a strict precedence:

```
DENY > REQUIRE_APPROVAL > REDACT > ALLOW
```

1. If any rule says DENY → the event is denied. Period.
2. If no DENY but a rule says REQUIRE_APPROVAL → approval is required (highest tier wins).
3. If no DENY or APPROVAL but a rule says REDACT → content is modified.
4. If nothing matches → the event is allowed.

This means you can safely add approval rules without worrying about them overriding deny rules. Security rules always win.

---

## Evaluation Flow

Here's what happens when `engine.evaluate(event)` is called:

```
Event arrives
    │
    ├─ 1. Profile check
    │     Is the agent's action in the profile deny list?
    │     YES → immediate DENY (rules not evaluated)
    │     NO  → continue
    │
    ├─ 2. Rate limit check
    │     Is any rate limit exceeded for this agent?
    │     YES → immediate DENY
    │     NO  → continue
    │
    ├─ 3. Rule evaluation (sorted by severity: critical → high → medium → low)
    │     For each matching rule:
    │       - Does the scope match?
    │       - Does the `when` condition evaluate to true?
    │       - If yes → record the decision
    │
    ├─ 4. Decision resolution
    │     Apply precedence: DENY > REQUIRE_APPROVAL > REDACT > ALLOW
    │
    └─ 5. Return Decision
          outcome, rule, reason, tier, severity, modifications, evaluation_time
```

The entire flow takes <0.01ms for a typical policy with 5-10 rules.

---

## Profiles vs. Rules

Profiles and rules are two layers of defense:

| | Profiles | Rules |
|---|---------|-------|
| **What they control** | Which actions an agent can/cannot perform | Conditions under which events are allowed/denied/modified |
| **Checked** | First (before rules) | Second (after profile) |
| **Granularity** | Action name only (e.g., "commit_pricing") | Any condition on any event field |
| **Override** | Deny is absolute — no rule can override | Rules only add restrictions |

**Example:** The sales-agent profile denies `commit_pricing`. Even if you write a rule that says "allow commit_pricing when manager_approved == true", the profile deny fires first and blocks it. Profiles are the hard boundary.

---

## Dry Run Mode

Dry run evaluates every rule and produces the full decision, but marks it as non-enforcing:

```python
engine = Engine(policy, dry_run=True)
decision = engine.evaluate(event)
# decision.outcome = "deny"  (what WOULD happen)
# decision.dry_run = True    (but not enforced)
```

Use dry run for:

- **Testing new policies** in production before turning them on
- **Compliance validation** — "show me what this policy would block"
- **Shadow mode** — log decisions without affecting agent behavior

The CLI also supports it:

```bash
guardrails check --config policy.yaml --dry-run --event '...'
# Shows DENY [DRY RUN] but exits with code 0
```

---

## Audit Logging

Every evaluation — including ALLOWs — is loggable. This is critical for compliance: you need to prove not just what was blocked, but what was allowed and why.

```python
from theaios.guardrails.audit import AuditLog

audit = AuditLog("audit.jsonl")
decision = engine.evaluate(event)
audit.write(event, decision, policy=policy)
```

Each entry is a single JSON line:

```json
{
  "timestamp": "2026-03-26T14:23:01.123Z",
  "event_id": "uuid",
  "agent": "sales-agent",
  "scope": "action",
  "outcome": "require_approval",
  "rule": "no-external-email-without-approval",
  "tier": "soft",
  "severity": "medium",
  "policy_name": "acme-corp-ai-policy",
  "evaluation_time_ms": 0.02
}
```

The JSONL format is appendable, streamable, and works with `jq`, `grep`, Elasticsearch, Splunk, Datadog, and every log aggregator.

---

## Performance

The engine is designed for inline evaluation — it sits in the hot path between your agent and the outside world.

| Metric | Value |
|--------|-------|
| Average evaluation time | ~0.005ms |
| Throughput | >200,000 evaluations/sec |
| Memory (loaded policy) | ~100KB for 50 rules |
| Dependencies | 3 (pyyaml, click, rich) |

This is possible because the engine does no I/O at evaluation time. All expressions are pre-compiled when the engine is created. All regex patterns are pre-compiled. All profiles are pre-resolved. Evaluation is a pure CPU operation: walk the AST, match patterns, return a decision.

For comparison, LLM-based guardrails (NeMo Guardrails, Lakera Guard) add 100-500ms per check because they call an ML model. Our engine adds 0.005ms — five orders of magnitude faster. This is the difference between "invisible overhead" and "noticeable latency."
