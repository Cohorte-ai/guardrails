# Writing Policies

A guardrails policy is a single YAML file that defines how your AI agents are governed. It is the source of truth for what agents can and cannot do.

This page is the complete reference. Read it once, then use it as a lookup.

---

## File Structure

Every policy file has these top-level sections:

```yaml
version: "1.0"              # Required. Always "1.0" for now.
metadata:                    # Optional. Who wrote this, when, why.
variables:                   # Optional. Shared values used in rules.
profiles:                    # Optional. Per-agent permission boundaries.
rules:                       # Required. The actual guardrail rules.
matchers:                    # Optional. Named pattern definitions.
```

Only `version` and `rules` are required. Everything else is optional.

---

## Metadata

```yaml
metadata:
  name: acme-corp-ai-policy
  description: AI agent governance policy for ACME Corporation
  author: compliance@acme.com
```

Metadata is for humans and audit logs. The engine doesn't use it for evaluation — it attaches it to audit entries so you can trace which policy version produced a decision.

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | Policy name. Shows in `guardrails inspect` and audit logs. |
| `description` | string | What this policy governs. |
| `author` | string | Who owns this policy. |

---

## Variables

Variables are shared values that rules reference with `$variable_name`. They keep your rules DRY and make it easy to update a value in one place.

```yaml
variables:
  company_domain: "acme.com"
  sensitive_domains: ["finance", "legal", "hr"]
  max_actions_per_minute: 100
```

Use variables in `when` clauses:

```yaml
rules:
  - name: external-email-check
    scope: action
    when: "recipient.domain != $company_domain"
    then: require_approval
```

Variables can be strings, numbers, booleans, or lists. They are substituted at evaluation time, not at parse time — so they work correctly with all operators including `in`.

```yaml
# This works: checks if domain is in the list
when: "resource.domain in $sensitive_domains"
```

---

## Profiles

Profiles define per-agent permission boundaries. They answer: "What is this agent allowed to do, and what is it absolutely forbidden from doing?"

```yaml
profiles:
  default:
    default_tier: autonomous

  sales-agent:
    extends: default
    allow: [read_crm, draft_email, search_knowledge, schedule_meeting]
    deny: [commit_pricing, modify_contract, access_financials]

  finance-agent:
    extends: default
    default_tier: soft
    allow: [read_ledger, generate_report, read_invoices]
    deny: [approve_payment, modify_budget, wire_transfer]
```

### Profile Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `extends` | string | `""` | Parent profile to inherit from. |
| `default_tier` | string | `"autonomous"` | Default approval tier for this agent. One of `autonomous`, `soft`, `strong`. |
| `allow` | list | `[]` | Actions this agent is explicitly permitted to perform. |
| `deny` | list | `[]` | Actions this agent is absolutely forbidden from performing. **Deny always wins.** |

### Inheritance

Profiles can extend other profiles. The child inherits the parent's `allow` and `deny` lists, then adds its own.

```yaml
profiles:
  base:
    allow: [read, search]
  specialized:
    extends: base
    allow: [draft_email]     # Now has: read, search, draft_email
    deny: [read]             # Deny overrides allow — read is now forbidden
```

**Key rule:** If an action appears in both `allow` and `deny` (directly or via inheritance), **deny wins**. This prevents accidental privilege escalation.

### How Profiles Are Evaluated

When an `action` event arrives:

1. The engine looks up the agent's profile by matching `event.agent` to a profile name
2. If the action is in the profile's `deny` list → **immediate DENY** (no rules evaluated)
3. If the action is in the profile's `allow` list → it passes the profile check (rules still evaluate)
4. If the agent has no profile → no profile restrictions apply

Profiles are a **first gate**. Rules are a **second gate**. An action must pass both.

---

## Rules

Rules are the core of the policy. Each rule is a condition-action pair: "when this happens, do this."

```yaml
rules:
  - name: block-prompt-injection
    description: Block detected prompt injection attempts
    scope: input
    when: "content matches prompt_injection"
    then: deny
    reason: "Potential prompt injection detected"
    severity: critical
    enabled: true
    tags: [security, injection]
```

### Rule Fields

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `name` | string | **Yes** | — | Unique identifier. Shows in decisions and audit logs. |
| `scope` | string | **Yes** | — | What event type this rule applies to. |
| `then` | string | **Yes** | — | What to do when the rule matches. |
| `when` | string | No | `""` | Condition expression. Empty = always matches. |
| `description` | string | No | `""` | Human-readable description of the rule's purpose. |
| `reason` | string | No | `""` | Explanation attached to the decision when this rule fires. |
| `severity` | string | No | `"medium"` | Priority level: `critical`, `high`, `medium`, `low`. |
| `tier` | string | No | `""` | Approval tier (only for `require_approval`): `autonomous`, `soft`, `strong`. |
| `enabled` | bool | No | `true` | Set to `false` to disable without deleting. |
| `tags` | list | No | `[]` | Labels for filtering and reporting. |
| `patterns` | list | No | `[]` | Matcher names to use for redaction (only for `redact` rules). |
| `rate_limit` | object | No | `null` | Rate limiting configuration. |
| `from` | string | No | `""` | Source agent (only for `cross_agent` scope). |
| `to` | string | No | `""` | Target agent (only for `cross_agent` scope). |

### Scope

The `scope` field determines what kind of event the rule applies to:

| Scope | What it means | Typical `data` fields |
|-------|--------------|----------------------|
| `input` | A prompt or message being sent to an agent | `content` |
| `output` | A response generated by an agent | `content` |
| `action` | An agent performing an action (tool call, API call, etc.) | `action`, plus action-specific fields |
| `tool_call` | An agent calling a specific tool | `tool_name`, `arguments` |
| `cross_agent` | One agent communicating with another | `message` |

A rule only evaluates against events that match its scope. An `input` rule never fires on an `action` event.

### Outcome (`then`)

| Outcome | What happens | When to use |
|---------|-------------|-------------|
| `deny` | Block the event. The agent cannot proceed. | Security violations, forbidden actions, data leaks. |
| `require_approval` | Pause and request human approval before proceeding. | Sensitive actions, external communications, financial operations. |
| `redact` | Allow the event but modify the content (remove PII, mask data). | Privacy protection, data sanitization. |
| `allow` | Explicitly allow (useful for overriding in specific cases). | Rarely needed — the default is already allow. |
| `log` | Allow but flag for review. | Monitoring, anomaly tracking. |

### Severity

Severity determines evaluation priority. **Higher severity rules fire first.**

| Severity | Priority | Use for |
|----------|----------|---------|
| `critical` | Highest (fires first) | Prompt injection, security breaches |
| `high` | Second | Data leaks, financial operations, PII |
| `medium` | Third | External communications, policy compliance |
| `low` | Lowest (fires last) | Logging, monitoring, informational |

When two rules with the same severity both match, **declaration order** (position in the YAML file) breaks the tie.

### The `when` Clause

The `when` clause is an expression that determines whether the rule fires. See the [Expression Language](expressions.md) page for the full syntax.

Quick examples:

```yaml
# Simple field comparison
when: "action == 'send_email'"

# Nested field access
when: "recipient.domain != $company_domain"

# Pattern matching (references a named matcher)
when: "content matches prompt_injection"

# Boolean logic
when: "action == 'send_email' and recipient.domain != $company_domain"

# List membership
when: "resource.domain in $sensitive_domains"

# String operations
when: "path starts_with 'finance/'"

# Combined
when: "(action == 'write' or action == 'delete') and resource.domain in $sensitive_domains"
```

If `when` is empty or omitted, the rule always matches events of the specified scope.

---

## Rule Types — Detailed Examples

### Deny Rules

Block an event entirely. The agent cannot proceed.

```yaml
- name: block-prompt-injection
  scope: input
  when: "content matches prompt_injection"
  then: deny
  reason: "Potential prompt injection detected"
  severity: critical
```

### Approval Rules

Pause the event and request human approval. Specify the `tier`:

- **`soft`** — the user confirms in the agent's UI (a simple "approve/reject" dialog)
- **`strong`** — out-of-band verification (email code, 2FA, manager approval)

```yaml
- name: external-email-approval
  scope: action
  when: "action == 'send_email' and recipient.domain != $company_domain"
  then: require_approval
  tier: soft
  severity: medium

- name: financial-writes
  scope: action
  when: "action == 'write' and resource.domain in $sensitive_domains"
  then: require_approval
  tier: strong
  severity: high
```

### Redact Rules

Allow the event but modify the content. The `patterns` field lists which matchers to use for redaction.

```yaml
- name: redact-pii-in-output
  scope: output
  when: "content matches pii"
  then: redact
  patterns: [ssn, email_addr, phone]
  severity: high
```

The `patterns` list can reference:

- **Matcher names** (e.g., `pii`) — the entire matcher's redaction is applied
- **Sub-pattern names** within a matcher (e.g., `ssn`, `email_addr`) — only those specific patterns are redacted

### Cross-Agent Rules

Govern communication between agents. Use `from` and `to` to specify which agent pair the rule applies to.

```yaml
- name: no-finance-data-to-sales
  scope: cross_agent
  from: finance-agent
  to: sales-agent
  when: "message matches financial_data"
  then: deny
  reason: "Financial data sharing restricted"
  severity: high
```

- `from` is matched against `event.source_agent`
- `to` is matched against `event.target_agent`
- If `to` is omitted, the rule applies to any target

### Rate Limit Rules

Prevent excessive activity. Rate limits are stateful — the engine tracks event counts per key.

```yaml
- name: rate-limit-actions
  scope: action
  rate_limit:
    max: 100          # Maximum events allowed
    window: 60        # Time window in seconds
    key: agent        # Group by: "agent", "session", or any event data field
  then: deny
  reason: "Rate limit exceeded"
  severity: medium
```

Rate limits check the count before evaluating the `when` clause. If the limit is exceeded, the rule fires regardless of the condition.

| `key` value | Groups by |
|-------------|-----------|
| `agent` | The agent's name (`event.agent`) |
| `session` | The session ID (`event.session_id`) |
| Any other string | A field in `event.data` (e.g., `"user_id"`) |

### Disabled Rules

Set `enabled: false` to keep a rule in the file without it firing. Useful for testing, phased rollouts, or temporarily suspending a rule.

```yaml
- name: strict-output-filter
  scope: output
  when: "content contains 'confidential'"
  then: deny
  severity: high
  enabled: false    # Disabled — will not fire
```

---

## Matchers

Matchers define reusable pattern detection logic. Rules reference them by name in `when` clauses using the `matches` operator.

```yaml
matchers:
  prompt_injection:
    type: keyword_list
    patterns:
      - "ignore previous instructions"
      - "you are now"
      - "disregard above"
      - "system prompt"
    options:
      case_insensitive: true

  pii:
    type: regex
    patterns:
      ssn: "\\b\\d{3}-\\d{2}-\\d{4}\\b"
      email_addr: "\\b[\\w.-]+@[\\w.-]+\\.\\w+\\b"
      phone: "\\b\\d{3}[\\s.-]\\d{3}[\\s.-]\\d{4}\\b"

  financial_data:
    type: keyword_list
    patterns:
      - "revenue"
      - "profit margin"
      - "salary"
    options:
      case_insensitive: true
```

### Matcher Types

| Type | What it does | `patterns` format |
|------|-------------|-------------------|
| `keyword_list` | Substring matching against a list of phrases | List of strings |
| `regex` | Regular expression matching | Dict of `name: pattern` or list of patterns |
| `pii` | Built-in PII detection (SSN, email, phone, credit card, IBAN, IP) | Dict of additional patterns (optional, extends built-in) |

See the [Matchers](matchers.md) page for details on each type and how to write custom matchers.

### Matcher Options

| Option | Applies to | Default | Description |
|--------|-----------|---------|-------------|
| `case_insensitive` | `keyword_list`, `regex` | `false` | Match regardless of case |

---

## Complete Example

A production-ready policy for a professional services firm:

```yaml
version: "1.0"
metadata:
  name: acme-corp-ai-policy
  description: AI agent governance policy for ACME Corporation
  author: compliance@acme.com

variables:
  company_domain: "acme.com"
  internal_domains: ["acme.com", "acme.co.uk", "acme.eu"]
  sensitive_domains: ["finance", "legal", "hr"]

profiles:
  default:
    default_tier: autonomous

  sales-agent:
    extends: default
    allow: [read_crm, draft_email, search_knowledge, schedule_meeting]
    deny: [commit_pricing, modify_contract, access_financials]

  finance-agent:
    extends: default
    default_tier: soft
    allow: [read_ledger, generate_report, read_invoices]
    deny: [approve_payment, modify_budget, wire_transfer]

  hr-agent:
    extends: default
    default_tier: soft
    allow: [read_policies, draft_letter, search_handbook]
    deny: [modify_salary, terminate_employee, access_medical]

rules:
  # === Security ===
  - name: block-prompt-injection
    description: Block detected prompt injection attempts
    scope: input
    when: "content matches prompt_injection"
    then: deny
    reason: "Potential prompt injection detected"
    severity: critical
    tags: [security, injection]

  # === Privacy ===
  - name: redact-pii-in-output
    description: Redact PII from all agent outputs before delivery
    scope: output
    when: "content matches pii"
    then: redact
    patterns: [ssn, email_addr, phone]
    severity: high
    tags: [privacy, pii, compliance]

  # === Communication ===
  - name: no-external-email-without-approval
    description: Emails to external domains require human review
    scope: action
    when: "action == 'send_email' and recipient.domain not in $internal_domains"
    then: require_approval
    tier: soft
    severity: medium
    tags: [compliance, email]

  # === Financial controls ===
  - name: financial-writes-need-strong-approval
    description: Writing to sensitive domains requires manager approval
    scope: action
    when: "action == 'write' and resource.domain in $sensitive_domains"
    then: require_approval
    tier: strong
    severity: high
    tags: [compliance, finance]

  # === Data isolation ===
  - name: no-finance-data-to-sales
    description: Finance agents cannot share raw financial data with sales
    scope: cross_agent
    from: finance-agent
    to: sales-agent
    when: "message matches financial_data"
    then: deny
    reason: "Financial data sharing restricted between these agent roles"
    severity: high
    tags: [data-isolation, compliance]

  # === Safety ===
  - name: rate-limit-actions
    description: Prevent runaway agents from flooding external systems
    scope: action
    rate_limit:
      max: 100
      window: 60
      key: agent
    then: deny
    reason: "Rate limit exceeded — max 100 actions per minute"
    severity: medium
    tags: [safety, rate-limit]

matchers:
  prompt_injection:
    type: keyword_list
    patterns:
      - "ignore previous instructions"
      - "ignore all previous"
      - "you are now"
      - "disregard above"
      - "system prompt"
      - "reveal your instructions"
      - "override safety"
      - "jailbreak"
    options:
      case_insensitive: true

  pii:
    type: regex
    patterns:
      ssn: "\\b\\d{3}-\\d{2}-\\d{4}\\b"
      email_addr: "\\b[\\w.-]+@[\\w.-]+\\.\\w+\\b"
      phone: "\\b\\d{3}[\\s.-]\\d{3}[\\s.-]\\d{4}\\b"
      credit_card: "\\b\\d{4}[\\s-]?\\d{4}[\\s-]?\\d{4}[\\s-]?\\d{4}\\b"

  financial_data:
    type: keyword_list
    patterns:
      - "revenue"
      - "profit margin"
      - "quarterly earnings"
      - "salary"
      - "compensation"
      - "operating income"
    options:
      case_insensitive: true
```

---

## Evaluation Order

Understanding how the engine evaluates rules is important for writing predictable policies.

1. **Profile check** — if the agent has a profile and the action is in `deny` → immediate DENY
2. **Rate limit check** — if any rate limit rule is exceeded → immediate DENY
3. **Rules evaluated by severity** — `critical` first, then `high`, `medium`, `low`
4. **Within same severity** — declaration order (position in the YAML file)
5. **First DENY wins** — engine short-circuits, no further rules evaluated
6. **If no DENY** — highest-tier REQUIRE_APPROVAL wins
7. **If no DENY or APPROVAL** — all REDACT decisions are merged
8. **If nothing matches** — default is **ALLOW**

!!! tip "Default is ALLOW"
    If no rule matches, the event is allowed. Guardrails add restrictions on top of your existing authorization layer — they don't replace it. Your auth system handles "who can do what." Guardrails handle "what should never happen."

---

## Tips for Writing Good Policies

**Start small.** Begin with 3-5 critical rules (injection blocking, PII redaction, external communication approval). Add more as you learn what your agents actually do.

**Use severity honestly.** Critical means "if this fires, something dangerous was about to happen." Don't make everything critical — it dilutes the signal.

**Name rules clearly.** The rule name shows up in every decision and audit entry. `block-prompt-injection` is better than `rule-1`.

**Use tags for organization.** Tags let you filter rules in `guardrails inspect --tag compliance` and in audit queries. Group by concern: `security`, `privacy`, `compliance`, `safety`.

**Use variables for values that change.** Company domains, rate limits, sensitive department lists — put them in `variables` so policy updates don't require editing every rule.

**Test with dry run.** Before enforcing a new policy in production, run with `dry_run=True` to see what would be blocked without actually blocking it.

**Version in git.** The YAML file is the policy. Treat it like code: pull requests, reviews, blame history. When an auditor asks "why was this agent blocked last Tuesday?", the answer is in the git log.
