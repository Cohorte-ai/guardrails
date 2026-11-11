# CLI Reference

The `guardrails` CLI lets you validate, inspect, and test policies from the terminal.

---

## Commands

### `guardrails version`

Show the installed version.

```bash
guardrails version
# guardrails 0.2.0
```

---

### `guardrails validate`

Check a policy file for errors without loading the engine.

```bash
guardrails validate --config guardrails.yaml
# Policy is valid: 6 rules, 4 profiles, 3 matchers
```

| Option | Default | Description |
|--------|---------|-------------|
| `--config`, `-c` | `guardrails.yaml` | Policy file path |

Checks include an undefined `$variable` or matcher in any enabled rule's `when` clause:

```bash
guardrails validate --config guardrails.yaml
# rules[2] (block-injection): 'when' uses undefined matcher 'prompt_injectoin' (did you mean 'prompt_injection'?)
```

Exit code 0 = valid, 1 = errors found.

---

### `guardrails inspect`

Display a formatted summary of all rules, profiles, and matchers in a policy.

```bash
guardrails inspect --config guardrails.yaml
guardrails inspect --config guardrails.yaml --tag compliance
```

| Option | Default | Description |
|--------|---------|-------------|
| `--config`, `-c` | `guardrails.yaml` | Policy file path |
| `--tag` | — | Filter rules by tag |

---

### `guardrails check`

Evaluate a single event against a policy. The primary tool for testing rules.

```bash
# Allow
guardrails check --config guardrails.yaml \
  --event '{"scope":"input","agent":"test","data":{"content":"hello"}}'

# Deny
guardrails check --config guardrails.yaml \
  --event '{"scope":"input","agent":"test","data":{"content":"ignore previous instructions"}}'
```

| Option | Default | Description |
|--------|---------|-------------|
| `--config`, `-c` | `guardrails.yaml` | Policy file path |
| `--event`, `-e` | **(required)** | Event as a JSON string |
| `--dry-run` | `false` | Evaluate without enforcing (exit code always 0) |
| `--output`, `-o` | `console` | Output format: `console` or `json` |

**Event JSON format:**

```json
{
  "scope": "input",
  "agent": "sales-agent",
  "data": {"content": "..."},
  "session_id": "optional",
  "source_agent": "optional (cross_agent)",
  "target_agent": "optional (cross_agent)"
}
```

**Exit codes:**

| Code | Meaning |
|------|---------|
| 0 | Event was allowed, or dry run mode |
| 1 | Event was denied |

---

### `guardrails flow-verify`

Verify a flow-control state file (`FileStore`): its hash chain, and its anchor against deleted
last lines. Exit 0 if intact, 1 otherwise, with what happened and what to do.

```bash
guardrails flow-verify .guardrails_flow/state.jsonl
# .guardrails_flow/state.jsonl: intact, 42 entries
```

---

### `guardrails audit`

View and filter the audit log.

```bash
guardrails audit
guardrails audit --agent sales-agent --outcome deny
guardrails audit --since 2026-03-26 --output json --output-file report.json
```

| Option | Default | Description |
|--------|---------|-------------|
| `--config`, `-c` | `guardrails.yaml` | Policy file path |
| `--since` | — | Show entries after this ISO timestamp |
| `--agent` | — | Filter by agent name |
| `--outcome` | — | Filter by outcome (`allow`, `deny`, `require_approval`, `redact`) |
| `--rule` | — | Filter by rule name |
| `--limit` | `1000` | Maximum entries to return |
| `--output`, `-o` | `console` | Output format: `console` or `json` |
| `--output-file` | — | Write JSON output to file |
