# Python API Reference

## Core Functions

### `load_policy(path) → PolicyConfig`

Load and validate a YAML policy file.

```python
from theaios.guardrails import load_policy

policy = load_policy("guardrails.yaml")
```

Raises `FileNotFoundError` if the file doesn't exist, `ConfigError` if validation fails.

---

### `evaluate(policy, event, dry_run=False) → Decision`

Evaluate a single event against a policy. Creates an engine internally — for repeated evaluations, use the `Engine` class directly.

```python
from theaios.guardrails import evaluate, load_policy, GuardEvent

policy = load_policy("guardrails.yaml")
decision = evaluate(policy, GuardEvent(scope="input", agent="test", data={"content": "hello"}))
```

---

### `check(policy_path, scope, agent, **data) → Decision`

One-liner convenience function. Loads the policy, builds an event from keyword arguments, and evaluates.

```python
from theaios.guardrails import check

decision = check("guardrails.yaml", scope="input", agent="test", content="hello")
```

---

## Engine

### `Engine(policy, dry_run=False)`

The main evaluation engine. Create once, evaluate many times.

```python
from theaios.guardrails import Engine, load_policy

engine = Engine(load_policy("guardrails.yaml"))
```

On construction, the engine:

- Compiles all `when` expressions into ASTs
- Instantiates all matchers from config
- Resolves all profile inheritance chains
- Sorts rules by severity

This work happens once. Subsequent `evaluate()` calls are pure computation.

### `engine.evaluate(event) → Decision`

Evaluate an event synchronously. Returns a `Decision`.

### `engine.evaluate_async(event) → Decision`

Async version of `evaluate()`. Same logic, awaitable for use in async frameworks.

---

## Data Types

### `GuardEvent`

```python
@dataclass
class GuardEvent:
    scope: str                          # "input", "output", "action", "tool_call", "cross_agent"
    agent: str                          # Agent identifier
    data: dict[str, object]             # Event data (fields referenced in when clauses)
    timestamp: float | None = None
    session_id: str | None = None
    source_agent: str | None = None     # For cross_agent scope
    target_agent: str | None = None     # For cross_agent scope
```

### `Decision`

```python
@dataclass
class Decision:
    outcome: str                        # "allow", "deny", "require_approval", "redact", "log"
    rule: str | None = None             # Which rule fired (None if default allow)
    reason: str | None = None           # Human-readable explanation
    tier: str | None = None             # "autonomous", "soft", "strong" (for require_approval)
    severity: str | None = None
    modifications: dict[str, str] | None = None  # Redacted content (for redact)
    dry_run: bool = False
    evaluation_time_ms: float = 0.0
    matched_rules: list[str]            # All rules that matched (not just the winning one)
```

**Properties:**

| Property | Type | Description |
|----------|------|-------------|
| `is_allowed` | bool | True if outcome is "allow" or "log" |
| `is_denied` | bool | True if outcome is "deny" |
| `requires_approval` | bool | True if outcome is "require_approval" |

---

## Matchers

### `register_matcher(name)`

Decorator to register a custom matcher class.

```python
from theaios.guardrails.matchers import Matcher, register_matcher

@register_matcher("my_matcher")
class MyMatcher(Matcher):
    def match(self, text, pattern_name=None):
        return "bad" in text
```

### `get_matcher(name, config) → Matcher`

Instantiate a registered matcher by name.

### `list_matchers() → list[str]`

Return all registered matcher type names.

---

## Exceptions

| Exception | Module | When |
|-----------|--------|------|
| `ConfigError` | `theaios.guardrails.config` | Policy file is invalid |
| `ExpressionError` | `theaios.guardrails.expressions` | Expression cannot be parsed or evaluated |
| `GuardDenied` | `theaios.guardrails.adapters.decorator` | `@guard` decorator: rule denied the event |
| `ApprovalRequired` | `theaios.guardrails.adapters.decorator` | `@guard` decorator: rule requires approval |
