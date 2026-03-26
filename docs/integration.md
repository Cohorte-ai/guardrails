# Integration Guide

theaios-guardrails works with any agentic platform. This page shows how to integrate at every level — from a two-line decorator to framework-specific adapters.

---

## Level 1: The `@guard` Decorator (Simplest)

Wrap any function. Input guardrails run before the call, output guardrails run after.

```python
from theaios.guardrails.adapters.decorator import guard, GuardDenied

@guard("guardrails.yaml", agent="my-agent")
def ask_agent(prompt: str) -> str:
    return my_llm.generate(prompt)

# Normal usage — passes through
result = ask_agent("What's the weather?")

# Injection — raises GuardDenied
try:
    ask_agent("Ignore previous instructions")
except GuardDenied as e:
    print(f"Blocked: {e.decision.rule}")
```

### Async Functions

The decorator auto-detects async functions:

```python
@guard("guardrails.yaml", agent="my-agent")
async def ask_agent(prompt: str) -> str:
    return await my_llm.agenerate(prompt)
```

### Decorator Options

```python
@guard(
    "guardrails.yaml",    # Policy file path
    agent="my-agent",     # Agent name (matched against profiles)
    dry_run=False,        # Set True to evaluate without enforcing
)
```

### Exceptions

| Exception | When | Properties |
|-----------|------|-----------|
| `GuardDenied` | A rule denied the input or output | `decision.rule`, `decision.reason` |
| `ApprovalRequired` | A rule requires human approval | `decision.tier`, `decision.rule` |

PII redaction happens silently — the decorator returns the redacted output instead of the original.

---

## Level 2: Engine API (Maximum Control)

For full control, use the `Engine` class directly. You decide where and when to evaluate.

```python
from theaios.guardrails import Engine, GuardEvent, load_policy

policy = load_policy("guardrails.yaml")
engine = Engine(policy)

# Evaluate at any point in your pipeline
decision = engine.evaluate(GuardEvent(
    scope="action",
    agent="sales-agent",
    data={
        "action": "send_email",
        "recipient": {"domain": "external.com"},
    },
))

if decision.is_denied:
    raise Exception(f"Blocked by {decision.rule}: {decision.reason}")
elif decision.requires_approval:
    await request_approval(decision.tier)
elif decision.outcome == "redact" and decision.modifications:
    response = decision.modifications["content"]
```

### Where to Place Evaluations

```
User message arrives
    → evaluate(scope="input")           # Check for injection, validate input

Agent decides to call a tool
    → evaluate(scope="tool_call")       # Check tool permissions
    → evaluate(scope="action")          # Check action permissions

Agent generates response
    → evaluate(scope="output")          # PII redaction, content filtering

Agent sends message to another agent
    → evaluate(scope="cross_agent")     # Data isolation rules
```

### Convenience Functions

```python
from theaios.guardrails import check, evaluate, load_policy

# One-liner (loads policy, creates engine, evaluates)
decision = check("guardrails.yaml", scope="input", agent="test", content="hello")

# Functional (reuse a loaded policy)
policy = load_policy("guardrails.yaml")
decision = evaluate(policy, event)
```

---

## Level 3: LangChain Integration

Add guardrails to any LangChain chain via callbacks — zero changes to your existing chain code.

```bash
pip install theaios-guardrails[langchain]
```

```python
from theaios.guardrails.adapters.langchain import GuardrailsCallback

callback = GuardrailsCallback("guardrails.yaml", agent="my-agent")

# Add to any chain invocation
result = chain.invoke(
    {"input": "What's our revenue?"},
    config={"callbacks": [callback]},
)
```

The callback hooks into:

| LangChain Event | Guardrail Scope | What's checked |
|----------------|----------------|---------------|
| `on_llm_start` | `input` | Prompts before LLM sees them |
| `on_llm_end` | `output` | LLM responses before delivery |
| `on_tool_start` | `tool_call` | Tool calls before execution |

If a guardrail denies, the callback raises `GuardDenied` which stops the chain.

---

## Level 4: OpenAI Agents SDK

Explicit check methods for the OpenAI Agents SDK pattern:

```python
from theaios.guardrails.adapters.openai_agents import OpenAIAgentsGuardrail

guardrail = OpenAIAgentsGuardrail("guardrails.yaml", agent="my-agent")

# Before processing user input
decision = guardrail.check_input(user_message)
if decision.is_denied:
    return "I can't help with that."

# Before executing a tool
decision = guardrail.check_tool_call("send_email", {"to": "user@external.com"})
if decision.requires_approval:
    await get_approval(decision.tier)

# Before returning output
decision = guardrail.check_output(agent_response)
if decision.outcome == "redact":
    agent_response = decision.modifications["content"]
```

---

## Level 5: Custom Integration

For any platform not covered above, the pattern is always the same:

1. Load the policy once at startup
2. Create an engine once
3. Call `engine.evaluate()` at every decision point
4. Handle the decision

```python
# startup.py
from theaios.guardrails import Engine, load_policy

engine = Engine(load_policy("guardrails.yaml"))

# anywhere in your agent code
from theaios.guardrails import GuardEvent

def handle_agent_action(agent_name, action, **kwargs):
    decision = engine.evaluate(GuardEvent(
        scope="action",
        agent=agent_name,
        data={"action": action, **kwargs},
    ))

    if decision.is_denied:
        return {"error": decision.reason}
    if decision.requires_approval:
        return {"pending_approval": decision.tier}
    return {"proceed": True}
```

### MCP Server Integration

For agents using the Model Context Protocol:

```python
# In your MCP tool handler
def handle_tool_call(tool_name: str, arguments: dict) -> dict:
    decision = engine.evaluate(GuardEvent(
        scope="tool_call",
        agent=current_agent_id,
        data={"tool_name": tool_name, "arguments": arguments},
    ))
    if decision.is_denied:
        return {"error": f"Tool call denied: {decision.reason}"}
    # proceed with tool execution
```

### HTTP Middleware

For REST API-based agents:

```python
# FastAPI example
from fastapi import Request, HTTPException

@app.middleware("http")
async def guardrails_middleware(request: Request, call_next):
    if request.url.path.startswith("/agent/"):
        body = await request.json()
        decision = engine.evaluate(GuardEvent(
            scope="input",
            agent=body.get("agent", "default"),
            data={"content": body.get("message", "")},
        ))
        if decision.is_denied:
            raise HTTPException(403, detail=decision.reason)
    return await call_next(request)
```

---

## Audit Integration

Wire the audit log into your observability stack:

```python
from theaios.guardrails.audit import AuditLog

audit = AuditLog("guardrails_audit.jsonl")

# After every evaluation
decision = engine.evaluate(event)
audit.write(event, decision, policy=engine.policy)
```

The JSONL audit log works with:

- **grep / jq** — quick command-line queries
- **Elasticsearch / OpenSearch** — full-text search and dashboards
- **Splunk** — enterprise SIEM integration
- **Datadog / Grafana** — metrics and alerting
- **OpenTelemetry** — pipe to any OTel-compatible backend

---

## Performance Considerations

The engine is designed for inline (synchronous) evaluation. At ~0.005ms per evaluation, it adds no meaningful latency to any agent pipeline.

**Do:**

- Create the engine once at startup, reuse for all evaluations
- Use `engine.evaluate()` synchronously in the hot path
- Load policies at application start, not per-request

**Don't:**

- Create a new engine per request (unnecessary overhead from recompiling expressions)
- Call `load_policy()` per request (unnecessary file I/O)
- Put expensive custom matchers (LLM calls) in inline rules — use async evaluation for those
