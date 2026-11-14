# LangChain agents (middleware)

For agents built with LangChain 1.x `create_agent` or with Deep Agents, flow control runs as
middleware: every tool call the model makes is admitted by your `FlowGuard` before it runs.

```bash
pip install "theaios-guardrails[langchain-agent]"
```

```python
from langchain.agents import create_agent
from langgraph.checkpoint.memory import InMemorySaver
from theaios.guardrails.config import load_policy
from theaios.guardrails.flow import FlowGuard, FileStore
from theaios.guardrails.adapters.langchain_agent import FlowMiddleware

guard = FlowGuard(load_policy("guardrails.yaml"), store=FileStore("flow.log"))

agent = create_agent(
    "openai:gpt-4.1-mini",
    tools=[read_inbox, send_email],
    middleware=[FlowMiddleware(guard)],
    checkpointer=InMemorySaver(),   # approval pauses the run: it needs a checkpointer
    name="assistant",               # the agent name your rules see (as _agent)
)
config = {"configurable": {"thread_id": "ticket-4711"}}  # the session: taint is per thread
```

## What happens to each tool call

| Admission | The tool | The model sees | The run |
|---|---|---|---|
| allow | runs, then the call is observed (taint) | the result | continues |
| deny | does not run | an error `ToolMessage` with the reason | continues |
| approval required | does not run yet | nothing yet | pauses (`interrupt`) |

A denial's structured decision is in the `ToolMessage`'s `artifact["theaios"]` (component,
codes, reason, proposal id), which is not sent to the model.

## Approving

When a call needs approval, the run pauses with one interrupt:

```python
out = agent.invoke({"messages": [("user", "answer the customer")]}, config, version="v2")
ask = out.interrupts[0].value
# {"type": "theaios.approval", "component": "guardrails", "proposal_id": "...",
#  "session": "ticket-4711", "tool": "send_email", "args": {...}, "tier": "soft",
#  "reasons": [{"code": "untrusted_to_send", "message": "..."}]}
```

Show `tool`, `args` and `reasons` to a person, then resume with their decision:

```python
from langgraph.types import Command

agent.invoke(Command(resume={"proposal_id": ask["proposal_id"], "approve": True,
                             "by": "alice", "note": "checked the address"}),
             config, version="v2")
```

- The decision must name the proposal and say who decided; `approve` must be `True` or
  `False` (not the string `"true"`). Anything else is refused and the tool does not run.
- An approved call runs exactly as proposed, once (`FlowGuard.claim`). A `False` always means
  the tool does not run, even if someone approved the proposal elsewhere meanwhile.
- You can also decide out of band (`guard.decide(...)`, for example from an approval
  dashboard) and then resume with the same decision.
- The session stays tainted after an approval: the next send asks again.

## Who is who

- **Session**: the LangGraph `thread_id` (or `session=lambda request: ...`). A tool call
  without a session is refused.
- **Agent**: `FlowMiddleware(guard, agent="...")`, or the graph's name (`create_agent(name=...)`,
  Deep Agents sub-agent names). Rules see it as `_agent`, profiles by name.
- The model chooses the tool and its arguments (checked); never the session or the agent.

## Deep Agents sub-agents

Deep Agents does not pass the main agent's middleware to its sub-agents. Add `FlowMiddleware`
to each sub-agent's `middleware`, sharing the same guard so taint is shared across the thread:

```python
subagents = [{"name": "researcher", "description": "...", "tools": [search_web],
              "middleware": [FlowMiddleware(guard)]}]
agent = create_deep_agent(model, tools, subagents=subagents, middleware=[FlowMiddleware(guard)],
                          checkpointer=saver, name="assistant")
```

## With agent-auth and agent-monitor

The middlewares compose; the first in the list is the outermost:

```python
middleware=[MonitorMiddleware(monitor), AgentAuthMiddleware(engine), FlowMiddleware(guard)]
```

The monitor sees every outcome, authorization decides who may call the tool, flow control
decides whether the session may call it now.
