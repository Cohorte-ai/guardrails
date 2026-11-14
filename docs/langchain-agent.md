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
    name="assistant",               # the agent name your rules see (as agent)
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

When a call needs approval, the run pauses with an interrupt:

```python
out = agent.invoke({"messages": [("user", "answer the customer")]}, config, version="v2")
ask = out.interrupts[0].value
# {"type": "theaios.approval", "component": "guardrails", "proposal_id": "...",
#  "session": "ticket-4711", "agent": "assistant", "tool": "send_email", "args": {...},
#  "tier": "soft", "reasons": [{"code": "untrusted_to_send", "message": "..."}]}
```

Show `tool`, `args` and `reasons` to a person, then resume with their decision:

```python
from langgraph.types import Command

agent.invoke(Command(resume={"proposal_id": ask["proposal_id"], "approve": True,
                             "by": "alice", "note": "checked the address"}),
             config, version="v2")
```

- **Several pauses at once.** When the model makes parallel tool calls, several interrupts can
  be pending; LangGraph then needs each decision keyed by its interrupt id:
  `Command(resume={out.interrupts[0].id: {...decision...}})`, one at a time. An interrupt id can
  change when a sibling is resumed: key your approval UI on `proposal_id`.
- The decision must name the proposal and say who decided; `approve` must be `True` or
  `False` (not the string `"true"`). Anything else is refused, the tool does not run, and the
  proposal is retired (`superseded`) so nothing can approve it later out of context.
- An approved call runs exactly as proposed, once. While it runs the proposal is `executing`
  (a run that pauses inside the tool, e.g. a sub-agent asking a person, resumes it without a
  second approval); then `executed`, or `superseded` if another check inside refused it.
- A `False` always wins and is recorded (`rejected`, with who said no), even over an approval
  made elsewhere meanwhile.
- You can decide out of band (`guard.decide(...)`, from an approval dashboard) and resume with
  the same decision. `guard.pending()` (no argument) lists what waits across all sessions.
  Executing out of band (`guard.execute`) runs outside the agent: pass plain functions
  (`{"send_email": send_email.func}` for a LangChain tool), and note that it bypasses the
  other middlewares.
- Approval needs a checkpointer; without one the pause looks normal but cannot be resumed.
  Resuming a thread with nothing pending does nothing: check `agent.get_state(config).interrupts`.
- The session stays tainted after an approval: the next send asks again.

## Who is who

- **Session**: the LangGraph `thread_id` (or `session=lambda request: ...`). A tool call
  without a session is refused.
- **Agent**: `FlowMiddleware(guard, agent="...")`, or the graph's name (`create_agent(name=...)`,
  Deep Agents sub-agent names). Rules see it as `agent` (since 0.3; a tool argument named
  `agent` cannot change it), profiles by name.
- The model chooses the tool and its arguments (checked); never the session or the agent.

## Deep Agents

**Every sub-agent needs the middleware, including the one you did not declare.** Deep Agents
does not pass the main agent's middleware to its sub-agents, and it adds a `general-purpose`
sub-agent with **all** the main agent's tools. Left alone, a model can hand any work to it and
skip every check. Either give it the middleware explicitly or turn it off:

```python
governed = [FlowMiddleware(guard)]          # share one guard: taint is per thread
subagents = [
    {"name": "researcher", "description": "...", "tools": [search_web], "middleware": governed},
    {"name": "general-purpose", "description": "General tasks.", "tools": tools,
     "middleware": governed},                # replaces the automatic one
]
agent = create_deep_agent(model, tools, subagents=subagents, middleware=governed,
                          checkpointer=saver, name="assistant")
```

agent-auth refuses hand-offs (`task`) to sub-agents its A2A rules do not allow, which also
closes the automatic one by default.

**Built-in tools go through the middleware too**: `task`, `ls`, `read_file`, `write_file`,
`edit_file`, `delete`, `glob`, `grep` (and `execute` with a sandbox backend). Undeclared tools
count as sends that return untrusted content, so declare them:

```yaml
tools:
  ls: {effect: read}
  glob: {effect: read}
  grep: {effect: read, returns: untrusted}       # file contents may carry instructions
  read_file: {effect: read, returns: untrusted}
  write_file: {effect: write}
  edit_file: {effect: write}
  delete: {effect: write}
  execute: {effect: send, returns: untrusted}
  task: {effect: read, returns: untrusted}        # a sub-agent's answer; its own tools are checked inside it
```

## With agent-auth and agent-monitor

The middlewares compose; the first in the list is the outermost. Use this order:

```python
middleware=[MonitorMiddleware(monitor), AgentAuthMiddleware(engine), FlowMiddleware(guard)]
```

The monitor sees every outcome; authorization decides who may call the tool (and keeps its
separation-of-duties record only if the call ran); flow control decides whether the session
may call it now, and asks a person last, so nobody approves a call authorization would refuse.
Enforcement holds in any order; in another order the monitor misses what the middlewares
outside it decide, and a person may be asked about calls that are then refused.
