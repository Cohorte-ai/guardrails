# Flow control

Rules and matchers look at one event at a time. Prompt injection does not work one event at a
time: an agent reads an email written by a stranger, and three steps later it sends your
customer data to the address that email gave it. Each step looks harmless; the sequence is
the attack.

Flow control decides at dispatch whether a tool call may run, **given what the session has
already read**. Its rule is the "lethal trifecta" (private data, untrusted content, a way out)
made structural:

| The session has read | Then a `read` | a `write` | a `send` |
|---|---|---|---|
| nothing labelled | runs | runs | runs |
| **untrusted** content (written by someone else) | runs | needs approval | needs approval |
| **sensitive** data (private) | runs | runs | needs approval |

The labels come from your declarations of what each tool returns, not from reading the
content. A prompt injection cannot talk its way past them, because nothing inspects what it
says.

Measured on an inbox assistant with gpt-4.1-mini: unguarded, 65 emails to attacker addresses
and 30 bank-detail tickets across 42 attack runs; with flow control, none executed. See
[examples/flow-control](https://github.com/Cohorte-ai/guardrails/tree/main/examples/flow-control).

---

## Declare your tools

```yaml
tools:
  read_inbox:
    effect: read
    returns: [untrusted, sensitive]   # strangers write it, and it is private
  read_crm:
    effect: read
    returns: sensitive
  search_web:
    effect: send                      # the query leaves the company
    returns: untrusted
  send_email:
    effect: send
  create_ticket:
    effect: write
  "crm_*":                            # globs work; an exact name wins over a glob
    effect: read
    returns: sensitive

flow:
  undeclared: treat_as_send   # or: deny
  on_block: require_approval  # or: deny
  approval_tier: strong       # or: soft
```

| Effect | Means | Examples |
|---|---|---|
| `read` | brings content in, changes nothing, sends nothing out | read a file, query a database |
| `write` | changes state inside the organisation | create a ticket, update a record |
| `send` | anything leaves the session's trust boundary, **including arguments** | email, webhook, web search, fetch a URL |

| Label | Put on a tool's results when |
|---|---|
| `untrusted` | someone other than the person the agent works for wrote it: email, web pages, uploaded files, tickets from customers |
| `sensitive` | it must not leave: customer records, HR, finance, secrets |

!!! warning "Declarations are the security boundary"
    A tool declared `read` whose arguments leave the company (a web search, a URL fetch, an
    API lookup by name) is an exfiltration channel: "search for <the customer's ARR>". Declare
    it `send`. When unsure, declare `send`.

An undeclared tool is treated as a `send` whose results are `untrusted`, or refused with
`flow: {undeclared: deny}`.

---

## Use it

```python
from theaios.guardrails import load_policy
from theaios.guardrails.flow import FlowGuard, FlowBlocked

guard = FlowGuard(load_policy("guardrails.yaml"))

# In your tool dispatcher:
admission = guard.admit(session_id, "send_email", {"to": to, "body": body}, agent="assistant")
if admission.allowed:
    result = send_email(to=to, body=body)
    guard.observe(session_id, "send_email")      # after EVERY tool call
elif admission.proposal is not None:
    queue_for_approval(admission.proposal)       # tell the model it is waiting
else:
    refuse(admission.reasons)
```

Or let the guard do the three steps:

```python
result = guard.call(session_id, "read_inbox", read_inbox)        # admit, run, observe
guard.call(session_id, "send_email", send_email, to=to, body=body)  # raises FlowBlocked

@guard.tool("send_email", session=lambda: current_session_id())
def send(to: str, body: str) -> str: ...
```

`observe` must be called after every tool call that ran (`call`, the decorator and `execute`
do it for you). Forgetting it is the one way to misuse the API: the session would not know
what it read.

Each call is also evaluated against your existing rules and profiles as an `action` event
(`data` = the arguments plus `action` = the tool name). A rule's `deny` wins over everything;
a rule's `require_approval` joins the flow reasons in the same proposal.

---

## Typed denials

Every decision that is not a plain allow carries reasons with a code for programs, a sentence
for people, and the tool calls that caused it:

```python
admission.codes            # [Code.UNTRUSTED_TO_SEND, Code.SENSITIVE_TO_SEND]
admission.reasons[0].message
# "the session read untrusted content (read_inbox); a send needs approval"
admission.reasons[0].provenance   # [Provenance(tool="read_inbox", label=..., call_id=..., at=...)]
```

| Code | When |
|---|---|
| `undeclared_tool` | `flow.undeclared: deny` and the tool is not declared |
| `untrusted_to_write` / `untrusted_to_send` | the session read untrusted content |
| `sensitive_to_send` | the session read sensitive data |
| `rule_deny` / `rule_approval` | one of your rules |

---

## Proposals: decided once, executed by code

A blocked call becomes a `Proposal`: the tool, the exact arguments, a SHA-256 digest of both,
the reasons and the tier. The agent does not retry it; a person decides, and your code runs it.

```python
for p in guard.pending(session_id):
    show(p.tool, p.args, [r.message for r in p.reasons])

guard.decide(p.id, approve=True, by="lea", note="checked the address")   # once
guard.execute(p.id, send_email)   # runs send_email(**p.args), at most once
```

- A proposal can be decided **once**; a second decision raises `ProposalError`.
- `execute` runs **only** an approved proposal, **only** with the proposed arguments (passing
  different ones is refused), and **at most once**, even under concurrency. It is marked
  executed before it runs, so a failed call is not retried automatically.
- Approval covers that one call. The session stays tainted: the next send needs its own
  approval. To start a fresh task, `guard.clear(session_id, by="lea", reason="new task")`.

---

## Durable state

By default labels and proposals live in memory. Keep them across restarts, and make the
history tamper-evident, with a file store:

```python
from theaios.guardrails.flow import FileStore

guard = FlowGuard(policy, store=FileStore(".guardrails_flow/state.jsonl"))
```

Every label, proposal, decision and clear is appended to a hash-chained log
(theaios-core). Editing or deleting a line is detected:

```bash
python -m theaios.core.audit verify .guardrails_flow/state.jsonl
```

---

## What it costs, and what it does not do

- **Approvals.** Every write or send after untrusted content, and every send after sensitive
  data, waits for a person. Measure how many before deploying (the example shows how).
- **The person still has to say no.** A proposal makes an attack visible, with its reason and
  arguments; someone who approves everything approves the attack. Watch the approval rate.
- **Content attacks are not covered.** An injection that changes what the agent *says* (a
  wrong summary, a false number) rather than what it *does* passes. Use
  [grounded numbers](#grounded-numbers) and TrustGate text checks.
- **Labels are per session, not per value.** After reading one untrusted email, every later
  send waits, even one built only from trusted data. Tracking each value's origin (as in
  CaMeL) would allow more without approval; it needs control of the agent's planner and is
  outside this library.

---

## Grounded numbers

Generated reports and emails get the prose right and a figure wrong. `check_numbers` finds
each number in a generated text and looks for it in the sources the agent was given, allowing
for rounding and units:

```python
from theaios.guardrails.grounding import check_numbers

report = check_numbers(draft, [crm_record, maria_email])
if not report.ok:
    print(report.summary())   # "1 of 4 figures not found in sources: 3.4M"
```

"3.2M" is grounded by "3,215,000", "12.3%" by "12.34%" or "0.1234". Whole numbers up to 10
("3 steps") are skipped by default (`ignore_small=-1` checks them). Identifiers such as
`gpt-4.1` or `Q3` and the parts of a date are not treated as claims. A figure written at low
precision matches more ("3M" is grounded by anything from 2.5M to 3.5M); an ungrounded figure
is not necessarily wrong (a correct sum is ungrounded too), it is one nobody can trace.
