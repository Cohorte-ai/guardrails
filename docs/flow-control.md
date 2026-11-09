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
`flow: {undeclared: deny}` (recommended once your tool list is complete).

**Globs.** An exact name wins over a glob. When several globs match a tool, they combine
conservatively: the most restrictive effect and all their labels, so the order in the file never
matters (`"crm_*": read` and `"crm_send*": send` make `crm_send_mail` a send). A glob also
covers tools added later: `"*_report": {effect: read}` silently makes a future `send_report` a
read. Use globs only for families whose effect you control, and never `"*": {effect: read}`.

---

## Use it

```python
from theaios.guardrails import load_policy
from theaios.guardrails.flow import FlowGuard, FlowBlocked

guard = FlowGuard(load_policy("guardrails.yaml"))   # one per process, kept for its lifetime

# In your tool dispatcher:
admission = guard.admit(session_id, "send_email", {"to": to, "body": body}, agent="assistant")
if admission.allowed:
    try:
        result = send_email(to=to, body=body)
    finally:
        guard.observe(session_id, "send_email")  # after EVERY call that ran, even if it raised
elif admission.proposal is not None:
    queue_for_approval(admission.proposal)       # tell the model it is waiting
else:
    refuse(admission.reasons)
```

Or let the guard do the three steps:

```python
result = guard.call(session_id, "read_inbox", read_inbox)               # admit, run, observe
guard.call(session_id, "send_email", send_email, {"to": to, "body": body})  # raises FlowBlocked

@guard.tool("send_email", session=lambda: current_session_id())
def send(to: str, body: str) -> str: ...
```

Arguments are passed as a dict, never mixed with the guard's own parameters: a model that puts
`"agent": "admin"` in its tool arguments cannot change the identity your profiles check.
Arguments must be plain JSON (strings, numbers, booleans, null, lists, objects with string
keys) and at most 1 MB; anything else raises `ValueError`, because the approval digest must
cover every byte.

`observe` must be called after every tool call that ran, **including one that raised**: an
error message can carry the injected content. `call`, the decorator and `execute` do it for
you. Forgetting it is the one way to misuse the API: the session would not know what it read.

**Keep one guard.** Taint lives in the guard's store. A guard created per request with the
default in-memory store forgets everything between requests.

Each call is also evaluated against your existing rules and profiles, as an `action` event
(`data` = the arguments plus `action` = the tool name) and as a `tool_call` event
(`data` = `{"tool_name": ..., "arguments": {...}}`), so rules written for either scope apply.
A rule's `deny` wins over everything; a rule's `require_approval` joins the flow reasons in the
same proposal. `agent` is what your profiles and rules see; taint is per `session_id` only, so
never reuse a session id across users.

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
the reasons and the tier. A person decides; your code runs it.

```python
TOOLS = {"send_email": send_email, "create_ticket": create_ticket}   # your tool registry

for p in guard.pending(session_id):
    show(p.tool, p.args, [r.message for r in p.reasons])

guard.decide(p.id, approve=True, by="lea", note="checked the address")   # once
guard.execute(p.id, TOOLS)   # runs TOOLS[p.tool](**p.args), at most once
guard.proposal(p.id)         # any proposal by id, whatever its status
```

- A proposal can be decided **once**; a second decision raises `ProposalError`.
- `execute` runs **only** an approved proposal, **only** the function registered under the
  approved tool name, **only** with the proposed arguments, and **at most once**, even under
  concurrency. It is marked executed before it runs: a call that fails is not retried, and a
  retry needs a new approval.
- If the model asks again for the same call, for the same reasons, while it is pending, `admit`
  returns the existing proposal instead of queueing a duplicate. If the reasons changed (the
  session read something since), a new proposal states them.
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

Every label, proposal, decision and clear is appended to a hash-chained log (theaios-core).
Next to it, `state.jsonl.head` records how many entries there are and the last hash, so that
deleting the last lines is caught too (a hash chain alone cannot see its end being cut).
`FileStore` checks both when it opens the file and raises `StoreCorrupted` rather than resume
from a history that was edited, truncated or emptied. Check a file from the command line:

```bash
guardrails flow-verify .guardrails_flow/state.jsonl   # exit 0 intact, 1 otherwise
```

- **One store per file.** `FileStore` holds a lock (`state.jsonl.lock`) while open; a second
  open, in this process or another, raises `StoreInUse`. Close it (`store.close()` or
  `with FileStore(...) as store:`) to release it.
- **Private.** The files are created readable by their owner only (0600): they hold the
  arguments of proposed calls. Back them up and delete them like any data they contain.
- **Recovery.** The error says what happened. An interrupted write (crash) leaves an incomplete
  last line: remove only that line. Anything else (edited, deleted or reordered entries, a
  missing file or anchor) means the history cannot be trusted: restore both files from backup.
  Starting a new file drops every label and pending proposal; do it knowingly.
- **Limits.** This detects edits and truncation; it does not stop someone who can rewrite both
  the log and its anchor. Protect the directory with file permissions, and copy the anchor
  elsewhere if you need more.

---

## Who may do what

The guard decides *whether* a call needs a person; it does not know *who* the person is.

- **Never expose `decide`, `execute` or `clear` as tools the model can call.** The model would
  approve its own proposals or clear its own taint.
- `by=` in `decide` and `clear` is recorded as given: authenticate the approver in your own
  application before calling them, and check they may decide for that session.
- Anyone with a proposal id and the guard can call `execute`; keep proposal ids inside your
  backend.
- **Agent and approval UI.** Run the guard in one service (the one that runs the agent). Expose
  pending proposals and a decide endpoint from that service to your approval UI, instead of
  opening the same store from a second process.
- Show the approver the reasons and the exact arguments, and watch the approval rate: if
  people approve without reading, the control has become theatre.

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

"3.2M" is grounded by "3,215,000", "12.3%" by "12.34%" or "0.1234". European formats are read
too ("9.999.000", "9 999 000", "12,34%"). Whole numbers up to 10 ("3 steps") are skipped by
default (`ignore_small=-1` checks them).

Not checked: **dates** in any common format ("2026-11-09", "11/09/2026", "14 March 2026"),
**identifiers** glued to letters (`gpt-4.1`, `Q3`), and **currencies** ("$3,215,000" is grounded
by "3,215,000 EUR": check currencies with a text rule). A figure written at low precision
matches more ("3M" is grounded by anything from 2.5M to 3.5M). An ungrounded figure is not
necessarily wrong (a correct sum is ungrounded too): it is one nobody can trace.
