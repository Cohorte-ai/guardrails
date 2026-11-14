# Changelog

All notable changes to theaios-guardrails will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] - Unreleased

### Added

- **LangChain 1.x / Deep Agents middleware** (`theaios.guardrails.adapters.langchain_agent.FlowMiddleware`, extra `langchain-agent`): every tool call is admitted by a `FlowGuard`. Allowed calls run and are observed; denied calls do not run and the model gets an error `ToolMessage` (the run continues; the decision is in its `artifact`); calls needing approval pause the run with a LangGraph `interrupt` carrying the proposal, resumed with `{"proposal_id", "approve", "by"}`. Session = the LangGraph `thread_id`; agent = `agent=` or the graph's name.
- `FlowGuard.claim(proposal_id, tool, args)`: marks an approved proposal executed for a runner that executes the tool itself, only if the call about to run is exactly the approved one; at most once.

### Deprecated

- `GuardrailsCallback` (LangChain callback): it can only raise, which aborts a LangChain 1.x agent run, and cannot pause for approval. Emits a `FutureWarning`; use `FlowMiddleware`.

## [0.2.0] - 2026-11-09

### Added

- **Flow control** (`theaios.guardrails.flow`): tools declare their effect (`read`, `write`, `send`) and what their results carry (`untrusted`, `sensitive`) in a new `tools:` section. Once a session has read untrusted content, writes and sends need a person's approval; once it has read sensitive data, sends do. `FlowGuard.admit` decides at dispatch; `observe` records what each call returned; `call` and the `tool` decorator do both.
- **Proposals**: a blocked call becomes a proposal frozen to a SHA-256 digest of the tool and its arguments. A person decides it once (`decide`); `execute` runs it at most once and only with the proposed arguments.
- **Typed denials**: every non-allow decision carries codes (`untrusted_to_send`, `sensitive_to_send`, `rule_deny`, ...), a message and the tool calls that caused it.
- **Durable state**: `FileStore` keeps labels, proposals and decisions in a hash-chained log with a truncation anchor, reloaded on restart and checked with `guardrails flow-verify` (not `python -m theaios.core.audit verify`, which cannot see deleted last lines). It catches crashes, truncation, edits and a second writer; it does not stop someone with write access to the state directory, which the docs say plainly.
- **Grounded numbers** (`theaios.guardrails.grounding.check_numbers`): flags figures in a generated text that no source contains, allowing for rounding, units and percentages.
- `examples/flow-control`: an inbox assistant with prompt injections, measured with TrustGate. With gpt-4.1-mini over 42 attack runs, in two independent runs: 65 and 64 emails to attacker addresses and 30 and 29 bank-detail tickets executed unguarded, none with flow control; legitimate sends after reading mail wait for approval.
- `guardrails flow-verify PATH`: checks a flow-state file's hash chain and truncation anchor, with what happened and what to do.
- `guardrails validate` counts tools; `guardrails inspect` shows tools and flow settings.
- Docs: flow control guide (including who may decide, clear and execute, and how to run an agent with an approval UI); `tools:` and `flow:` in the policy reference; matchers documented as detectors, not the security boundary against prompt injection.

### Changed (from the pre-release test, before 0.2.0 shipped)

The pre-release usability test (three simulated users, one acting as a red team) found ways around flow control in the first build. All are fixed, each with a regression test (`tests/flow/test_ux_findings.py`):

- A tool that raised was not observed, so its error message could carry an injection and the next send ran without approval. `call`, the decorator and `execute` now observe every call that ran, even if it raised.
- Overlapping globs resolved by file order (a `send` glob could become a `read`). Matching globs now combine conservatively: the most restrictive effect and all labels.
- `execute` ran any function it was given; it now takes the tool registry and runs only the function registered under the approved tool name.
- Arguments that are not plain JSON could change without changing the approval digest; they are refused, as are arguments over 1 MB.
- A model could put `agent` in its tool arguments and escape a profile deny; `call` now takes arguments as a dict, separate from its own parameters.
- Rules with `scope: tool_call` were ignored by flow control; each call is now evaluated as an `action` event and as a `tool_call` event.
- Two stores on one file could execute an approved call twice and corrupt the log; `FileStore` now holds a lock (`StoreInUse`).
- Deleting the last lines of the state file, or emptying it, went undetected (a hash chain cannot see its end cut off) and could re-run an approved call or wipe a session's taint; an anchor file (`.head`) now catches it. Error messages say whether the history was edited, truncated or interrupted mid-write, and what to do.
- State files are created private (0600): they hold proposal arguments.
- Identical retries while a proposal is pending reuse it instead of queueing a duplicate that could be approved twice.
- Duplicate keys in a policy file are rejected (a merge conflict could turn a `send` into a `read`).
- `check_numbers` reads European formats and skips dates in common formats (it used to flag "14 March 2026"); a figure after a month name ("In March 9,999,000 units") is still checked.

A second, independent re-verification then found more, also fixed with tests:

- A pending proposal stayed open when the same call was proposed again for new reasons, so one call could be approved and run twice; the old proposal is now `superseded`.
- The store lock keyed on the path, so a hard link opened a second store; it now locks the log file itself.
- Entries appended outside the store were accepted; at most one entry past the anchor (a crash) is now tolerated.
- A function decorated with `@guard.tool` in the `execute` registry admitted itself again and never ran; `execute` now runs the original. The decorator refuses `*args`/`**kwargs` tools, whose calls could not be replayed exactly.
- Non-string keys in arguments (`{1: "x"}`) were silently turned into strings; they are refused. An existing state file is tightened to 0600. `pending`, `proposal` and `decide` return copies.

A second re-verification found:

- `admit` (and `FlowBlocked.admission`) returned the stored proposal itself: application code that set its status to `approved` could execute it with no decision. Every accessor now returns a copy, and `execute` requires a recorded decision.
- Asking again for a call that was approved but not yet run created a second proposal, so one call could run twice; the approved one is returned instead (and superseded if the reasons changed).
- `check_numbers`: a space-grouped figure after a month name ("In March 9 999 000") and a European decimal ("1.234,56") are read as single figures.

A final red-team pass on the proposal lifecycle found, and these are fixed:

- `decide(approve="false")` approved (the string is truthy): `approve` must be `True` or `False`.
- `execute` trusted a `_flow_original` attribute, which `functools.wraps` copies: an application wrapper (redaction, audit) could be skipped, and any function carrying the attribute could redirect the call. Decorated tools are now recognised by identity, and only under the name they were decorated with.
- The decorator recorded only the arguments passed, so defaults ran unseen by the approver; defaults are now included. Positional-only parameters are refused (they burned the approval).
- The store returns and keeps copies of proposals.
- Docs: what flow control protects against (the model and the content it reads) and what it trusts (your application code).

### Changed

- New optional top-level sections `tools:` and `flow:`. Policies without them load and behave exactly as before.
- README: "formally verify" with TrustGate is now "measure".

## [0.1.6] - 2026-11-09

### Security

- A rule whose `when` clause named an undefined `$variable` or matcher (a typo such as `$max_amout` or `prompt_injectoin`) passed validation and was then silently skipped at every evaluation, so a deny rule with a typo allowed everything. Such policies are now rejected when they load (`load_policy`, `Engine(...)`, `guardrails validate`), with a "did you mean" suggestion. Disabled rules are not checked. **If your policy stops loading after upgrading, it had a rule that never fired.**
- A rule whose condition cannot be evaluated is now treated as matched instead of skipped (fail closed): a deny rule denies, an approval rule requires approval, and the decision's reason says the rule could not be evaluated.

- Mistakes in a policy's structure no longer load silently. Each of these used to be accepted and change what the policy does, often allowing what it was written to block. They are now rejected, by name and with a suggestion where one exists:
  - an unknown key anywhere a fixed set applies: top level (`rule:` for `rules:`, which loaded zero rules), rules (`condition:` for `when:`, `enabeld:`), profiles, rate limits, and the options of built-in matchers (`case_insesitive:`);
  - a section of the wrong type (`rules:` written as a mapping loaded zero rules; `variables:` as a list);
  - a `when` that is not a string (`when: 42` matched every event), `enabled: "false"` in quotes (the rule stayed on), a rule `name` YAML reads as a boolean (`off`);
  - matcher `patterns` that are not a list or mapping of strings (a `keyword_list` with a single string never fired), an empty `regex` or `keyword_list`, and a regex that does not compile (validation passed, then the engine crashed).
- A redact rule without `patterns` redacted nothing while reporting `redact`, so the README quick start's rule returned PII unchanged. It now redacts with the matchers its `when` uses; a redact rule with neither is rejected.
- A string amount such as `"10000"` passed a numeric cap (`amount > $max_transfer`) because it was compared as text. Numbers in strings now compare as numbers; a value that cannot be compared with a number (`"10,000"`) makes the rule fail closed (theaios-core 0.1.1).
- A redact rule listing a pattern name that no matcher defines (`patterns: [sssn]`) redacted nothing when the policy had no matchers, and everything otherwise. Pattern names are now checked against the matcher names and the named patterns inside built-in matchers (skipped when a custom matcher type is used).
- `==`, `!=`, `in` and `not in` treat `"1001"` and `1001` as equal, so a blocklist of numeric ids cannot be bypassed by sending the id as a string (theaios-core 0.1.1).
- `Engine(...)` built from a `PolicyConfig` in code now runs the same validation as `load_policy` and raises `ConfigError`; before, `then="block"` or `scope="actions"` was accepted and silently allowed everything.

### Fixed

- YAML syntax errors, a directory or a non-UTF-8 file passed as the policy raise `ConfigError` with the file and line instead of a Python traceback.
- Custom matcher types registered with `@register_matcher` (as documented in docs/matchers.md) were rejected by validation; matcher types are now checked against the registry.
- `guardrails check`, `inspect` and `audit` printed text in square brackets as terminal markup, so a reason like "[rule could not be evaluated ...]" disappeared; all policy and event text is now shown verbatim.
- An unknown rule key `condition:` suggested `description` (following it left a rule that matches everything); it now suggests `when`.
- docs/matchers.md described a `custom_class` config key that never existed.
- docs/expressions.md: the operator-precedence example described the wrong grouping, and the variables section said undefined variables fail at evaluation time.

### Changed

- Requires theaios-core 0.1.1 or later.

## [0.1.5] - 2026-11-09

### Changed

- The expression engine and the audit log writer now come from [theaios-core](https://github.com/Cohorte-ai/theaios-core), a new dependency shared by the theaios libraries. The four libraries carried identical copies of the engine; it now lives in one place. Existing configs, imports (`theaios.guardrails.expressions` still works) and audit files are unchanged.

### Fixed

- Expressions longer than 10,000 characters or nested deeper than 64 levels now raise `ExpressionError` instead of crashing with a Python `RecursionError`. Long `and` / `or` chains no longer hit the recursion limit.

## [0.1.4] - 2026-09-10

### Added

- `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `SECURITY.md`

### Changed

- CI toolchain pinned to verified versions (ruff 0.15.x, mypy 1.19.x, pytest <10)

> The entries below for 0.1.2–0.1.3 were reconstructed on 2026-09-10 from the commit history.

## [0.1.3] - 2026-03-31

### Fixed

- Windows BOM issue in `--event-file`; Windows examples updated for PowerShell and CMD

## [0.1.2] - 2026-03-31

### Added

- `--event-file` option for Windows CMD compatibility

### Changed

- Publish workflow uses a PyPI API token instead of trusted publishing

## [0.1.1] - 2026-03-29

### Security

- ReDoS protection: 100K character input limit on regex matcher match() and redact()
- Graceful regex compilation: invalid patterns raise ValueError instead of crashing

## [0.1.0] - 2026-03-26

### Added

- Declarative YAML policy engine with rules, profiles, variables, and matchers
- Safe expression language for `when` clauses — recursive descent parser with 12 operators, no `eval()`
- Three-tier action classification: autonomous / soft-approval / strong-approval
- Agent profiles with inheritance (`extends`) and allow/deny action lists
- Cross-agent guardrails (`scope: cross_agent`) with `from`/`to` agent filtering
- Built-in matchers: `keyword_list`, `regex`, `pii` (SSN, email, phone, credit card, IBAN, IP)
- Extensible matcher registry via `@register_matcher` decorator
- In-memory sliding window rate limiter (`rate_limit` rules)
- JSONL audit logging with filtering by agent, outcome, rule, and timestamp
- Dry run mode (`Engine(dry_run=True)`) for testing policies without enforcement
- Severity-based rule evaluation order (critical > high > medium > low)
- Decision precedence: deny > require_approval > redact > allow
- CLI commands: `validate`, `check`, `inspect`, `audit`, `version`
- `@guard` decorator for wrapping sync and async functions
- LangChain callback handler (`GuardrailsCallback`)
- OpenAI Agents SDK adapter (`OpenAIAgentsGuardrail`)
- TrustGate verification bridge (`verify()` with attack set testing)
- 131 unit tests, mypy strict, ruff lint + format
- CI pipeline: lint, typecheck, test (Python 3.10-3.13), build verification
- MkDocs Material documentation site with 10 pages
- Example policies (basic + enterprise) and 6 runnable Python examples
- End-to-end test guide with 32 manual test steps
- PEP 561 compliant (`py.typed` marker)
