# Changelog

All notable changes to theaios-guardrails will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-11-09

### Added

- **Flow control** (`theaios.guardrails.flow`): tools declare their effect (`read`, `write`, `send`) and what their results carry (`untrusted`, `sensitive`) in a new `tools:` section. Once a session has read untrusted content, writes and sends need a person's approval; once it has read sensitive data, sends do. `FlowGuard.admit` decides at dispatch; `observe` records what each call returned; `call` and the `tool` decorator do both.
- **Proposals**: a blocked call becomes a proposal frozen to a SHA-256 digest of the tool and its arguments. A person decides it once (`decide`); `execute` runs it at most once and only with the proposed arguments.
- **Typed denials**: every non-allow decision carries codes (`untrusted_to_send`, `sensitive_to_send`, `rule_deny`, ...), a message and the tool calls that caused it.
- **Durable, tamper-evident state**: `FileStore` keeps labels, proposals and decisions in a hash-chained log, reloaded on restart and verifiable with `python -m theaios.core.audit verify`.
- **Grounded numbers** (`theaios.guardrails.grounding.check_numbers`): flags figures in a generated text that no source contains, allowing for rounding, units and percentages.
- `examples/flow-control`: an inbox assistant with prompt injections, measured with TrustGate. With gpt-4.1-mini over 42 attack runs: 65 emails to attacker addresses and 30 bank-detail tickets executed unguarded, none with flow control; legitimate sends after reading mail wait for approval.
- Docs: flow control guide; matchers documented as detectors, not the security boundary against prompt injection.

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
