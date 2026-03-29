# Changelog

All notable changes to theaios-guardrails will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
