# Matchers

Matchers are reusable pattern detection components. You define them in the `matchers:` section of your policy and reference them in rules with the `matches` operator.

---

## Built-in Matcher Types

### `keyword_list` — Keyword Phrase Matching

Checks whether the text contains any of the listed phrases as substrings.

```yaml
matchers:
  prompt_injection:
    type: keyword_list
    patterns:
      - "ignore previous instructions"
      - "you are now"
      - "disregard above"
      - "system prompt"
      - "reveal your instructions"
    options:
      case_insensitive: true
```

| Option | Default | Description |
|--------|---------|-------------|
| `case_insensitive` | `false` | Match regardless of case |

**When to use:** Prompt injection detection, topic blocking, content filtering. Fast and predictable.

**Limitations:** Exact substring matching only. `"ignore previous"` will not match `"ignore all previous"`. Include all variants you want to catch.

---

### `regex` — Regular Expression Matching

Matches text against compiled regular expressions. Patterns can be named (dict) or unnamed (list).

**Named patterns** (recommended for redaction):

```yaml
matchers:
  pii:
    type: regex
    patterns:
      ssn: "\\b\\d{3}-\\d{2}-\\d{4}\\b"
      email_addr: "\\b[\\w.-]+@[\\w.-]+\\.\\w+\\b"
      phone: "\\b\\d{3}[\\s.-]\\d{3}[\\s.-]\\d{4}\\b"
```

Named patterns produce labeled redactions: `123-45-6789` → `[SSN]`, `john@acme.com` → `[EMAIL_ADDR]`.

**Unnamed patterns:**

```yaml
matchers:
  secrets:
    type: regex
    patterns:
      - "sk-[a-zA-Z0-9]{48}"         # OpenAI API key
      - "ghp_[a-zA-Z0-9]{36}"        # GitHub personal access token
      - "AKIA[A-Z0-9]{16}"           # AWS access key
```

Unnamed patterns produce generic redactions: `sk-abc...` → `[REDACTED]`.

| Option | Default | Description |
|--------|---------|-------------|
| `case_insensitive` | `false` | Add `re.IGNORECASE` flag |

**When to use:** PII detection, secret scanning, structured pattern matching. More powerful than keywords but harder to maintain.

!!! tip "Escape backslashes in YAML"
    YAML requires double backslashes for regex: `\\b` in YAML becomes `\b` in the regex. Use `\\d`, `\\w`, `\\s`, etc.

---

### `pii` — Built-in PII Detection

A specialized matcher with pre-built patterns for common PII types. You don't need to write any regex — the built-in patterns are ready to use.

```yaml
matchers:
  pii:
    type: pii
    patterns: {}    # Use built-in patterns only
```

**Built-in PII patterns:**

| Name | What it detects | Redaction label |
|------|----------------|-----------------|
| `ssn` | US Social Security numbers (123-45-6789) | `[SSN]` |
| `email` | Email addresses | `[EMAIL]` |
| `phone` | US phone numbers (555-123-4567) | `[PHONE]` |
| `credit_card` | Credit card numbers (4111-1111-1111-1111) | `[CREDIT_CARD]` |
| `iban` | International Bank Account Numbers | `[IBAN]` |
| `ipv4` | IPv4 addresses | `[IP_ADDRESS]` |

**Adding custom PII patterns:**

```yaml
matchers:
  pii:
    type: pii
    patterns:
      employee_id: "EMP-\\d{6}"      # Custom pattern, adds [EMPLOYEE_ID]
      nhs_number: "\\d{3}\\s\\d{3}\\s\\d{4}"  # UK NHS number
```

Custom patterns are added alongside the built-in ones. If you use the same name as a built-in pattern, your pattern overrides it.

**When to use:** Any time you need PII detection. Start with the built-in patterns, add custom ones for your domain.

---

## Using Matchers in Rules

### The `matches` Operator

Reference a matcher by name in a `when` clause:

```yaml
rules:
  - name: block-injection
    scope: input
    when: "content matches prompt_injection"    # ← references the matcher
    then: deny

matchers:
  prompt_injection:                              # ← the matcher
    type: keyword_list
    patterns: ["ignore previous instructions"]
```

The engine passes the value of the left-side field (`content`) to the matcher's `match()` method.

### Redaction with `patterns`

For `redact` rules, the `patterns` field lists which patterns to apply:

```yaml
rules:
  - name: redact-pii
    scope: output
    when: "content matches pii"
    then: redact
    patterns: [ssn, email_addr, phone]    # ← which patterns to redact
```

The `patterns` list can contain:

- **Matcher names** — `pii` applies the entire matcher's redaction
- **Sub-pattern names** — `ssn`, `email_addr` target specific patterns within a matcher

---

## Writing Custom Matchers

You can extend the matcher system with your own Python classes. Register them with `@register_matcher` and reference them in your policy YAML.

```python
from theaios.guardrails.matchers import Matcher, register_matcher
from theaios.guardrails.types import MatcherConfig

@register_matcher("toxicity")
class ToxicityMatcher(Matcher):
    """Detect toxic content using a keyword list.

    In production, you might call an ML classification model here.
    """

    def __init__(self, config: MatcherConfig) -> None:
        self._words = set()
        if isinstance(config.patterns, list):
            self._words = {w.lower() for w in config.patterns}

    def match(self, text: str, pattern_name: str | None = None) -> bool:
        words = set(text.lower().split())
        return bool(words & self._words)

    def redact(self, text: str, pattern_name: str | None = None) -> str:
        result = text
        for word in self._words:
            result = result.replace(word, "[TOXIC]")
        return result
```

Then use it in your policy:

```yaml
matchers:
  toxicity:
    type: toxicity    # matches the @register_matcher name
    patterns:
      - "hate"
      - "kill"
      - "destroy"

rules:
  - name: block-toxic
    scope: input
    when: "content matches toxicity"
    then: deny
```

### The Matcher Interface

Every matcher must implement:

| Method | Required | Signature | Description |
|--------|----------|-----------|-------------|
| `match` | **Yes** | `match(text, pattern_name=None) -> bool` | Return True if text matches |
| `redact` | No | `redact(text, pattern_name=None) -> str` | Return text with matches replaced |

- `pattern_name` is passed when redaction targets a specific sub-pattern (e.g., `"ssn"` within a PII matcher)
- The default `redact()` implementation returns the text unchanged

### Loading Custom Matchers

Custom matchers must be registered before the engine loads. Two ways:

1. **Import in your code** (recommended): Import the module that contains your `@register_matcher` before creating the engine
2. **`custom_class`** in config (advanced): Reference a dotted Python path in the matcher config
