# Expression Language

The `when` clause in rules uses a safe, purpose-built expression language. It supports field access, comparisons, boolean logic, pattern matching, and variable substitution — nothing more.

No `eval()`. No arbitrary code. No imports. Just the operations you need to write policy conditions.

---

## Quick Reference

```yaml
# Field comparison
when: "action == 'send_email'"

# Nested field access (dot notation)
when: "recipient.domain != $company_domain"

# Boolean operators
when: "action == 'send_email' and recipient.domain != $company_domain"
when: "role == 'admin' or role == 'superadmin'"
when: "not is_internal"

# Pattern matching (references a named matcher)
when: "content matches prompt_injection"

# String operations
when: "content contains 'confidential'"
when: "path starts_with 'finance/'"
when: "file ends_with '.csv'"

# List membership
when: "resource.domain in $sensitive_domains"
when: "action not in ['read', 'search', 'list']"

# Inline lists
when: "status in ['draft', 'pending', 'review']"

# Parentheses for grouping
when: "(action == 'write' or action == 'delete') and resource.domain in $sensitive_domains"

# Numeric comparison
when: "amount > 10000"
when: "confidence_score < 0.8"

# Null check (for missing fields)
when: "approval_id == null"
```

---

## Operators

### Comparison

| Operator | Meaning | Example |
|----------|---------|---------|
| `==` | Equals | `action == 'send_email'` |
| `!=` | Not equals | `domain != $company_domain` |
| `>` | Greater than | `amount > 10000` |
| `<` | Less than | `score < 0.5` |
| `>=` | Greater than or equal | `retries >= 3` |
| `<=` | Less than or equal | `confidence <= 0.8` |

### String

| Operator | Meaning | Example |
|----------|---------|---------|
| `contains` | Left contains right as substring | `content contains 'password'` |
| `starts_with` | Left starts with right | `path starts_with 'finance/'` |
| `ends_with` | Left ends with right | `file ends_with '.pdf'` |

### Pattern

| Operator | Meaning | Example |
|----------|---------|---------|
| `matches` | Left text matches a named matcher | `content matches prompt_injection` |

The right side of `matches` is a matcher name defined in the `matchers:` section of your policy. See [Matchers](matchers.md).

### Membership

| Operator | Meaning | Example |
|----------|---------|---------|
| `in` | Left is in right (list or string) | `role in ['admin', 'manager']` |
| `not in` | Left is not in right | `action not in ['read', 'list']` |

The right side can be an inline list (`["a", "b"]`) or a variable (`$allowed_roles`).

### Boolean

| Operator | Meaning | Example |
|----------|---------|---------|
| `and` | Both sides must be true | `a == 'x' and b == 'y'` |
| `or` | At least one side must be true | `a == 'x' or a == 'y'` |
| `not` | Negate the expression | `not is_approved` |

`and` and `or` short-circuit: if the left side of `and` is false, the right side is not evaluated. If the left side of `or` is true, the right side is not evaluated.

---

## Values

### Fields

Fields access data from the event using dot notation:

```yaml
when: "recipient.domain != $company_domain"
```

Given an event with `data = {"recipient": {"domain": "external.com"}}`, the field `recipient.domain` resolves to `"external.com"`.

If a field doesn't exist, it resolves to `null`. This means you can safely reference nested fields without worrying about missing keys:

```yaml
when: "approval.manager != null"  # True only if the field exists
```

### Variables

Variables reference values from the `variables:` section of your policy:

```yaml
variables:
  company_domain: "acme.com"
  sensitive_domains: ["finance", "legal", "hr"]

rules:
  - when: "domain != $company_domain"           # string variable
  - when: "dept in $sensitive_domains"           # list variable
```

Variables are prefixed with `$`. If a variable doesn't exist, the engine raises an error at evaluation time — this is intentional, to catch typos.

### Literals

| Type | Syntax | Examples |
|------|--------|---------|
| String | Single or double quotes | `'hello'`, `"hello"` |
| Number | Digits, optional decimal | `42`, `3.14` |
| Boolean | `true` or `false` | `true` |
| Null | `null` or `none` | `null` |
| List | Square brackets | `["a", "b", "c"]` |

---

## Operator Precedence

From lowest to highest:

1. `or`
2. `and`
3. `not`
4. Comparisons (`==`, `!=`, `>`, `<`, `>=`, `<=`, `in`, `not in`, `matches`, `contains`, `starts_with`, `ends_with`)

Use parentheses to override precedence:

```yaml
# Without parentheses: "a and (b or c)" — and binds tighter than or
when: "action == 'write' and resource == 'finance' or resource == 'legal'"

# With parentheses: "(a) and (b or c)" — explicit grouping
when: "action == 'write' and (resource == 'finance' or resource == 'legal')"
```

!!! warning "Use parentheses when mixing `and` and `or`"
    The expression `a and b or c` means `(a and b) or c`, not `a and (b or c)`. When in doubt, add parentheses.

---

## Grammar

For the technically curious, here's the formal grammar:

```
expression  → or_expr
or_expr     → and_expr ("or" and_expr)*
and_expr    → not_expr ("and" not_expr)*
not_expr    → "not" not_expr | comparison
comparison  → primary (comp_op primary)?
comp_op     → "==" | "!=" | ">" | "<" | ">=" | "<="
             | "matches" | "contains" | "starts_with" | "ends_with"
             | "in" | "not" "in"
primary     → STRING | NUMBER | BOOL | NULL | variable | field | list | "(" expression ")"
variable    → "$" IDENTIFIER
field       → IDENTIFIER ("." IDENTIFIER)*
list        → "[" (expression ("," expression)*)? "]"
```

The parser is a recursive descent parser implemented in ~300 lines of Python with zero external dependencies.
