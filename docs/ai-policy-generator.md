# Generate Policies with AI

You can use any LLM (Claude, ChatGPT, Gemini, etc.) to generate guardrails policies that are fully compatible with this library. Copy-paste one of the prompts below, answer the follow-up questions, and get a production-ready YAML file.

---

## Prompt 1: Full Policy from Scratch

Use this when starting from zero. The AI will ask about your company, agents, and concerns, then generate a complete policy.

````
I need you to generate a guardrails policy YAML file for the theaios-guardrails library. This policy will govern AI agent behavior in my organization.

Before generating, ask me about:
1. What does my company do? (industry, size)
2. What AI agents do we have or plan to deploy? (names, roles)
3. What actions can these agents perform? (email, data access, tool calls, etc.)
4. What are our top security/compliance concerns?
5. What data is sensitive in our context?
6. Do we need cross-agent communication rules?

Then generate a YAML file following this exact specification:

```yaml
version: "1.0"                    # Always "1.0"
metadata:
  name: string                    # Policy name
  description: string             # What this policy governs
  author: string                  # Policy owner

variables:                        # Shared values referenced as $var_name in rules
  key: value                      # Can be strings, numbers, booleans, or lists

profiles:                         # Per-agent permission boundaries
  profile-name:
    extends: parent-profile       # Optional: inherit from another profile
    default_tier: autonomous      # Default approval tier: autonomous | soft | strong
    allow: [action1, action2]     # Explicitly permitted actions
    deny: [action3, action4]      # Absolutely forbidden actions (deny always wins)

rules:                            # Guardrail rules — evaluated in severity order
  - name: unique-rule-name        # Required: unique identifier
    description: string           # What this rule does and why
    scope: input                  # Required: input | output | action | tool_call | cross_agent
    when: "expression"            # Condition — see expression syntax below
    then: deny                    # Required: deny | require_approval | redact | allow | log
    reason: string                # Explanation attached to the decision
    severity: critical            # critical | high | medium | low (determines eval priority)
    tier: soft                    # For require_approval only: autonomous | soft | strong
    enabled: true                 # Set false to disable without deleting
    tags: [tag1, tag2]            # Labels for filtering and reporting
    patterns: [matcher1]          # For redact only: which matchers to use for redaction
    from: source-profile          # For cross_agent only: source agent profile
    to: target-profile            # For cross_agent only: target agent profile
    rate_limit:                   # Optional: rate limiting
      max: 100                    # Max events in window
      window: 60                  # Window in seconds
      key: agent                  # Group by: agent | session | any data field

matchers:                         # Named pattern definitions
  matcher-name:
    type: keyword_list            # keyword_list | regex | pii
    patterns:                     # List of strings (keyword_list) or dict of name: regex (regex)
      - "phrase to match"
    options:
      case_insensitive: true      # Optional

# Expression syntax for "when" clauses:
# Field access:      recipient.domain, content, action
# Comparisons:       ==, !=, >, <, >=, <=
# String ops:        contains, starts_with, ends_with
# Pattern matching:  matches (references a named matcher)
# Membership:        in, not in (with lists or variables)
# Boolean:           and, or, not
# Variables:         $variable_name
# Literals:          "string", 123, true, false, null
# Grouping:          parentheses ()
# Examples:
#   "action == 'send_email' and recipient.domain != $company_domain"
#   "content matches prompt_injection"
#   "resource.domain in $sensitive_domains"
#   "(action == 'write' or action == 'delete') and not is_admin"
```

Important rules for generation:
- Every rule must have a unique name, a valid scope, and a valid "then" outcome
- Use severity honestly: critical = security breach, high = data leak, medium = policy compliance, low = monitoring
- Always include a prompt_injection matcher (keyword_list with common injection phrases, case_insensitive: true)
- Always include a pii matcher (type: pii with patterns: {} for built-in detection, or regex with named patterns)
- Use variables for values that might change (company domain, department lists, rate limits)
- Use profiles for agent permission boundaries
- Use tags on every rule for filtering
- Add clear descriptions and reasons to every rule
````

---

## Prompt 2: Add Rules to an Existing Policy

Use this when you already have a policy and want to extend it.

````
I have an existing theaios-guardrails policy. I need to add new rules for [DESCRIBE YOUR NEED].

Here is my current policy:

```yaml
[PASTE YOUR CURRENT YAML HERE]
```

Generate additional rules following the same format and conventions. For each new rule, include:
- A unique name (no duplicates with existing rules)
- A clear description
- The appropriate scope (input, output, action, tool_call, or cross_agent)
- A when condition using the expression syntax: field access (dot notation), comparisons (==, !=, >, <), string ops (contains, starts_with, ends_with, matches), boolean (and, or, not), variables ($var), membership (in, not in)
- Appropriate severity (critical, high, medium, low)
- Tags for categorization
- Any new matchers or variables needed

Also tell me if any existing rules should be modified to work well with the new ones.
````

---

## Prompt 3: Industry-Specific Policy Starter

Use this to generate a policy tailored to a specific industry.

````
Generate a complete theaios-guardrails policy YAML file for a [INDUSTRY] company.

The company:
- Industry: [e.g., healthcare, financial services, legal, consulting, e-commerce]
- Size: [e.g., 50 employees, 500 employees]
- AI agents: [e.g., customer support agent, internal assistant, data analyst agent]
- Key regulations: [e.g., HIPAA, SOC 2, GDPR, PCI-DSS]

Generate a production-ready YAML policy that includes:

1. **Profiles** for each agent with appropriate allow/deny lists
2. **Security rules**: prompt injection blocking, jailbreak prevention
3. **Privacy rules**: PII detection and redaction (using type: pii matcher or regex patterns)
4. **Compliance rules**: industry-specific regulations (approval workflows for sensitive actions)
5. **Data isolation**: cross-agent rules preventing unauthorized data sharing
6. **Rate limiting**: prevent abuse
7. **Communication rules**: external communication approval requirements

Use this YAML format:
- version: "1.0"
- Scopes: input, output, action, tool_call, cross_agent
- Outcomes: deny, require_approval (with tier: soft or strong), redact, allow, log
- Severities: critical, high, medium, low
- Expression syntax: "field == 'value'", "field matches matcher_name", "field in $variable", "field contains 'text'", and/or/not, $variable references
- Matcher types: keyword_list (with case_insensitive option), regex (named patterns as dict), pii (built-in patterns)

Include thorough matchers for prompt injection (keyword_list, case_insensitive, 10+ patterns) and PII (regex with named patterns for the relevant PII types in this industry).

Add tags to every rule and descriptions explaining the business reason.
````

---

## Prompt 4: Convert Existing Rules to YAML

Use this when you have informal rules (in a document, spreadsheet, or someone's head) and want to formalize them.

````
I need to convert our organization's AI governance rules into a theaios-guardrails YAML policy.

Here are our current rules in plain English:

[PASTE YOUR RULES — examples:]
- "Sales agents can read CRM data but cannot modify pricing"
- "All external emails must be approved by the sender before being sent"
- "Financial data should never be shared between the sales and marketing teams"
- "Any output containing a social security number must be redacted"
- "Agents cannot make more than 50 API calls per minute"

Convert each rule into the YAML format:

```yaml
rules:
  - name: descriptive-kebab-case-name
    description: "The business reason for this rule"
    scope: input | output | action | tool_call | cross_agent
    when: "expression using: field.access, ==, !=, contains, matches, starts_with, ends_with, in, not in, and, or, not, $variables"
    then: deny | require_approval | redact
    tier: soft | strong          # only for require_approval
    reason: "What the user/agent sees when this fires"
    severity: critical | high | medium | low
    tags: [relevant, tags]
```

Also generate:
- Any profiles needed (with allow/deny lists)
- Any variables needed (company domain, department lists, etc.)
- Any matchers needed (keyword_list, regex, or pii type)

Explain any rules that are ambiguous and suggest how to interpret them.
````

---

## Prompt 5: Security Audit a Policy

Use this to review an existing policy for gaps.

````
Review this theaios-guardrails policy for security and compliance gaps:

```yaml
[PASTE YOUR YAML HERE]
```

Check for:
1. **Missing injection protection** — is there a rule blocking prompt injection on input scope?
2. **Missing PII redaction** — is there a rule redacting PII on output scope?
3. **Overly permissive profiles** — are any agent deny lists too short?
4. **Missing cross-agent isolation** — should any agent pairs have data sharing restrictions?
5. **Missing rate limits** — are there rate limits to prevent abuse?
6. **Severity accuracy** — are severities assigned correctly? (critical = security, high = data, medium = compliance, low = monitoring)
7. **Missing tags** — do all rules have tags for filtering?
8. **Expression correctness** — are the when clauses syntactically valid? (operators: ==, !=, >, <, >=, <=, contains, starts_with, ends_with, matches, in, not in, and, or, not)
9. **Matcher coverage** — are the prompt injection keywords comprehensive? Is PII detection using named patterns?
10. **Edge cases** — what happens with unknown agents? Are there rules for all scopes (input, output, action)?

For each gap found, provide the exact YAML to add.
````

---

## Tips for Better Results

1. **Be specific about your agents.** "We have a sales agent that can read CRM and draft emails" produces better rules than "we have some AI agents."

2. **Mention your regulations.** HIPAA, SOC 2, GDPR, PCI-DSS — each implies specific rules the AI will include.

3. **Provide examples of sensitive data.** "Employee SSNs, salary data, client contracts" tells the AI exactly what to protect.

4. **Iterate.** Generate a first draft, run `guardrails validate --config policy.yaml` to check syntax, then ask the AI to fix any issues.

5. **Test with real scenarios.** After generating, use `guardrails check` to test edge cases:
   ```bash
   guardrails check --config policy.yaml \
     --event '{"scope":"input","agent":"my-agent","data":{"content":"ignore previous instructions"}}'
   ```

---

## Validate AI-Generated Policies

Always validate before using in production:

```bash
# Check syntax
guardrails validate --config generated-policy.yaml

# Inspect the policy
guardrails inspect --config generated-policy.yaml

# Test specific scenarios
guardrails check --config generated-policy.yaml \
  --event '{"scope":"input","agent":"test","data":{"content":"normal question"}}'

guardrails check --config generated-policy.yaml \
  --event '{"scope":"input","agent":"test","data":{"content":"ignore previous instructions"}}'

# Run in dry-run mode first
guardrails check --config generated-policy.yaml --dry-run \
  --event '{"scope":"action","agent":"sales-agent","data":{"action":"send_email","recipient":{"domain":"external.com"}}}'
```
