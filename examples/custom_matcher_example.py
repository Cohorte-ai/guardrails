"""Creating a custom matcher — extend guardrails with your own detection logic."""

from theaios.guardrails import Engine, GuardEvent
from theaios.guardrails.matchers import Matcher, register_matcher
from theaios.guardrails.types import (
    MatcherConfig,
    PolicyConfig,
    PolicyMetadata,
    RuleConfig,
)


# 1. Define your custom matcher
@register_matcher("toxicity")
class ToxicityMatcher(Matcher):
    """Simple keyword-based toxicity detector.

    In production, you'd call a classification model here.
    """

    def __init__(self, config: MatcherConfig) -> None:
        self._toxic_words = {"hate", "kill", "destroy", "attack"}

    def match(self, text: str, pattern_name: str | None = None) -> bool:
        words = set(text.lower().split())
        return bool(words & self._toxic_words)

    def redact(self, text: str, pattern_name: str | None = None) -> str:
        result = text
        for word in self._toxic_words:
            result = result.replace(word, "[TOXIC]")
            result = result.replace(word.capitalize(), "[TOXIC]")
        return result


# 2. Use it in a policy (programmatic, not YAML — both work)
policy = PolicyConfig(
    metadata=PolicyMetadata(name="custom-matcher-demo"),
    rules=[
        RuleConfig(
            name="block-toxic-input",
            scope="input",
            then="deny",
            when="content matches toxicity",
            reason="Toxic content detected",
            severity="critical",
        ),
    ],
    matchers={
        "toxicity": MatcherConfig(
            name="toxicity",
            type="toxicity",  # matches the @register_matcher name
            patterns=[],
        ),
    },
)

engine = Engine(policy)

# 3. Test it
tests = [
    "What's the best restaurant in town?",
    "I hate this product, destroy it",
    "Can you help me with my report?",
]

for text in tests:
    decision = engine.evaluate(GuardEvent(
        scope="input", agent="test", data={"content": text},
    ))
    print(f"{'BLOCKED' if decision.is_denied else 'OK':<10} {text}")
