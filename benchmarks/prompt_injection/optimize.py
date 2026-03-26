"""Prompt injection benchmark: naive vs optimized matcher.

Methodology:
1. Split deepset/prompt-injections into 70% train / 30% test
2. Evaluate naive matcher on BOTH splits (baseline)
3. Analyze train-set false negatives → build optimized matcher
4. Evaluate optimized matcher on held-out TEST SET ONLY
5. Compare: naive vs optimized, with honest test-set metrics

The optimized matcher is NEVER tuned on the test set.
"""

from __future__ import annotations

import json
import random
import time
from dataclasses import dataclass, field
from pathlib import Path

from theaios.guardrails import Engine, GuardEvent
from theaios.guardrails.types import (
    MatcherConfig,
    PolicyConfig,
    PolicyMetadata,
    RuleConfig,
)

SEED = 42


@dataclass
class Result:
    name: str = ""
    total: int = 0
    tp: int = 0
    tn: int = 0
    fp: int = 0
    fn: int = 0
    elapsed_ms: float = 0.0
    fn_samples: list[str] = field(default_factory=list)
    fp_samples: list[str] = field(default_factory=list)

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if (self.tp + self.fp) > 0 else 0.0

    @property
    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if (self.tp + self.fn) > 0 else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) > 0 else 0.0

    @property
    def accuracy(self) -> float:
        return (self.tp + self.tn) / self.total if self.total > 0 else 0.0


# ---------------------------------------------------------------------------
# Naive matcher (our original 50+ English-only keywords)
# ---------------------------------------------------------------------------

NAIVE_PATTERNS = [
    "ignore previous instructions",
    "ignore all previous",
    "ignore your instructions",
    "disregard previous",
    "disregard above",
    "override your instructions",
    "override safety",
    "bypass safety",
    "you are now",
    "system prompt",
    "reveal your instructions",
    "reveal your prompt",
    "show me your instructions",
    "what are your instructions",
    "jailbreak",
    "DAN",
    "do anything now",
    "[INST]",
    "[/INST]",
    "<|im_start|>",
    "<<SYS>>",
    "developer mode",
    "sudo mode",
    "unrestricted mode",
    "no restrictions",
    "ignore all rules",
    "ignore ethical",
    "ignore safety",
    "ignore content policy",
]

# ---------------------------------------------------------------------------
# Optimized matcher — built from analyzing TRAIN SET false negatives
#
# Key patterns found in the training data:
# 1. German translations of injection phrases (~50% of dataset is German)
# 2. "Forget" variants (forget everything, forget all, vergiss)
# 3. Role-play attacks (act as, pretend, you are X)
# 4. Task-switching ("new task", "neue Aufgabe", "now focus on")
# 5. Spanish injections ("olvida", "ignora")
# 6. Instruction extraction ("print your prompt", "show your rules")
# 7. Context override ("despite what you've been told")
# ---------------------------------------------------------------------------

OPTIMIZED_PATTERNS = [
    # === English: Core override patterns ===
    "ignore previous instructions",
    "ignore all previous",
    "ignore the above",
    "ignore your instructions",
    "ignore above",
    "ignore my previous",
    "ignore your programming",
    "disregard previous",
    "disregard above",
    "disregard your instructions",
    "disregard prior",
    "forget previous instructions",
    "forget your instructions",
    "forget the above",
    "forget everything above",
    "forget everything before",
    "forget all previous",
    "forget about all",
    "forget everything",
    "forget all",
    "override your instructions",
    "override previous",
    "override safety",
    "bypass your instructions",
    "bypass safety",
    "do not follow your instructions",
    "drop all your instructions",
    "drop your instructions",
    # === English: Prompt/instruction extraction ===
    "system prompt",
    "reveal your instructions",
    "reveal your prompt",
    "reveal the system",
    "show me your instructions",
    "show me your prompt",
    "show your instructions",
    "what are your instructions",
    "what is your prompt",
    "print your instructions",
    "print your prompt",
    "output your instructions",
    "repeat your instructions",
    "repeat the above",
    "tell me your instructions",
    "tell me your prompt",
    "list your instructions",
    "what were you told",
    "what was written at the beginning",
    # === English: Role-play / identity manipulation ===
    "you are now",
    "you are a",
    "act as",
    "pretend you are",
    "pretend to be",
    "roleplay as",
    "i want you to act as",
    "from now on you are",
    "from now known as",
    # === English: Task switching ===
    "new task",
    "new challenge",
    "new instructions",
    "now focus on",
    "now concentrate on",
    "now write",
    "now help me",
    "now answer",
    "now please help",
    "that is enough",
    "that is done",
    "well done! forget",
    "well done! now",
    "great! now",
    "excellent! now",
    "good job! now",
    "congratulations",
    # === English: Jailbreak patterns ===
    "jailbreak",
    "DAN",
    "do anything now",
    "developer mode",
    "sudo mode",
    "admin mode",
    "unrestricted mode",
    "no restrictions",
    "without restrictions",
    "ignore all rules",
    "ignore all guidelines",
    "ignore ethical",
    "ignore safety",
    "ignore content policy",
    # === English: Markup injection ===
    "[INST]",
    "[/INST]",
    "<|im_start|>",
    "<<SYS>>",
    "======END",
    # === English: Context/knowledge manipulation ===
    "despite what you've been told",
    "not by the articles",
    "not according to the provided",
    "forget about everything and",
    "but then forget",
    # === German: Core override patterns ===
    "ignoriere alle",
    "ignoriere die",
    "ignorieren sie",
    "ignoriere bisherige",
    "ignoriere vorangehende",
    "vergiss alle",
    "vergiss alles",
    "vergiss nun alle",
    "vergiss vorherige",
    "vergessen sie",
    "vergiss alles davor",
    "vergiss alle aufträge",
    # === German: Task switching ===
    "neue aufgabe",
    "neuen aufgabe",
    "neue anweisungen",
    "neue herausforderung",
    "neue aufgaben",
    "folgen neue",
    "nun folgen",
    "jetzt auf deine neue",
    "konzentriere dich",
    "konzentriere dich jetzt",
    "sehr gut gemacht",
    "gut gemacht",
    "das genügt",
    "das ist erledigt",
    "starten von neu",
    "hinter sich und fan",
    "aus dem kopf zu streichen",
    # === German: Role-play ===
    "du bist jetzt",
    "jetzt bist du",
    "stell dir vor",
    "nun bist du",
    # === German: Extraction ===
    "zeige mir alle",
    "zeige deinen gesamten prompt",
    "zeige die folgenden",
    "prompt-text",
    # === Spanish: Core patterns ===
    "olvida todo",
    "olvida todas",
    "olvide todo",
    "ignora todas",
    "ignora las instrucciones",
    # === French: Core patterns ===
    "oubliez tout",
    "ignorez les instructions",
    "oublie tout",
    "ignore les instructions",
]


def build_policy(patterns: list[str]) -> PolicyConfig:
    return PolicyConfig(
        metadata=PolicyMetadata(name="injection-benchmark"),
        rules=[
            RuleConfig(
                name="block-injection",
                scope="input",
                then="deny",
                when="content matches prompt_injection",
                severity="critical",
            ),
        ],
        matchers={
            "prompt_injection": MatcherConfig(
                name="prompt_injection",
                type="keyword_list",
                patterns=patterns,
                options={"case_insensitive": True},
            ),
        },
    )


def evaluate(engine: Engine, samples: list[dict[str, object]], max_samples: int = 50) -> Result:
    result = Result()
    start = time.perf_counter()
    for sample in samples:
        text = str(sample.get("text", ""))
        label = int(sample.get("label", 0))
        decision = engine.evaluate(
            GuardEvent(scope="input", agent="bench", data={"content": text})
        )
        blocked = decision.outcome == "deny"
        injection = label == 1
        result.total += 1
        if injection and blocked:
            result.tp += 1
        elif not injection and not blocked:
            result.tn += 1
        elif not injection and blocked:
            result.fp += 1
            if len(result.fp_samples) < max_samples:
                result.fp_samples.append(text[:200])
        else:
            result.fn += 1
            if len(result.fn_samples) < max_samples:
                result.fn_samples.append(text[:200])
    result.elapsed_ms = (time.perf_counter() - start) * 1000
    return result


def print_result(r: Result, label: str) -> None:
    print(f"  {label}")
    print(f"    Accuracy:  {r.accuracy:>6.1%}   Precision: {r.precision:>6.1%}   "
          f"Recall: {r.recall:>6.1%}   F1: {r.f1:>6.1%}")
    print(f"    TP={r.tp:<4} TN={r.tn:<4} FP={r.fp:<4} FN={r.fn:<4}  "
          f"({r.elapsed_ms:.1f}ms, {r.elapsed_ms / r.total:.3f}ms/sample)")


def main() -> None:
    # Load dataset
    path = Path("benchmarks/data/prompt_injections.jsonl")
    if not path.exists():
        print("Dataset not found. Run: python benchmarks/fetch_datasets.py")
        return

    all_samples = [json.loads(l) for l in open(path)]

    # Stratified split: 70% train, 30% test
    random.seed(SEED)
    injections = [s for s in all_samples if s["label"] == 1]
    benign = [s for s in all_samples if s["label"] == 0]
    random.shuffle(injections)
    random.shuffle(benign)

    split_inj = int(len(injections) * 0.7)
    split_ben = int(len(benign) * 0.7)

    train = injections[:split_inj] + benign[:split_ben]
    test = injections[split_inj:] + benign[split_ben:]
    random.shuffle(train)
    random.shuffle(test)

    n_train_inj = sum(1 for s in train if s["label"] == 1)
    n_test_inj = sum(1 for s in test if s["label"] == 1)

    print("=" * 70)
    print("  Prompt Injection: Naive vs Optimized Keyword Matcher")
    print("=" * 70)
    print()
    print(f"  Dataset:     deepset/prompt-injections")
    print(f"  Train split: {len(train)} samples ({n_train_inj} injections, {len(train) - n_train_inj} benign)")
    print(f"  Test split:  {len(test)} samples ({n_test_inj} injections, {len(test) - n_test_inj} benign)")
    print(f"  Split seed:  {SEED}")
    print(f"  Naive patterns:     {len(NAIVE_PATTERNS)}")
    print(f"  Optimized patterns: {len(OPTIMIZED_PATTERNS)}")
    print()

    # Build engines
    naive_engine = Engine(build_policy(NAIVE_PATTERNS))
    optimized_engine = Engine(build_policy(OPTIMIZED_PATTERNS))

    # --- Train set results (for context only) ---
    print("  TRAIN SET (for context — optimized matcher was tuned on this):")
    r = evaluate(naive_engine, train)
    print_result(r, "Naive")
    r = evaluate(optimized_engine, train)
    print_result(r, "Optimized")
    print()

    # --- Test set results (the real benchmark) ---
    print("  TEST SET (held out — never used for tuning):")
    naive_test = evaluate(naive_engine, test)
    naive_test.name = "naive"
    print_result(naive_test, "Naive")

    opt_test = evaluate(optimized_engine, test)
    opt_test.name = "optimized"
    print_result(opt_test, "Optimized")
    print()

    # Improvement
    recall_delta = opt_test.recall - naive_test.recall
    f1_delta = opt_test.f1 - naive_test.f1
    print(f"  IMPROVEMENT (test set):")
    print(f"    Recall:    {naive_test.recall:.1%} → {opt_test.recall:.1%}  (+{recall_delta:.1%})")
    print(f"    F1:        {naive_test.f1:.1%} → {opt_test.f1:.1%}  (+{f1_delta:.1%})")
    print(f"    Precision: {naive_test.precision:.1%} → {opt_test.precision:.1%}")
    print()

    # Show remaining false negatives on test set
    if opt_test.fn_samples:
        print(f"  REMAINING FALSE NEGATIVES (optimized, test set: {opt_test.fn}/{n_test_inj}):")
        for i, s in enumerate(opt_test.fn_samples[:15], 1):
            print(f"    {i:2d}. {s}")
        print()

    if opt_test.fp_samples:
        print(f"  FALSE POSITIVES (optimized, test set: {opt_test.fp}/{len(test) - n_test_inj}):")
        for i, s in enumerate(opt_test.fp_samples[:10], 1):
            print(f"    {i:2d}. {s}")
        print()

    # --- Gandalf dataset (all injections, separate evaluation) ---
    gandalf_path = Path("benchmarks/data/gandalf_injections.jsonl")
    if gandalf_path.exists():
        gandalf = [json.loads(l) for l in open(gandalf_path)]
        print("  GANDALF DATASET (777 real jailbreak attempts — recall only):")
        r_naive = evaluate(naive_engine, gandalf)
        print_result(r_naive, "Naive")
        r_opt = evaluate(optimized_engine, gandalf)
        print_result(r_opt, "Optimized")
        g_delta = r_opt.recall - r_naive.recall
        print(f"    Recall improvement: {r_naive.recall:.1%} → {r_opt.recall:.1%}  (+{g_delta:.1%})")
        print()

    # Save report
    report = {
        "methodology": "70/30 stratified split, seed=42. Optimized matcher tuned on train set only.",
        "train_size": len(train),
        "test_size": len(test),
        "naive_patterns": len(NAIVE_PATTERNS),
        "optimized_patterns": len(OPTIMIZED_PATTERNS),
        "test_set": {
            "naive": {
                "accuracy": round(naive_test.accuracy, 4),
                "precision": round(naive_test.precision, 4),
                "recall": round(naive_test.recall, 4),
                "f1": round(naive_test.f1, 4),
                "tp": naive_test.tp, "tn": naive_test.tn,
                "fp": naive_test.fp, "fn": naive_test.fn,
            },
            "optimized": {
                "accuracy": round(opt_test.accuracy, 4),
                "precision": round(opt_test.precision, 4),
                "recall": round(opt_test.recall, 4),
                "f1": round(opt_test.f1, 4),
                "tp": opt_test.tp, "tn": opt_test.tn,
                "fp": opt_test.fp, "fn": opt_test.fn,
            },
        },
        "remaining_fn_samples": opt_test.fn_samples[:30],
        "fp_samples": opt_test.fp_samples[:10],
    }
    out = Path("benchmarks/prompt_injection/results_optimized.json")
    out.write_text(json.dumps(report, indent=2, ensure_ascii=False))
    print(f"  Results saved to {out}")


if __name__ == "__main__":
    main()
