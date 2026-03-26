"""Benchmark: Prompt injection detection.

Tests theaios-guardrails keyword matcher against the deepset/prompt-injections
dataset (662 labeled samples) and optionally the Lakera Gandalf dataset.

Produces: confusion matrix, precision, recall, F1, per-category breakdown.
"""

from __future__ import annotations

import json
import time
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from theaios.guardrails import Engine, GuardEvent
from theaios.guardrails.types import (
    MatcherConfig,
    PolicyConfig,
    PolicyMetadata,
    RuleConfig,
)


@dataclass
class BenchmarkResult:
    total: int = 0
    tp: int = 0  # True positive: injection correctly blocked
    tn: int = 0  # True negative: benign correctly allowed
    fp: int = 0  # False positive: benign incorrectly blocked
    fn: int = 0  # False negative: injection incorrectly allowed
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


def build_injection_policy() -> PolicyConfig:
    """Build a policy with only the prompt injection rule, using our standard matcher."""
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
                patterns=[
                    "ignore previous instructions",
                    "ignore all previous",
                    "ignore the above",
                    "ignore your instructions",
                    "disregard previous",
                    "disregard above",
                    "disregard your instructions",
                    "forget previous instructions",
                    "forget your instructions",
                    "forget the above",
                    "do not follow your instructions",
                    "override your instructions",
                    "override previous",
                    "override safety",
                    "bypass your instructions",
                    "bypass safety",
                    "you are now",
                    "you are a",
                    "act as",
                    "pretend you are",
                    "pretend to be",
                    "roleplay as",
                    "system prompt",
                    "reveal your instructions",
                    "reveal your prompt",
                    "reveal the system",
                    "show me your instructions",
                    "show me your prompt",
                    "what are your instructions",
                    "what is your prompt",
                    "print your instructions",
                    "output your instructions",
                    "repeat your instructions",
                    "repeat the above",
                    "jailbreak",
                    "DAN",
                    "do anything now",
                    "[INST]",
                    "[/INST]",
                    "<|im_start|>",
                    "<<SYS>>",
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
                    "ignore your programming",
                ],
                options={"case_insensitive": True},
            ),
        },
    )


def load_dataset(path: str) -> list[dict[str, object]]:
    """Load a JSONL dataset."""
    samples: list[dict[str, object]] = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                samples.append(json.loads(line))
    return samples


def evaluate_dataset(
    engine: Engine,
    samples: list[dict[str, object]],
    max_fn_samples: int = 50,
    max_fp_samples: int = 50,
) -> BenchmarkResult:
    """Run all samples through the engine and compute metrics."""
    result = BenchmarkResult()

    start = time.perf_counter()
    for sample in samples:
        text = str(sample.get("text", ""))
        label = int(sample.get("label", 0))  # 1 = injection, 0 = benign

        decision = engine.evaluate(
            GuardEvent(scope="input", agent="benchmark", data={"content": text})
        )

        is_blocked = decision.outcome == "deny"
        is_injection = label == 1

        result.total += 1
        if is_injection and is_blocked:
            result.tp += 1
        elif not is_injection and not is_blocked:
            result.tn += 1
        elif not is_injection and is_blocked:
            result.fp += 1
            if len(result.fp_samples) < max_fp_samples:
                result.fp_samples.append(text[:200])
        elif is_injection and not is_blocked:
            result.fn += 1
            if len(result.fn_samples) < max_fn_samples:
                result.fn_samples.append(text[:200])

    result.elapsed_ms = (time.perf_counter() - start) * 1000
    return result


def print_report(name: str, result: BenchmarkResult) -> None:
    """Print a formatted benchmark report."""
    print(f"\n{'=' * 60}")
    print(f"  {name}")
    print(f"{'=' * 60}")
    print()
    print("  Confusion Matrix:")
    print(f"                    Predicted DENY    Predicted ALLOW")
    print(f"  Actual injection:   TP = {result.tp:<12}  FN = {result.fn}")
    print(f"  Actual benign:      FP = {result.fp:<12}  TN = {result.tn}")
    print()
    print(f"  Total samples:  {result.total}")
    print(f"  Accuracy:       {result.accuracy:.1%}")
    print(f"  Precision:      {result.precision:.1%}")
    print(f"  Recall:         {result.recall:.1%}")
    print(f"  F1 Score:       {result.f1:.1%}")
    print(f"  Eval time:      {result.elapsed_ms:.1f}ms ({result.elapsed_ms / result.total:.3f}ms/sample)")
    print()

    if result.fn_samples:
        print(f"  --- False Negatives (missed injections, showing {len(result.fn_samples)}/{result.fn}) ---")
        for i, s in enumerate(result.fn_samples[:20], 1):
            print(f"    {i:2d}. {s}")
        print()

    if result.fp_samples:
        print(f"  --- False Positives (benign blocked, showing {len(result.fp_samples)}/{result.fp}) ---")
        for i, s in enumerate(result.fp_samples[:20], 1):
            print(f"    {i:2d}. {s}")
        print()


def main() -> None:
    policy = build_injection_policy()
    engine = Engine(policy)

    print("Prompt Injection Detection Benchmark")
    print("Policy: keyword_list matcher with 50+ injection patterns")
    print("Engine: theaios-guardrails v0.1.0")
    print()

    # Benchmark 1: deepset/prompt-injections
    deepset_path = Path("benchmarks/data/prompt_injections.jsonl")
    if deepset_path.exists():
        samples = load_dataset(str(deepset_path))
        result = evaluate_dataset(engine, samples)
        print_report("deepset/prompt-injections (662 samples)", result)

        # Save detailed results
        report = {
            "dataset": "deepset/prompt-injections",
            "total": result.total,
            "tp": result.tp,
            "tn": result.tn,
            "fp": result.fp,
            "fn": result.fn,
            "accuracy": round(result.accuracy, 4),
            "precision": round(result.precision, 4),
            "recall": round(result.recall, 4),
            "f1": round(result.f1, 4),
            "eval_time_ms": round(result.elapsed_ms, 2),
            "ms_per_sample": round(result.elapsed_ms / result.total, 4),
            "fn_samples": result.fn_samples,
            "fp_samples": result.fp_samples,
        }
        Path("benchmarks/prompt_injection/results_deepset.json").write_text(
            json.dumps(report, indent=2, ensure_ascii=False)
        )
    else:
        print(f"  Dataset not found: {deepset_path}")
        print("  Run: python benchmarks/fetch_datasets.py")

    # Benchmark 2: Lakera Gandalf (all injections — measures recall only)
    gandalf_path = Path("benchmarks/data/gandalf_injections.jsonl")
    if gandalf_path.exists():
        samples = load_dataset(str(gandalf_path))
        result = evaluate_dataset(engine, samples)
        print_report("Lakera/gandalf_ignore_instructions (all injections)", result)

        report = {
            "dataset": "Lakera/gandalf_ignore_instructions",
            "total": result.total,
            "tp": result.tp,
            "fn": result.fn,
            "recall": round(result.recall, 4),
            "eval_time_ms": round(result.elapsed_ms, 2),
            "fn_samples": result.fn_samples[:50],
        }
        Path("benchmarks/prompt_injection/results_gandalf.json").write_text(
            json.dumps(report, indent=2, ensure_ascii=False)
        )
    else:
        print(f"  Dataset not found: {gandalf_path}")
        print("  Run: python benchmarks/fetch_datasets.py")


if __name__ == "__main__":
    main()
