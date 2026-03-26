"""Download benchmark datasets from HuggingFace.

Requires: pip install datasets
"""

from __future__ import annotations

import csv
import json
from pathlib import Path


def fetch_prompt_injection() -> None:
    """Download deepset/prompt-injections dataset."""
    from datasets import load_dataset

    print("Fetching deepset/prompt-injections...")
    ds = load_dataset("deepset/prompt-injections", split="train")

    out = Path("benchmarks/data/prompt_injections.jsonl")
    out.parent.mkdir(parents=True, exist_ok=True)

    count = 0
    with open(out, "w", encoding="utf-8") as f:
        for row in ds:
            entry = {
                "text": row["text"],
                "label": int(row["label"]),  # 1 = injection, 0 = benign
            }
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
            count += 1

    print(f"  Saved {count} samples to {out}")

    # Stats
    labels = [int(row["label"]) for row in ds]
    n_pos = sum(labels)
    n_neg = len(labels) - n_pos
    print(f"  Positives (injection): {n_pos}")
    print(f"  Negatives (benign):    {n_neg}")


def fetch_gandalf() -> None:
    """Download Lakera/gandalf_ignore_instructions dataset."""
    from datasets import load_dataset

    print("Fetching Lakera/gandalf_ignore_instructions...")
    ds = load_dataset("Lakera/gandalf_ignore_instructions", split="train")

    out = Path("benchmarks/data/gandalf_injections.jsonl")
    out.parent.mkdir(parents=True, exist_ok=True)

    count = 0
    with open(out, "w", encoding="utf-8") as f:
        for row in ds:
            entry = {
                "text": row["text"],
                "label": 1,  # All samples are injection attempts
            }
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
            count += 1

    print(f"  Saved {count} samples to {out}")


def fetch_pii() -> None:
    """Download ai4privacy/pii-masking-400k dataset (sample)."""
    from datasets import load_dataset

    print("Fetching ai4privacy/pii-masking-400k (first 5000 samples)...")
    ds = load_dataset(
        "ai4privacy/pii-masking-400k",
        split="train",
        streaming=True,
    )

    out = Path("benchmarks/data/pii_samples.jsonl")
    out.parent.mkdir(parents=True, exist_ok=True)

    count = 0
    max_samples = 5000
    with open(out, "w", encoding="utf-8") as f:
        for row in ds:
            # The dataset has 'source_text' with PII and 'masked_text' with redactions
            # plus 'privacy_mask' with span annotations
            entry: dict[str, object] = {
                "text": row.get("source_text", ""),
                "masked_text": row.get("masked_text", ""),
                "has_pii": True,  # All samples in this dataset contain PII
            }
            # Extract PII types from privacy_mask if available
            mask = row.get("privacy_mask")
            if mask:
                if isinstance(mask, str):
                    try:
                        mask = json.loads(mask)
                    except json.JSONDecodeError:
                        mask = []
                if isinstance(mask, list):
                    pii_types = list({item.get("label", "") for item in mask if isinstance(item, dict)})
                    entry["pii_types"] = pii_types

            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
            count += 1
            if count >= max_samples:
                break

    print(f"  Saved {count} samples to {out}")


def main() -> None:
    print("=" * 60)
    print("Fetching benchmark datasets")
    print("=" * 60)
    print()

    fetch_prompt_injection()
    print()
    fetch_gandalf()
    print()
    fetch_pii()

    print()
    print("Done. Datasets saved to benchmarks/data/")


if __name__ == "__main__":
    main()
