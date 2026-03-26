"""Benchmark: PII detection.

Tests theaios-guardrails PII matcher against the ai4privacy/pii-masking-400k
dataset. Measures detection rate across PII types.

Note: This benchmark tests DETECTION (does the matcher find PII in the text?),
not EXTRACTION (does it find the exact spans?). Our matcher returns bool,
not span offsets.
"""

from __future__ import annotations

import json
import time
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from theaios.guardrails.matchers import get_matcher
from theaios.guardrails.types import MatcherConfig


# Map ai4privacy labels to our matcher's built-in pattern names
LABEL_MAP: dict[str, str | None] = {
    "email": "email",
    "EMAIL": "email",
    "phone_number": "phone",
    "PHONENUMBER": "phone",
    "phone": "phone",
    "ssn": "ssn",
    "SSN": "ssn",
    "credit_card_number": "credit_card",
    "CREDITCARDNUMBER": "credit_card",
    "ip_address": "ipv4",
    "IPADDRESS": "ipv4",
    "iban": "iban",
    "IBAN": "iban",
    # Types our regex matcher doesn't cover (expected misses)
    "name": None,
    "NAME": None,
    "FIRSTNAME": None,
    "LASTNAME": None,
    "firstname": None,
    "lastname": None,
    "address": None,
    "ADDRESS": None,
    "STREETADDRESS": None,
    "street_address": None,
    "date_of_birth": None,
    "DATEOFBIRTH": None,
    "DATE": None,
    "CITY": None,
    "STATE": None,
    "ZIPCODE": None,
    "COUNTRY": None,
    "USERNAME": None,
    "PASSWORD": None,
    "COMPANYNAME": None,
    "JOBTITLE": None,
    "URL": None,
    "SEX": None,
    "GENDER": None,
    "AGE": None,
    "ETHEREUMADDRESS": None,
    "BITCOINADDRESS": None,
    "CURRENCYNAME": None,
    "CURRENCYSYMBOL": None,
    "CURRENCYCODE": None,
    "AMOUNT": None,
    "TIME": None,
    "VEHICLEIDENTIFICATIONNUMBER": None,
    "VEHICLEVRM": None,
    "UKNINUMBER": None,
    "NEABORHOODNAME": None,
    "BUILDINGNUMBER": None,
    "SECONDARYADDRESS": None,
    "PREFIX": None,
    "ACCOUNTNUMBER": None,
    "ACCOUNTNAME": None,
    "ORDINALDIRECTION": None,
    "MASKEDNUMBER": None,
    "MIDDLENAME": None,
    "COUNTY": None,
    "SUFFIX": None,
    "USERAGENT": None,
    "EYECOLOR": None,
    "NEARBYSTREET": None,
    "LITECOINADDRESS": None,
    "HEIGHT": None,
    "PIN": None,
    "CURRENCYAMOUNT": None,
    "TITLE": None,
    "PHONECOUNTRYCODE": None,
    "PHONEEXTENSION": None,
    "MONEY": None,
    "MAC": None,
    "IMEI": None,
    "DOB": None,
}


@dataclass
class PIIResult:
    """Results for a specific PII type."""

    pii_type: str
    total: int = 0
    detected: int = 0
    missed: int = 0
    missed_samples: list[str] = field(default_factory=list)

    @property
    def detection_rate(self) -> float:
        return self.detected / self.total if self.total > 0 else 0.0


@dataclass
class BenchmarkResult:
    total_samples: int = 0
    samples_with_detectable_pii: int = 0
    samples_detected: int = 0
    samples_missed: int = 0
    elapsed_ms: float = 0.0
    by_type: dict[str, PIIResult] = field(default_factory=dict)
    unsupported_types: dict[str, int] = field(default_factory=lambda: defaultdict(int))

    @property
    def detection_rate(self) -> float:
        if self.samples_with_detectable_pii == 0:
            return 0.0
        return self.samples_detected / self.samples_with_detectable_pii


def load_dataset(path: str) -> list[dict[str, object]]:
    """Load a JSONL dataset."""
    samples: list[dict[str, object]] = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                samples.append(json.loads(line))
    return samples


def evaluate_pii(samples: list[dict[str, object]]) -> BenchmarkResult:
    """Run PII detection benchmark."""
    # Use the built-in PII matcher with no custom patterns
    matcher = get_matcher("pii", MatcherConfig(name="pii", type="pii", patterns={}))

    result = BenchmarkResult()

    start = time.perf_counter()
    for sample in samples:
        text = str(sample.get("text", ""))
        pii_types_raw = sample.get("pii_types", [])
        pii_types = pii_types_raw if isinstance(pii_types_raw, list) else []

        result.total_samples += 1

        # Determine which PII types in this sample our matcher CAN detect
        detectable_types: list[str] = []
        for pt in pii_types:
            mapped = LABEL_MAP.get(str(pt))
            if mapped is not None:
                detectable_types.append(mapped)
            else:
                result.unsupported_types[str(pt)] += 1

        if not detectable_types:
            continue  # No detectable PII types in this sample

        result.samples_with_detectable_pii += 1

        # Check if the matcher detects anything
        detected = matcher.match(text)
        if detected:
            result.samples_detected += 1
        else:
            result.samples_missed += 1

        # Per-type analysis
        for pt in detectable_types:
            if pt not in result.by_type:
                result.by_type[pt] = PIIResult(pii_type=pt)
            type_result = result.by_type[pt]
            type_result.total += 1

            type_detected = matcher.match(text, pattern_name=pt)
            if type_detected:
                type_result.detected += 1
            else:
                type_result.missed += 1
                if len(type_result.missed_samples) < 10:
                    type_result.missed_samples.append(text[:200])

    result.elapsed_ms = (time.perf_counter() - start) * 1000
    return result


def print_report(result: BenchmarkResult) -> None:
    """Print formatted benchmark report."""
    print(f"\n{'=' * 60}")
    print("  PII Detection Benchmark")
    print(f"{'=' * 60}")
    print()
    print(f"  Total samples:              {result.total_samples}")
    print(f"  Samples with detectable PII:{result.samples_with_detectable_pii}")
    print(f"  Detected:                   {result.samples_detected}")
    print(f"  Missed:                     {result.samples_missed}")
    print(f"  Detection rate:             {result.detection_rate:.1%}")
    print(f"  Eval time:                  {result.elapsed_ms:.1f}ms")
    if result.total_samples > 0:
        print(f"  Per sample:                 {result.elapsed_ms / result.total_samples:.3f}ms")
    print()

    # Per-type breakdown
    if result.by_type:
        print("  Per-Type Detection Rate:")
        print(f"  {'Type':<15} {'Total':>8} {'Detected':>10} {'Missed':>8} {'Rate':>8}")
        print(f"  {'-' * 51}")
        for pt in sorted(result.by_type.keys()):
            tr = result.by_type[pt]
            print(f"  {tr.pii_type:<15} {tr.total:>8} {tr.detected:>10} {tr.missed:>8} {tr.detection_rate:>7.1%}")
        print()

    # Unsupported types (informational)
    if result.unsupported_types:
        print("  Unsupported PII types (not covered by regex matcher):")
        for pt, count in sorted(result.unsupported_types.items(), key=lambda x: -x[1])[:15]:
            print(f"    {pt}: {count} occurrences")
        print()
        print("  Note: Names, addresses, dates, and other entity types require")
        print("  NER models, not regex. Our matcher focuses on structured PII")
        print("  (SSN, email, phone, credit card, IBAN, IP) which has fixed formats.")
        print()

    # Missed samples for detectable types
    for pt in sorted(result.by_type.keys()):
        tr = result.by_type[pt]
        if tr.missed_samples:
            print(f"  --- Missed {pt} samples (showing {len(tr.missed_samples)}/{tr.missed}) ---")
            for i, s in enumerate(tr.missed_samples[:5], 1):
                print(f"    {i}. {s}")
            print()


def main() -> None:
    print("PII Detection Benchmark")
    print("Matcher: built-in PII (regex: SSN, email, phone, credit_card, IBAN, IP)")
    print("Engine: theaios-guardrails v0.1.0")
    print()

    dataset_path = Path("benchmarks/data/pii_samples.jsonl")
    if not dataset_path.exists():
        print(f"Dataset not found: {dataset_path}")
        print("Run: python benchmarks/fetch_datasets.py")
        return

    samples = load_dataset(str(dataset_path))
    result = evaluate_pii(samples)
    print_report(result)

    # Save results
    report = {
        "dataset": "ai4privacy/pii-masking-400k (5000 sample)",
        "total_samples": result.total_samples,
        "samples_with_detectable_pii": result.samples_with_detectable_pii,
        "samples_detected": result.samples_detected,
        "samples_missed": result.samples_missed,
        "detection_rate": round(result.detection_rate, 4),
        "eval_time_ms": round(result.elapsed_ms, 2),
        "by_type": {
            pt: {
                "total": tr.total,
                "detected": tr.detected,
                "missed": tr.missed,
                "detection_rate": round(tr.detection_rate, 4),
            }
            for pt, tr in result.by_type.items()
        },
        "unsupported_types": dict(result.unsupported_types),
    }
    Path("benchmarks/pii_detection/results.json").write_text(
        json.dumps(report, indent=2, ensure_ascii=False)
    )
    print("Results saved to benchmarks/pii_detection/results.json")


if __name__ == "__main__":
    main()
