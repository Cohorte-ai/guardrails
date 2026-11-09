"""Grounded numbers: every figure in a generated text should be traceable to a source.

An agent that writes a report, an email or a summary often gets the prose right and a figure
wrong. This check extracts the numbers from the generated text and looks for each one in the
sources the agent was given (tool results, documents), allowing for rounding and units: "3.2M"
is grounded by "3,215,000", "12.3%" by "12.34%" or "0.1234".

An ungrounded number is not necessarily wrong (it may be a correct sum); it is a number nobody
can trace, which is exactly when a person should look before the text goes out.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field

_SCALE = {
    "k": 1e3,
    "K": 1e3,
    "thousand": 1e3,
    "M": 1e6,
    "million": 1e6,
    "bn": 1e9,
    "B": 1e9,
    "billion": 1e9,
}

_MONTH = (
    r"(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|June?|July?|Aug(?:ust)?"
    r"|Sep(?:t(?:ember)?)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)\b\.?"
)
# A day is not followed by a separator and more digits: "March 9,999,000" and
# "March 9 999 000" are figures.
_DAY = r"(?:3[01]|[12]\d|0?[1-9])(?:st|nd|rd|th)?\b(?![.,]\d|[ \u00a0\u202f]\d{3}\b)"
# Dates are not figures: they are removed before extraction, in every common format.
_DATES = re.compile(
    r"\b\d{4}-\d{1,2}-\d{1,2}\b"  # 2026-11-09
    r"|\b\d{1,2}[/.]\d{1,2}[/.]\d{2,4}\b"  # 11/09/2026, 09.11.2026
    rf"|\b{_DAY}\s+{_MONTH}(?:,?\s+\d{{4}}\b)?"  # 14 March 2026
    rf"|\b{_MONTH}\s+{_DAY}(?:,?\s+\d{{4}}\b)?",  # March 15, 2026
    re.IGNORECASE,
)

# A number not glued to an identifier ("gpt-4.1", "Q3", "v2") or inside a date or range
# ("2026-11-09" yields 2026 only), with optional thousands separators, decimals, a percent
# sign or a magnitude word.
_NUMBER = re.compile(
    r"(?<![\w.\-/:])"
    r"(?P<sign>-)?"
    r"(?P<int>\d{1,3}(?:\.\d{3})+(?=,\d{1,2}(?!\d))"  # 1.234,56 (European decimal comma)
    r"|\d{1,3}(?:,\d{3})+"  # 1,234,567
    r"|\d{1,3}(?:\.\d{3}){2,}"  # 9.999.000 (two groups or more: 1.234 stays a decimal)
    r"|\d{1,3}(?:[ \u00a0\u202f]\d{3}){2,}"  # 9 999 000
    r"|\d+)"
    r"(?P<dec>\.\d+|,\d{1,2}(?!\d))?"  # 12.34 or 12,34 (decimal comma)
    r"(?:\s?(?P<unit>%|k|K|M|bn|B|thousand|million|billion)\b|(?P<pct>%))?"
    r"(?![\w]|\.\d)"
)


@dataclass(frozen=True)
class Figure:
    """A number as written: its text, mantissa, decimals shown, scale and percent flag."""

    text: str
    mantissa: float
    decimals: int
    scale: float
    percent: bool

    @property
    def value(self) -> float:
        return self.mantissa * self.scale


@dataclass
class Finding:
    figure: Figure
    grounded: bool
    source: str | None = None  # the source figure that grounds it


@dataclass
class GroundingReport:
    findings: list[Finding] = field(default_factory=list)

    @property
    def ungrounded(self) -> list[Finding]:
        return [f for f in self.findings if not f.grounded]

    @property
    def ok(self) -> bool:
        return not self.ungrounded

    def summary(self) -> str:
        if not self.findings:
            return "no figures to check"
        if self.ok:
            n = len(self.findings)
            return (
                f"{'the figure is' if n == 1 else f'all {n} figures are'} grounded in the sources"
            )
        bad = ", ".join(f.figure.text for f in self.ungrounded)
        return f"{len(self.ungrounded)} of {len(self.findings)} figures not found in sources: {bad}"


def extract_figures(text: str) -> list[Figure]:
    """The numbers in a text, as written."""
    out: list[Figure] = []
    text = _DATES.sub(lambda m: " " * len(m.group(0)), text)
    for m in _NUMBER.finditer(text):
        raw_int = m.group("int")
        digits = re.sub(r"[,. \u00a0\u202f]", "", raw_int)
        dec = (m.group("dec") or "").replace(",", ".")
        unit = m.group("unit") or m.group("pct")
        mantissa = float(digits + dec)
        if m.group("sign"):
            mantissa = -mantissa
        out.append(
            Figure(
                text=m.group(0).strip(),
                mantissa=mantissa,
                decimals=len(dec) - 1 if dec else 0,
                scale=_SCALE.get(unit or "", 1.0),
                percent=unit == "%",
            )
        )
    return out


def _matches(claim: Figure, source: Figure) -> bool:
    """True if the claim is the source figure, written at the claim's precision and scale."""
    candidates = [source.value]
    if claim.percent and not source.percent:
        candidates.append(source.value * 100)  # 0.1234 written as 12.34%
    if source.percent and not claim.percent:
        candidates.append(source.value / 100)
    for value in candidates:
        rounded = round(value / claim.scale, claim.decimals)
        if math.isclose(rounded, claim.mantissa, rel_tol=0, abs_tol=10 ** -(claim.decimals + 6)):
            return True
    return False


def check_numbers(
    text: str,
    sources: list[str] | str,
    *,
    ignore_small: int = 10,
    ignore: set[float] | None = None,
) -> GroundingReport:
    """Check that every figure in ``text`` appears in ``sources``.

    Parameters
    ----------
    text : str
        The generated text (report, email, answer).
    sources : str or list of str
        What the agent was given: tool results, documents, the user's message.
    ignore_small : int
        Whole numbers from 0 up to this value are not checked (counts such as "3 steps").
        Set to -1 to check every number.
    ignore : set of float, optional
        Other values not to check.
    """
    source_text = sources if isinstance(sources, str) else "\n".join(sources)
    source_figures = extract_figures(source_text)
    skip = ignore or set()
    report = GroundingReport()
    for fig in extract_figures(text):
        whole = fig.decimals == 0 and fig.scale == 1.0 and not fig.percent
        if (whole and 0 <= fig.mantissa <= ignore_small) or fig.value in skip:
            continue
        match = next((s for s in source_figures if _matches(fig, s)), None)
        report.findings.append(Finding(fig, match is not None, match.text if match else None))
    return report
