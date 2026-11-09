"""Grounded numbers."""

from __future__ import annotations

import pytest

from theaios.guardrails.grounding import check_numbers, extract_figures

SOURCE = """
Q3 revenue: 3,215,000 EUR (up 12.34% on Q2). Churn 0.047. Headcount 182.
Report generated 2026-11-09 by gpt-4.1. Margin 41%.
"""


@pytest.mark.parametrize(
    "claim",
    [
        "Revenue was 3,215,000 EUR.",
        "Revenue reached €3.2M.",
        "Revenue reached 3.215 million euros.",
        "Revenue grew 12.3% quarter on quarter.",
        "Revenue grew 12% quarter on quarter.",
        "Churn was 4.7%.",
        "We are 182 people.",
        "Margin stayed at 41%.",
        "Margin stayed at 0.41 of revenue.",
    ],
)
def test_grounded(claim: str) -> None:
    report = check_numbers(claim, SOURCE)
    assert report.ok, report.summary()
    assert report.findings


@pytest.mark.parametrize(
    ("claim", "bad"),
    [
        ("Revenue reached €3.4M.", "3.4M"),
        ("Revenue grew 21.3% quarter on quarter.", "21.3%"),
        ("We are 128 people.", "128"),
        ("Churn was 7.4%.", "7.4%"),
        ("Revenue was 3,251,000 EUR.", "3,251,000"),
    ],
)
def test_ungrounded(claim: str, bad: str) -> None:
    report = check_numbers(claim, SOURCE)
    assert not report.ok
    assert [f.figure.text for f in report.ungrounded] == [bad]
    assert bad in report.summary()


def test_identifiers_dates_and_small_counts_are_not_claims() -> None:
    text = "In Q3, gpt-4.1 wrote 3 sections on 2026-11-09 using model v2."
    report = check_numbers(text, "")
    assert [f.figure.text for f in report.findings] == ["2026"]  # the year is checked
    assert check_numbers(text, "dated 2026").ok


def test_ignore_options() -> None:
    assert not check_numbers("3 steps", "", ignore_small=-1).ok
    assert check_numbers("3 steps", "").ok
    assert check_numbers("budget 500", "", ignore={500}).ok


def test_extraction_details() -> None:
    figs = {f.text: f for f in extract_figures("-4.5% then 1,200 and 7 bn and 2k")}
    assert figs["-4.5%"].mantissa == -4.5 and figs["-4.5%"].percent
    assert figs["1,200"].value == 1200
    assert figs["7 bn"].value == 7e9
    assert figs["2k"].value == 2000
