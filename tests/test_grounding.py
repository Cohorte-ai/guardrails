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
    assert check_numbers(text, "").findings == []
    for date in ("14 March 2026", "March 15, 2026", "03/14/2026", "14.03.2026", "Nov 9th"):
        assert check_numbers(f"Signed on {date}.", "").findings == [], date


@pytest.mark.parametrize(
    ("claim", "source", "grounded"),
    [
        ("Acme signed for 9.999.000 EUR.", "3,215,000 EUR", False),
        ("Acme signed for 3.215.000 EUR.", "3,215,000 EUR", True),
        ("Revenue 9 999 000 EUR.", "9,999,000", True),
        ("Growth 12,34%.", "up 12.34%", True),
        ("Growth 21,34%.", "up 12.34%", False),
        ("We serve 12 300 sites.", "12 sites, 300 staff", True),
        ("Margin 41% in March.", "Margin 41%", True),
        ("Margin 45% in March.", "Margin 41%", False),
        ("May 2026 revenue: 3.4M.", "3,215,000", False),
    ],
)
def test_european_formats(claim: str, source: str, grounded: bool) -> None:
    assert check_numbers(claim, source).ok is grounded


def test_summary_wording() -> None:
    assert check_numbers("nothing here", "").summary() == "no figures to check"
    assert check_numbers("182 people", "182").summary() == "the figure is grounded in the sources"


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
