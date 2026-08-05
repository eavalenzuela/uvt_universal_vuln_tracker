"""Severity/CVSS agreement.

The API accepted ``severity="Critical"`` alongside ``cvss_score=5.5``, and the
list rendered both without comment. In a vulnerability tracker those two fields
are the basis of every triage decision and every SLA clock, so letting them
contradict each other silently means the queue cannot be trusted.

The CVSS v3.x qualitative ratings (specification section 5) are the reference:

    0.0        None
    0.1 – 3.9  Low
    4.0 – 6.9  Medium
    7.0 – 8.9  High
    9.0 – 10.0 Critical

Deliberate disagreement is legitimate — a Medium CVSS may be Critical in a
particular deployment, or a scanner's rating may be wrong. So this warns and
records rather than rejecting: callers get the derived severity and a message
to surface, and the stored value stays whatever the analyst chose.
"""

from __future__ import annotations

from decimal import Decimal, InvalidOperation

# (inclusive lower bound, inclusive upper bound, rating)
CVSS_V3_RATINGS = (
    (Decimal("0.0"), Decimal("0.0"), "None"),
    (Decimal("0.1"), Decimal("3.9"), "Low"),
    (Decimal("4.0"), Decimal("6.9"), "Medium"),
    (Decimal("7.0"), Decimal("8.9"), "High"),
    (Decimal("9.0"), Decimal("10.0"), "Critical"),
)

SEVERITY_ORDER = ("None", "Low", "Medium", "High", "Critical")


def severity_for_cvss(score) -> str | None:
    """Map a CVSS base score to its qualitative rating, or None if unusable."""
    if score is None or score == "":
        return None
    try:
        value = Decimal(str(score))
    except (InvalidOperation, TypeError, ValueError):
        return None
    if value < 0 or value > 10:
        return None
    for low, high, rating in CVSS_V3_RATINGS:
        if low <= value <= high:
            return rating
    return None


def check_severity_consistency(severity: str | None, cvss_score) -> dict | None:
    """Compare a declared severity against the one its CVSS score implies.

    Returns ``None`` when they agree (or when there is nothing to compare),
    otherwise a dict describing the mismatch and how far apart the two are.
    """
    derived = severity_for_cvss(cvss_score)
    if derived is None or not severity:
        return None
    if derived == severity:
        return None

    try:
        distance = abs(SEVERITY_ORDER.index(severity) - SEVERITY_ORDER.index(derived))
    except ValueError:
        distance = None

    return {
        "declared_severity": severity,
        "derived_severity": derived,
        "cvss_score": str(cvss_score),
        "levels_apart": distance,
        "message": (
            f"Severity is set to {severity} but CVSS {cvss_score} rates as {derived}. "
            "Keep it if the deployment context justifies the difference; "
            "otherwise correct one of the two."
        ),
    }
