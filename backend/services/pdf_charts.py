"""Matplotlib chart helpers for PDF reports (F17 Slice 2).

Each helper returns a base64-encoded PNG ``data:`` URI that templates can
drop straight into ``<img src="...">``. Using data URIs avoids leaking
filesystem paths into the WeasyPrint render context and keeps the output
self-contained.

We pin the non-interactive ``Agg`` backend at import time so headless
workers (Celery or sync) don't try to attach to a display.
"""

from __future__ import annotations

import base64
import io

import matplotlib

matplotlib.use("Agg")  # noqa: E402 — must precede pyplot import
import matplotlib.pyplot as plt  # noqa: E402

DEFAULT_PRIMARY = "#2563eb"

SEVERITY_COLORS = {
    "Critical": "#b91c1c",
    "High": "#ea580c",
    "Medium": "#ca8a04",
    "Low": "#16a34a",
    "None": "#6b7280",
}

SLA_COLORS = {
    "on_track": "#16a34a",
    "at_risk": "#ca8a04",
    "breached": "#b91c1c",
}


def _png_data_uri(fig) -> str:
    buf = io.BytesIO()
    fig.savefig(buf, format="png", dpi=150, bbox_inches="tight")
    plt.close(fig)
    encoded = base64.b64encode(buf.getvalue()).decode("ascii")
    return f"data:image/png;base64,{encoded}"


def severity_donut(by_severity: dict[str, int], primary_color: str = DEFAULT_PRIMARY) -> str | None:
    """Render a severity donut chart from {severity_label: count}."""
    if not by_severity or not any(by_severity.values()):
        return None
    order = ["Critical", "High", "Medium", "Low", "None"]
    labels, values, colors = [], [], []
    for sev in order:
        count = by_severity.get(sev, 0)
        if count <= 0:
            continue
        labels.append(f"{sev} ({count})")
        values.append(count)
        colors.append(SEVERITY_COLORS.get(sev, primary_color))

    fig, ax = plt.subplots(figsize=(4.0, 3.0))
    ax.pie(
        values,
        labels=labels,
        colors=colors,
        startangle=90,
        wedgeprops={"width": 0.4, "edgecolor": "white"},
        textprops={"fontsize": 9},
    )
    ax.set_aspect("equal")
    return _png_data_uri(fig)


def sla_bar(sla_status: dict[str, int], primary_color: str = DEFAULT_PRIMARY) -> str | None:
    """Render a horizontal bar chart for SLA bucket counts.

    Accepts {"on_track": int, "at_risk": int, "breached": int}.
    """
    buckets = ["on_track", "at_risk", "breached"]
    values = [int(sla_status.get(b, 0) or 0) for b in buckets]
    if not any(values):
        return None
    labels = ["On track", "At risk", "Breached"]
    colors = [SLA_COLORS[b] for b in buckets]

    fig, ax = plt.subplots(figsize=(5.5, 1.8))
    ax.barh(labels, values, color=colors)
    ax.invert_yaxis()
    for spine in ("top", "right"):
        ax.spines[spine].set_visible(False)
    ax.tick_params(axis="both", labelsize=9)
    for i, v in enumerate(values):
        ax.text(v, i, f" {v}", va="center", fontsize=9)
    ax.set_xlim(0, max(values) * 1.15 if max(values) else 1)
    return _png_data_uri(fig)
