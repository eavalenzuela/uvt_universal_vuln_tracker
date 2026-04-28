"""PDF report rendering via WeasyPrint + Jinja2.

Slice 1: parity with the previous hand-written PDF — same payloads, just
rendered as styled HTML/CSS. Layouts live in ``backend/templates/reports/``
and are selected by ``layout_name``. The default layout supports the two
existing report types (``vulnerabilities`` and ``dashboard_summary``).
"""

from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape
from weasyprint import HTML

TEMPLATES_DIR = Path(__file__).resolve().parent.parent / "templates" / "reports"

_env = Environment(
    loader=FileSystemLoader(str(TEMPLATES_DIR)),
    autoescape=select_autoescape(["html"]),
    trim_blocks=True,
    lstrip_blocks=True,
)


def render_pdf(layout_name: str, context: dict) -> bytes:
    """Render ``layout_name`` (without extension) with ``context`` to PDF bytes.

    Adds ``generated_at`` (UTC ISO-8601) to the context if not provided.
    """
    ctx = dict(context or {})
    ctx.setdefault("generated_at", datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"))
    template = _env.get_template(f"{layout_name}.html")
    html = template.render(**ctx)
    return HTML(string=html).write_pdf()
