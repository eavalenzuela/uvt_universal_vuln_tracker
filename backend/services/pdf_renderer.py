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


DEFAULT_BRANDING = {
    "primary_color": "#2563eb",
    "footer_text": "",
    "logo_data_uri": None,
}


def _load_branding() -> dict:
    """Read OrganizationBranding row (Slice 3) and return a render dict.

    Falls back to DEFAULT_BRANDING when the table doesn't exist or no row
    is configured. Imported lazily so the renderer doesn't drag SQLAlchemy
    into pure-template tests.
    """
    try:
        from ..models import OrganizationBranding  # type: ignore
    except ImportError:
        return dict(DEFAULT_BRANDING)
    try:
        row = OrganizationBranding.query.first()
    except Exception:
        return dict(DEFAULT_BRANDING)
    if not row:
        return dict(DEFAULT_BRANDING)
    return {
        "primary_color": row.primary_color or DEFAULT_BRANDING["primary_color"],
        "footer_text": row.footer_text or "",
        "logo_data_uri": row.logo_data_uri() if hasattr(row, "logo_data_uri") else None,
    }


def render_pdf(layout_name: str, context: dict) -> bytes:
    """Render ``layout_name`` (without extension) with ``context`` to PDF bytes.

    Adds ``generated_at`` (UTC) and ``branding`` to the context if not provided.
    """
    ctx = dict(context or {})
    ctx.setdefault("generated_at", datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"))
    if "branding" not in ctx:
        ctx["branding"] = _load_branding()
    template = _env.get_template(f"{layout_name}.html")
    html = template.render(**ctx)
    return HTML(string=html).write_pdf()
