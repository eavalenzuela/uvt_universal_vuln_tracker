# F17 — Improved PDF Reports: Implementation Plan

## 1. Renderer decision — WeasyPrint

**Recommendation: WeasyPrint.** The current PDF is a hand-written 5-object stream (`backend/api/report_exports.py` lines 227-251); there is no PDF library installed at all. Of the three options:

- **ReportLab** forces manual flowables/canvas coordinates. Charts must be imaged in anyway, and non-engineers cannot edit a layout.
- **Playwright/Chromium** gives the best fidelity but adds ~500 MB to the image, a cold-start of 1-3 s per render, and a persistent browser process to manage. It is currently a dev-only dep (`requirements-dev.txt`) used for screenshots, not shipped in the production image.
- **WeasyPrint** takes Jinja-rendered HTML+CSS and produces PDF. Its native deps (pango/cairo/gdk-pixbuf) add roughly 80-120 MB to the Debian base image — noticeable but one-time. Cold-start is ~300 ms. Crucially, a non-engineer can edit a Jinja HTML template the same way they would edit an email template, and the same HTML can be previewed in a browser during development.

WeasyPrint is the right middle ground: good theming (CSS paged media, `@page`, `counter(page)`), a template a designer can own, no headless-browser runtime tax, and no monkey-patching the frontend build into the backend image. Chromium is overkill unless we commit to frontend-component reuse, which (see §2) we are not.

## 2. Chart source decision — server-side PNG via Matplotlib

**Recommendation: Matplotlib PNGs embedded as `<img>` tags.** Frontend charts today are hand-rolled SVG (e.g. `frontend/src/views/products/productDependencyGraphView.js` — literal `el("svg", …)` with no chart library at all), so there is no existing component to reuse. That eliminates the "render in browser, screenshot" option — we would be building new frontend chart code *and* a Playwright pipeline to photograph it.

Matplotlib produces deterministic PNGs with a single `figure.savefig(buf, format="png", dpi=150)` call. WeasyPrint embeds PNGs cleanly, sizes them via CSS, and the output is consistent across platforms. SVG-in-HTML would work too but Matplotlib's PNG output is simpler to theme with the tenant primary color (pass `color=theme.primary`).

Rejected alternatives: native SVG Python libs (pygal) add another dep for little gain; browser-rendered charts would need Playwright, which we just rejected.

## 3. Branding/theming surface — MVP is logo + primary color + footer text

Three fields, stored per-tenant (organization-global, not per-template):

- `logo_path` — uploaded PNG/SVG, stored under `instance/branding/<org_id>/logo.<ext>` alongside the existing `instance/report_artifacts/` convention (see `_report_dir()` in `report_exports.py`).
- `primary_color` — hex string, validated `^#[0-9a-fA-F]{6}$`. Drives chart accent, table header background, and heading color via a single CSS variable.
- `footer_text` — free-form string, rendered in the `@bottom-center` CSS region with the page number.

**Out of scope for v1:** custom CSS/HTML blobs (injection risk, large test surface, and users will not actually edit them), per-template overrides, logo in multiple variants.

**Where it lives:** a new `organization_branding` table (or columns on the existing org/tenant table — check whichever F15 adopts). F15's team-scope work does *not* change branding scope; branding is org-global, team scope only affects *which data* appears, not *how the page looks*. If F15 ships first, F17 re-uses its org model; if F17 ships first, we add branding on the tenant/org entity and F15 inherits it.

## 4. Template architecture — keep ReportTemplate, add a renderer layer

Keep `ReportTemplate.filters_json` / `fields_json` (`backend/models/reports.py`). These describe *what data* to pull; they are already used for CSV/JSON and should not be thrown away.

Add a separate concept: a small set of **named HTML layouts** shipped on disk at `backend/templates/reports/` (e.g. `executive_summary.html`, `vulnerabilities_detail.html`). `ReportTemplate` gains one nullable column `pdf_layout` (string, default `"default"`) selecting which Jinja template to render. This is additive, does not break existing CSV/JSON exports, and avoids the trap of letting users upload arbitrary HTML.

A new module `backend/services/pdf_renderer.py` takes `(layout_name, data_context, branding) -> bytes`.

## 5. Content expansions — named sections, must vs nice

**Must-have (Slice 2):**

- Executive summary strip — total open, critical count, SLA compliance %, new-this-period count. Four KPI tiles.
- Severity distribution — donut chart (Critical/High/Medium/Low/None).
- SLA status — horizontal bar (on-track / at-risk / breached).
- Appendix — full vuln table (CVE, severity, status, assignee, SLA due). This is already the CSV payload; just render as `<table>`.

**Nice-to-have (Slice 2 stretch or Slice 3):**

- Trend chart — vuln count over last N days. The data already exists in `dashboard_aggregate`'s `buckets` field (`reporting_service.py` line 80).
- Top 10 most-exploited components. Useful but requires an aggregation we do not compute today.

## 6. Async/perf — move to Celery

**Move to async.** Matplotlib + WeasyPrint + a 1000-row appendix table will take 2-10 s, and `_build_export_artifact` currently blocks the request (`report_exports.py` line 264). Celery is already installed and wired (`backend/celery_app.py`).

New task `tasks.reports.render_pdf(report_type, filters, user_id, layout, branding_id) -> artifact_id`. The API route returns `202 Accepted` with an artifact id in `pending` state; the existing `ReportArtifact` table gains a `status` column (`pending|ready|failed`). The artifact download endpoint already exists and only needs a 404/409 for non-ready rows. The frontend polls.

## 7. Testing strategy — structured, not binary

Three layers:

1. **Data-context tests** — pure-Python: given a filter set, assert the dict passed to Jinja has the right KPIs, bucket counts, severity breakdown. Fast, zero rendering.
2. **HTML snapshot tests** — render the Jinja template with a fixed context, snapshot the HTML string (normalized: strip whitespace, stable ordering). Catches template regressions without PDF diffing.
3. **One smoke test per layout** — render to PDF, assert `output[:5] == b"%PDF-"`, assert `len > 1 KB`, optionally extract text with `pdfminer.six` (test-only dep) and grep for expected headings. Do not snapshot the binary.

Chart PNGs: render to buffer in a helper, assert non-empty and PNG-magic-bytes. Do not compare pixels.

## 8. Implementation phases

**Slice 1 — renderer swap, parity with today (~2 days).** Add WeasyPrint + Jinja2 to `requirements.txt`; add `backend/services/pdf_renderer.py`; add `backend/templates/reports/default.html` reproducing the current JSON-dump output as a styled table; replace `_pdf_bytes` with the new renderer; keep the sync request path for this slice. Add Dockerfile packages for pango/cairo. Deliverable: same data, real PDF, real fonts, real page breaks.

**Slice 2 — executive summary + charts + async (~3 days).** Add Matplotlib + `pdfminer.six` (test). Add `executive_summary.html` layout with four KPI tiles, severity donut, SLA bar, appendix table. Move rendering to Celery; add `status` column on `ReportArtifact` + migration; return 202 from export endpoints. Frontend polls for ready state (minor change).

**Slice 3 — branding (~1-2 days).** Add `organization_branding` table (or columns) with logo path, primary color, footer text. Add admin upload endpoint for the logo (PNG/SVG, size-capped, content-type-validated). Inject CSS variables into all layouts. Add trend chart if there is time.

## 9. Non-goals for v1

- Email HTML digest formatting (separate roadmap item).
- PDF/UA accessibility tagging (WeasyPrint supports some of this, but certifying it is a multi-week effort).
- Digital signatures / PKI.
- Watermarks ("DRAFT", "CONFIDENTIAL").
- User-editable HTML templates.
- Per-template branding overrides.
- Multi-page executive summaries with cover art.
