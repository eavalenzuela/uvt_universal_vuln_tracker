#!/usr/bin/env python3
"""Take screenshots of all UVT frontend pages for visual review.

Expects the app to already be running (e.g. via docker compose up).

Usage:
    python scripts/screenshot-pages.py --user admin --pass changeme
    python scripts/screenshot-pages.py --url http://localhost:8080 --user admin --pass changeme
    python scripts/screenshot-pages.py --pages login,dashboard --user admin --pass changeme
    python scripts/screenshot-pages.py --save-as v2.12.0-before --user admin --pass changeme

Screenshots go to screenshots/ by default (gitignored).
Use --save-as to persist snapshots into docs/images/<label>/ for changelog records.
"""

from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_URL = "http://localhost:8080"
DEFAULT_OUTPUT = REPO_ROOT / "screenshots"
DOCS_IMAGES = REPO_ROOT / "docs" / "images"

# Pages to capture — (filename, hash_route, needs_auth)
PAGES = [
    ("01-login",                       "/login",                       False),
    ("02-dashboard",                   "/",                            True),
    ("03-vulnerabilities",             "/vulnerabilities",             True),
    ("04-products",                    "/products",                    True),
    ("05-controls",                    "/controls",                    True),
    ("06-notifications",               "/notifications",               True),
    ("07-admin-users",                 "/admin/users",                 True),
    ("08-admin-plugins",               "/admin/plugins",               True),
    ("09-admin-reports",               "/admin/reports",               True),
    ("10-admin-logs",                  "/admin/logs",                  True),
    ("11-admin-notification-rules",    "/admin/notification-rules",    True),
    ("12-admin-notification-delivery", "/admin/notification-delivery", True),
    ("13-admin-api-tokens",            "/admin/api-tokens",            True),
    ("14-admin-teams",                 "/admin/teams",                 True),
    ("15-admin-branding",              "/admin/branding",              True),
]


def take_screenshots(
    base_url: str,
    output_dir: Path,
    pages: list[str] | None,
    admin_user: str,
    admin_pass: str,
    viewport_width: int = 1440,
    viewport_height: int = 900,
) -> list[Path]:
    """Launch Playwright, log in, and screenshot each page."""
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        print("ERROR: playwright not installed. Run:")
        print("  pip install playwright && playwright install chromium")
        sys.exit(1)

    output_dir.mkdir(parents=True, exist_ok=True)

    # Filter pages if requested
    page_list = list(PAGES)
    if pages:
        page_set = {p.strip().lower() for p in pages}
        page_list = [
            entry for entry in PAGES
            if entry[0] in page_set
            or entry[0].split("-", 1)[-1] in page_set
        ]

    captured: list[Path] = []

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(
            viewport={"width": viewport_width, "height": viewport_height},
            ignore_https_errors=True,
        )
        # Allow pointing the SPA at a separate backend (dev mode without nginx).
        # Set UVT_API_BASE in the environment to inject window.__UVT_API_BASE__
        # before frontend bootstrap runs.
        import os as _os
        _api_base = _os.environ.get("UVT_API_BASE")
        if _api_base:
            context.add_init_script(
                f"window.__UVT_API_BASE__ = {_api_base!r};"
            )
        page = context.new_page()

        # Capture console errors for debugging
        _console_errors = []
        page.on("console", lambda msg: _console_errors.append(
            f"  [console.{msg.type}] {msg.text}"
        ) if msg.type in ("error", "warning") else None)
        page.on("pageerror", lambda err: _console_errors.append(
            f"  [pageerror] {err}"
        ))

        def _wait_ready(pg, timeout_ms=5000):
            """Wait for JS views to render into #app-main."""
            pg.wait_for_load_state("load")
            pg.wait_for_timeout(timeout_ms)

        # ── Capture pages that don't need auth (login page) ──
        pre_auth = [x for x in page_list if not x[2]]
        for name, route, _ in pre_auth:
            url = f"{base_url}/#{route}"
            print(f"  [{name}] {url}")
            page.goto(url)
            _wait_ready(page)
            path = output_dir / f"{name}.png"
            page.screenshot(path=str(path), full_page=True)
            captured.append(path)

        # ── Authenticate ──
        auth_pages = [x for x in page_list if x[2]]
        if auth_pages:
            print("  [auth] Logging in...")
            page.goto(f"{base_url}/#/login")
            _wait_ready(page)

            # Fill login form
            inputs = page.locator("input")
            inputs.nth(0).fill(admin_user)
            inputs.nth(1).fill(admin_pass)
            page.locator(
                "button[type='submit'], "
                "button:has-text('Log in'), "
                "button:has-text('Sign in')"
            ).first.click()
            _wait_ready(page, 3000)

            # ── Capture authenticated pages ──
            for name, route, _ in auth_pages:
                url = f"{base_url}/#{route}"
                print(f"  [{name}] {url}")
                _console_errors.clear()
                page.goto(url)
                _wait_ready(page)
                if _console_errors:
                    for e in _console_errors:
                        print(e)
                path = output_dir / f"{name}.png"
                page.screenshot(path=str(path), full_page=True)
                captured.append(path)

        browser.close()

    return captured


def main():
    parser = argparse.ArgumentParser(
        description="Screenshot UVT frontend pages for visual review.",
    )
    parser.add_argument(
        "--url", default=DEFAULT_URL,
        help=f"Base URL of the running app (default: {DEFAULT_URL})",
    )
    parser.add_argument("--pages", help="Comma-separated page names to capture (default: all)")
    parser.add_argument("--output-dir", help=f"Output directory (default: screenshots/)")
    parser.add_argument(
        "--save-as",
        help="Also copy screenshots to docs/images/<label>/ for changelog records",
    )
    parser.add_argument("--user", required=True, help="Admin username")
    parser.add_argument("--pass", dest="password", required=True, help="Admin password")
    parser.add_argument("--width", type=int, default=1440, help="Viewport width (default: 1440)")
    parser.add_argument("--height", type=int, default=900, help="Viewport height (default: 900)")
    args = parser.parse_args()

    output_dir = Path(args.output_dir) if args.output_dir else DEFAULT_OUTPUT
    page_filter = args.pages.split(",") if args.pages else None

    print("UVT Screenshot Tool")
    print("=" * 40)
    print(f"Target: {args.url}")

    print(f"\n[1/2] Capturing screenshots → {output_dir}/")
    captured = take_screenshots(
        args.url, output_dir, page_filter, args.user, args.password,
        viewport_width=args.width, viewport_height=args.height,
    )

    # Optionally copy to docs/images/<label>/
    if args.save_as:
        label_dir = DOCS_IMAGES / args.save_as
        label_dir.mkdir(parents=True, exist_ok=True)
        for src in captured:
            dst = label_dir / src.name
            shutil.copy2(src, dst)
        print(f"\n  Saved to docs/images/{args.save_as}/")

    print(f"\n[2/2] Done — {len(captured)} screenshots")
    print()
    for path in captured:
        print(f"  {path.resolve()}")
    print()


if __name__ == "__main__":
    main()
