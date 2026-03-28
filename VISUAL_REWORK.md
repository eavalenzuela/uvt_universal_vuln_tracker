# Visual Rework Plan

Assessment and improvement plan for the UVT frontend visual design.

---

## Current State

The app has a dark theme (#0b0d12 background, #e6e8ee text, #2563eb accent) with a fixed sidebar + header layout. It's functional but has structural issues that make it hard to maintain and improve.

**What works well:**
- Consistent dark color palette
- System font stack (fast, native feel)
- Card-based layout pattern
- Focus outlines for accessibility
- Toast notifications and modal overlays

**What needs rework:**

---

## V1. Extract Inline Styles to CSS
**Priority:** High | **Effort:** Large

The majority of styling lives as inline `style:` strings in JavaScript — dashboard widget colors, badge colors, layout positioning, spacing, and more. This makes design changes require editing JS files across the codebase.

Examples:
- `dashboardConstants.js` defines `WIDGET_BORDER`, `WIDGET_BG`, `WIDGET_SURFACE` as JS constants
- `severityBadge()` builds inline style strings with hardcoded color maps
- Header notification dropdown uses inline `position:absolute; right:12px; top:56px; width:360px;`
- Nearly every view builds styles via string concatenation in `el()` calls

**What to do:**
- Audit all `style:` attributes in `el()` calls across `src/`
- Create CSS classes for recurring patterns: `.severity-critical`, `.severity-high`, `.widget-card`, `.dropdown-panel`, etc.
- Move all color constants from JS to CSS custom properties
- Keep only truly dynamic styles (e.g., computed positions) inline

---

## V2. CSS Custom Properties (Design Tokens)
**Priority:** High | **Effort:** Small

All colors are hardcoded — in CSS files, in JS constants, and in inline styles. There's no single source of truth for the color palette.

**What to do:**
Add to `base.css`:
```css
:root {
  --color-bg: #0b0d12;
  --color-surface: #0f1320;
  --color-surface-raised: rgba(255,255,255,0.04);
  --color-border: rgba(255,255,255,0.08);
  --color-border-subtle: rgba(255,255,255,0.12);
  --color-text: #e6e8ee;
  --color-text-muted: rgba(230,232,238,0.7);
  --color-accent: #2563eb;
  --color-accent-subtle: rgba(106,169,255,0.18);
  --color-focus: #6aa9ff;

  --severity-critical: #dc2626;
  --severity-high: #f59e0b;
  --severity-medium: #eab308;
  --severity-low: #22c55e;
  --severity-none: #64748b;

  --radius-sm: 8px;
  --radius-md: 10px;
  --radius-lg: 12px;
  --spacing-xs: 4px;
  --spacing-sm: 8px;
  --spacing-md: 12px;
  --spacing-lg: 16px;
  --spacing-xl: 24px;
}
```

Replace all hardcoded values with `var(--token-name)`. This also enables future light-theme support via a `.theme-light` class override.

---

## V3. Responsive / Mobile Layout
**Priority:** High | **Effort:** Medium

The layout uses a fixed `grid-template-columns: 240px 1fr` with no breakpoints. On screens narrower than ~800px the sidebar consumes too much space and content is cramped.

**What to do:**
- Add media query breakpoints to `layout.css`:
  - `< 768px`: collapse sidebar to hamburger menu overlay
  - `768–1024px`: narrow sidebar (icons only, expand on hover)
  - `> 1024px`: current layout
- Make dashboard widget grid responsive (1 column on mobile, 2 on tablet, 3 on desktop)
- Ensure filter rows wrap on narrow screens
- Test notification dropdown positioning on small screens

---

## V4. Consistent Spacing System
**Priority:** Medium | **Effort:** Medium

Spacing uses arbitrary values: 4, 8, 10, 12, 14, 16px with no clear system. Elements like `{ style: "height:10px" }` are used as ad-hoc spacers.

**What to do:**
- Adopt a 4px base scale: 4, 8, 12, 16, 24, 32, 48
- Use CSS custom properties (`--spacing-*`) everywhere
- Replace ad-hoc spacer divs with margin/gap on parent containers

---

## V5. Loading & Empty States
**Priority:** Medium | **Effort:** Medium

When data is loading or absent, most views show nothing or a brief "No records" text. There are no skeleton loaders, spinner animations, or illustrated empty states.

**What to do:**
- Add a CSS spinner animation (`.loading-spinner`)
- Create skeleton placeholder components for cards, tables, and lists
- Design empty-state illustrations or icons with helpful messages ("No vulnerabilities match your filters")
- Add `withLoading()` wrapper consistently to all data-fetching views

---

## ~~V6. Table / Data Grid Component~~ ✅ Done (v5.0.0)
Created reusable `DataTable` component (`frontend/src/ui/components/dataTable.js`) with sortable column headers, row striping, sticky header, compact/comfortable density toggle, loading/empty states, and pagination helper. Refactored admin views (users, audit logs, notification delivery) from cards/manual tables to DataTable. Kept cards for vulnerability list and dashboard where visual hierarchy helps.

---

## V7. Hover & Interactive States
**Priority:** Medium | **Effort:** Small

CSS defines minimal interactive states. No hover effects on buttons, cards, or nav links beyond what the browser provides. No transition smoothing.

**What to do:**
```css
.btn { transition: background 0.15s, border-color 0.15s; }
.btn:hover { background: rgba(255,255,255,0.1); }
.card { transition: border-color 0.15s; }
.card:hover { border-color: rgba(255,255,255,0.15); }
.nav a { transition: background 0.15s; }
.nav a:hover { background: rgba(255,255,255,0.06); }
```

---

## V8. Badge & Status Pill System
**Priority:** Low | **Effort:** Small

Severity badges and status pills are built inline in JS with hardcoded color maps. Multiple functions (`severityBadge()` in dashboardConstants.js, `severityBadge()` in vulnShared.js, `statusPill()`) each define their own colors.

**What to do:**
- Consolidate into CSS classes: `.badge-critical`, `.badge-high`, `.pill-open`, `.pill-resolved`, etc.
- Single JS helper that returns `el("span", { class: "badge badge-critical" }, "Critical")`
- Colors defined once in CSS custom properties

---

## V9. Typography Scale
**Priority:** Low | **Effort:** Small

Font sizes are inconsistent — `18px` page titles, `12px` inbox items, default body size, with no defined scale.

**What to do:**
- Define a type scale in CSS:
  ```css
  --text-xs: 11px;
  --text-sm: 13px;
  --text-base: 15px;
  --text-lg: 18px;
  --text-xl: 22px;
  --text-2xl: 28px;
  ```
- Apply consistently via classes: `.text-sm`, `.text-lg`, `.page-title`

---

## ~~V10. Light Theme Option~~ ✅ Done (v6.0.0)
Added `[data-theme="light"]` overrides for all CSS custom properties in `base.css`. Converted all remaining hardcoded colors in `components.css`, `layout.css`, and inline JS styles to CSS variables. Theme toggle button (sun/moon) in header, preference persisted in localStorage (`uvt.theme.v1`), defaults to OS `prefers-color-scheme`. Theme state module at `frontend/src/state/theme.js`, initialized before first render in `main.js`.

---

## Implementation Order

```
V2 (CSS variables)  →  V1 (extract inline styles)  →  V7 (hover states)
                    →  V8 (badge system)
                    →  V4 (spacing)
                    →  V9 (typography)
V3 (responsive)
V5 (loading states)
V6 (data tables)
V10 (light theme) — after V1 + V2
```

V2 should be done first since V1, V8, V9, and V10 all depend on having design tokens in place.

---

## Summary

| ID | Priority | Effort | Description |
|----|----------|--------|-------------|
| V1 | High | Large | Extract inline styles from JS to CSS |
| V2 | High | Small | CSS custom properties / design tokens |
| V3 | High | Medium | Responsive / mobile layout |
| V4 | Medium | Medium | Consistent spacing system |
| V5 | Medium | Medium | Loading & empty states |
| ~~V6~~ | ~~Medium~~ | ~~Medium~~ | ~~Table / data grid component~~ ✅ |
| V7 | Medium | Small | Hover & interactive states |
| V8 | Low | Small | Badge & status pill CSS classes |
| V9 | Low | Small | Typography scale |
| ~~V10~~ | ~~Low~~ | ~~Medium~~ | ~~Light theme option~~ ✅ |
