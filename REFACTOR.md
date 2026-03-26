# Refactor Work

## Purpose
This app needs a re-assessment of its design, both front and backend. It will be re-factored in 2 ways:
* module-by-module (code analysis)
* webpage-by-webpage (screenshot visual design analysis)

## Goals
[x] Document each backend source module (high level)
    [x] Create a BACKEND.md wiki file
[x] Document each webpage (high level)
    [x] Create a FRONTEND.md wiki file
[x] Identify security fixes and redesigns
    [x] Create a SECURITY_FIXES.md plan
[x] Identify missing features needed to bring this to a production-ready tool
    [x] Create a detailed FEATURE_ROADMAP.md plan
[x] Determine whether the current visual design of the app needs rework
    [x] If so, design a VISUAL_REWORK.md plan
[x] Lastly, update the README

---

## Testing Improvements

### T1. Remaining Low-Coverage Services
**Priority:** Medium | **Effort:** Medium

- [ ] `services/component_correlation.py` — no coverage
- [ ] `services/oidc_mapping.py` (78%)
- [ ] `services/sbom_ingest.py` (59%)

---

## Dependency Cleanup

### D1. Audit psycopg Dependency
**Priority:** Low | **Effort:** Small

- [ ] Audit whether `psycopg[binary]` is needed in dev (SQLite is the default); consider making it an optional extra
