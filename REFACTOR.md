# Refactor Work

## Purpose
This app needs a re-assessment of its design, both front and backend. It will be re-factored in 2 ways:
* module-by-module (code analysis)
* webpage-by-webpage (screenshot visual design analysis)

## Goals
[ ] Document each backend source module (high level)
    [ ] Create a BACKEND.md wiki file
[ ] Document each webpage (high level)
    [ ] Create a FRONTEND.md wiki file
[ ] Identify security fixes and redesigns
    [ ] Create a SECURITY_FIXES.md plan
[ ] Identify missing features needed to bring this to a production-ready tool
    [ ] Create a detailed FEATURE_ROADMAP.md plan
[ ] Determine whether the current visual design of the app needs rework
    [ ] If so, design a VISUAL_REWORK.md plan
[ ] Lastly, update the README

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
