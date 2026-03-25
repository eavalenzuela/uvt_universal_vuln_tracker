# UVT Remediation Plan

## High Priority

### 7. Rate Limiting Gaps
Only login, vuln list, and export are rate-limited. Unprotected endpoints include:
- Password change
- Report generation (CPU-intensive)
- All other write endpoints

Also: the in-memory rate limit backend doesn't work across multiple worker processes.

**Fix:** Add rate limits to write endpoints and expensive operations. Document that production deployments should use the Redis backend.

---

## Medium Priority

### 12. Accessibility Gaps
- Several views use `window.prompt()` instead of proper modal dialogs
- Form inputs often lack proper `<label>` associations
- Notification dropdown in `frontend/src/ui/layout/header.js` isn't keyboard-navigable

**Fix:** Replace `window.prompt()` with the existing modal UI primitive. Add `<label>` and `aria-label` attributes where missing. Make dropdowns keyboard-navigable.

---

### 13. Missing Loading States
Many async operations (comment edit/delete, product version updates, vulnerability updates) disable the button but provide no visual feedback.

**Fix:** Add a spinner or text change to buttons during in-flight requests.

---

## Low Priority

### 15. Inconsistent Error Response Format
**File:** `backend/api/validation.py`

`error_response()` includes `status` in the JSON body redundantly with the HTTP status code.

**Fix:** Remove the `status` field from JSON payloads, or standardize its presence across all error responses.

---

### 16. Frontend Memory Leaks
- Global `liveStream` in `frontend/src/main.js` isn't cleaned up on logout
- `dropdownOpen` state in `frontend/src/ui/layout/header.js` persists across routes

**Fix:** Close `liveStream` on logout. Reset dropdown state on route change.

---

### 17. Frontend Test Coverage
8 test files cover API adapters and logic, but no view components, state store, or UI primitives are tested.

**Fix:** Add tests for the store (especially `upsertNotification`), UI primitives, and at least smoke tests for key views.

---

### 18. No localStorage Quota Checking
**File:** `frontend/src/features/dashboard/layoutState.js`

Dashboard layout state writes to localStorage without checking available space.

**Fix:** Wrap `localStorage.setItem` in a try-catch to handle `QuotaExceededError`.
