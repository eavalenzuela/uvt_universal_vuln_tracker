# Security Fixes Plan

Audit findings for UVT, organized by severity.

---

## S1. Debug Mode Hardcoded in Entry Point
**Severity:** Critical | **Effort:** Small

`backend/uvt_app.py:74` — `app.run(debug=True)` is unconditional:
- Exposes Werkzeug interactive debugger (arbitrary code execution)
- Leaks stack traces, env vars, source code to any visitor

**Fix:** Gate on environment:
```python
app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")),
        debug=os.getenv("FLASK_ENV") == "development")
```

---

## S2. Temporary Password Returned in API Response
**Severity:** High | **Effort:** Medium

`backend/api/users_crud.py:194` — `payload["temp_password"] = password` sends the plaintext password in the JSON response body when an admin creates a user or generates a password reset.

- Password appears in access logs, browser devtools, proxy logs
- Persists in response caches

**Fix:** Replace with a time-limited password-reset link (e.g., `itsdangerous.URLSafeTimedSerializer` with 30-minute expiry). Return only the link, never the password itself.

---

## S3. User Creation/Invite Uses Lenient Rate Limit
**Severity:** High | **Effort:** Small

`backend/api/users_crud.py:122,162` — `create_user` and `invite_user` use `RATE_LIMIT_WRITE_LIMIT` (30/60s) instead of `RATE_LIMIT_SENSITIVE_LIMIT` (10/60s). A compromised admin account could bulk-create users rapidly.

**Fix:** Change both to `RATE_LIMIT_SENSITIVE_LIMIT` / `RATE_LIMIT_SENSITIVE_WINDOW_SECONDS`.

---

## S4. No Security Response Headers
**Severity:** Medium | **Effort:** Small

The app sets no security headers. Missing:

| Header | Purpose |
|--------|---------|
| `Content-Security-Policy` | Prevents XSS, inline script injection |
| `X-Frame-Options: DENY` | Prevents clickjacking |
| `X-Content-Type-Options: nosniff` | Prevents MIME-type sniffing |
| `Strict-Transport-Security` | Forces HTTPS in production |
| `Referrer-Policy: strict-origin-when-cross-origin` | Limits referrer leakage |

**Fix:** Add an `after_request` hook in `uvt_app.py` that sets these headers on all responses. Use `flask-talisman` or set manually.

---

## S5. CSRF Validation Silently Passes When Cookie Is Missing
**Severity:** Medium | **Effort:** Small

`backend/auth.py` — `_validate_csrf()` returns `(True, None)` if the request is not cookie-authenticated, which is correct. However, for cookie-authenticated requests where the `uvt_csrf_token` cookie is somehow absent (cleared by the browser, expired), the check fails closed (returns 403), which is the right behavior.

The current double-submit cookie pattern (`httponly=False` on the CSRF cookie) is correct — the frontend must read the cookie to send it as an `X-CSRF-Token` header. The `SameSite=Lax` attribute prevents cross-origin cookie attachment, which is the actual CSRF defense layer.

**Improvement:** Add logging when CSRF validation fails to detect potential attack attempts.

---

## S6. No Password Complexity Requirements
**Severity:** Medium | **Effort:** Small

`backend/auth.py` — `create_user()` and password-reset accept any non-empty password. No minimum length, complexity, or breach-check enforcement.

**Fix:** Add a `validate_password(password)` helper enforcing at minimum 12 characters and checking against common password lists.

---

## S7. Run Dependency Audit
**Severity:** Medium | **Effort:** Small

No automated dependency vulnerability scanning. Add `pip-audit` to CI:

```bash
pip install pip-audit && pip-audit
```

---

## S8. Account Enumeration via Login Timing
**Severity:** Low | **Effort:** Small

`backend/auth.py` — `authenticate_user()` returns early if the user doesn't exist (no password hash comparison), creating a timing difference vs. invalid-password attempts. An attacker can enumerate valid usernames.

**Fix:** Always run `check_password_hash()` against a dummy hash when the user is not found.

---

## S9. Health Endpoint Has No Rate Limit
**Severity:** Low | **Effort:** Small

`GET /api/health` has no rate limiting. Low risk since it returns a static response, but could be used for reconnaissance or lightweight DoS if exposed publicly.

**Fix:** Add a generous rate limit (e.g., 120/60s).

---

## Summary

| ID | Severity | Effort | Description |
|----|----------|--------|-------------|
| S1 | Critical | Small | Remove hardcoded `debug=True` |
| S2 | High | Medium | Stop returning temp passwords in responses |
| S3 | High | Small | Tighten rate limit on user creation/invite |
| S4 | Medium | Small | Add security response headers |
| S5 | Medium | Small | Log CSRF validation failures |
| S6 | Medium | Small | Add password complexity validation |
| S7 | Medium | Small | Add `pip-audit` to CI |
| S8 | Low | Small | Prevent account enumeration via timing |
| S9 | Low | Small | Rate-limit health endpoint |

### Positive Findings (No Action Needed)

- JWT auth properly implemented (HS256, 12h expiry, token versioning)
- Auth cookie is `httponly=True` — tokens not accessible to JS
- CSRF double-submit pattern correctly implemented
- SQLAlchemy ORM prevents SQL injection throughout
- No `eval`/`exec`/`pickle` usage
- OIDC callback validates `next` path (no open redirect)
- Report artifact downloads use signed tokens (no IDOR)
- Frontend uses safe DOM construction (`el()` + `textContent`, no raw innerHTML with user data)
- Plugin imports restricted to configured paths
- Sensitive fields filtered from audit log snapshots
