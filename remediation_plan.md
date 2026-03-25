# UVT Remediation Plan

## High Priority

### 7. Rate Limiting Gaps
Only login, vuln list, and export are rate-limited. Unprotected endpoints include:
- Password change
- Report generation (CPU-intensive)
- All other write endpoints

Also: the in-memory rate limit backend doesn't work across multiple worker processes.

**Fix:** Add rate limits to write endpoints and expensive operations. Document that production deployments should use the Redis backend.
