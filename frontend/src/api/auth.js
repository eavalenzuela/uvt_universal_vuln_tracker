import { apiFetch } from "./client.js";

export async function login(username, password) {
  return apiFetch("/api/auth/login", {
    method: "POST",
    body: { username, password },
  });
}

export async function refresh(refreshToken = null) {
  return apiFetch("/api/auth/refresh", {
    method: "POST",
    body: refreshToken ? { refresh_token: refreshToken } : {},
  });
}

export async function logout(refreshToken = null) {
  return apiFetch("/api/auth/logout", {
    method: "POST",
    body: refreshToken ? { refresh_token: refreshToken } : {},
  });
}

export async function logoutAll() {
  return apiFetch("/api/auth/logout_all", { method: "POST" });
}

export async function me() {
  return apiFetch("/api/auth/me", { method: "GET" });
}

export async function authProviders() {
  return apiFetch("/api/auth/providers", { method: "GET" });
}

export async function forgotPassword(email) {
  return apiFetch("/api/auth/forgot-password", {
    method: "POST",
    body: { email },
  });
}

export async function resetPassword(token, password) {
  return apiFetch("/api/auth/reset-password", {
    method: "POST",
    body: { token, password },
  });
}

export async function verifyEmail(token) {
  return apiFetch("/api/auth/verify-email", {
    method: "POST",
    body: { token },
  });
}

export async function resendVerification(email) {
  return apiFetch("/api/auth/resend-verification", {
    method: "POST",
    body: { email },
  });
}

// ── Multi-factor authentication ─────────────────────────────
export async function mfaStatus() {
  return apiFetch("/api/auth/mfa/status", { method: "GET" });
}

export async function mfaEnroll() {
  return apiFetch("/api/auth/mfa/enroll", { method: "POST" });
}

export async function mfaConfirm(code) {
  return apiFetch("/api/auth/mfa/confirm", { method: "POST", body: { code } });
}

export async function mfaDisable(password) {
  return apiFetch("/api/auth/mfa/disable", { method: "POST", body: { password } });
}

/** Exchange the login challenge plus a code (or recovery code) for a session. */
export async function mfaVerify({ mfaToken, code, recoveryCode }) {
  return apiFetch("/api/auth/mfa/verify", {
    method: "POST",
    body: { mfa_token: mfaToken, code, recovery_code: recoveryCode },
  });
}
