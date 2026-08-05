import { el } from "../../ui/dom/el.js";
import { toast } from "../../ui/components/toast.js";
import { authProviders, login, me, mfaVerify } from "../../api/auth.js";
import { getState, setSession } from "../../state/store.js";
import { navigate } from "../../router/router.js";
import { promptModal } from "../../ui/components/modal.js";

export async function LoginView() {
  const currentSession = getState()?.session || { token: null, user: null };
  try {
    const fresh = await me();
    setSession({
      token: currentSession.token,
      refreshToken: currentSession.refreshToken,
      user: fresh,
      teams: fresh?.teams || [],
      currentTeamId: fresh?.current_team_id ?? null,
    });
    navigate("/");
    return null;
  } catch {
    // not authenticated yet
  }

  const usernameInput = el("input", { class: "input", id: "login-username", type: "text", autocomplete: "username", placeholder: "Username", required: true });
  const passwordInput = el("input", { class: "input", id: "login-password", type: "password", autocomplete: "current-password", placeholder: "Password", required: true });

  const btn = el("button", { class: "btn primary", type: "submit" }, "Log in");

  async function handleSubmit(event) {
    if (event) event.preventDefault();
    btn.disabled = true;
    btn.textContent = "Logging in\u2026";
    try {
      const username = usernameInput.value.trim();
      const password = passwordInput.value;

      if (!username || !password) {
        toast({ title: "Missing fields", message: "Enter username and password." });
        return;
      }

      let res = await login(username, password);

      // The password alone is not a session when 2FA is on: the server hands
      // back a short-lived challenge that a code exchanges for real tokens.
      if (res?.mfa_required) {
        const code = await promptModal({
          title: "Two-factor authentication",
          message: "Enter the six-digit code from your authenticator app, or a recovery code.",
          inputLabel: "Code",
          placeholder: "123456",
          required: true,
        });
        if (!code) {
          toast({ title: "Sign-in cancelled", message: "A verification code is required." });
          return;
        }
        const trimmed = String(code).trim();
        // Recovery codes contain dashes; TOTP codes are six digits.
        res = await mfaVerify({
          mfaToken: res.mfa_token,
          code: /^\d{6}$/.test(trimmed) ? trimmed : undefined,
          recoveryCode: /^\d{6}$/.test(trimmed) ? undefined : trimmed,
        });
      }

      setSession({ token: res.token, refreshToken: res.refresh_token || null, user: res.user });

      try {
        const fresh = await me();
        setSession({
          token: res.token,
          refreshToken: res.refresh_token || null,
          user: fresh,
          teams: fresh?.teams || [],
          currentTeamId: fresh?.current_team_id ?? null,
        });
      } catch {
        // fine if /me not implemented yet
      }

      toast({ title: "Welcome", message: `Logged in as ${username}` });
      navigate("/");
    } catch (e) {
      toast({ title: "Login failed", message: e?.message || "Unknown error" });
    } finally {
      btn.disabled = false;
      btn.textContent = "Log in";
    }
  }

  let showSso = false;
  try {
    const providers = await authProviders();
    showSso = Boolean(providers?.oidc?.enabled);
  } catch {
    showSso = false;
  }

  const ssoButton = showSso
    ? el("button", { class: "btn", type: "button", onclick: () => (window.location.href = "/api/auth/oidc/login?next=/") }, "Continue with SSO")
    : null;

  // Use a real <form> with associated <label>s so Enter submits and the inputs
  // are announced to assistive tech (placeholders are not labels).
  const form = el(
    "form",
    { class: "form-grid" },
    el("label", { class: "flex-col", style: "gap:4px" }, el("span", { class: "muted" }, "Username"), usernameInput),
    el("label", { class: "flex-col", style: "gap:4px" }, el("span", { class: "muted" }, "Password"), passwordInput),
    el("div", { class: "form-actions" }, btn),
  );
  form.addEventListener("submit", handleSubmit);

  const card = el("div", { class: "card", style: "max-width: 420px; margin: 40px auto;" },
    el("h1", { class: "page-title", text: "Log in" }),
    el("p", { class: "muted", text: "Use your UVT credentials." }),
    form,
    el("div", { style: "margin-top: 12px; text-align: center;" },
      el("a", { href: "#/forgot-password", class: "link", text: "Forgot password?" })
    ),
    ssoButton ? el("div", { class: "form-actions", style: "margin-top: 16px;" }, ssoButton) : null
  );

  return card;
}
