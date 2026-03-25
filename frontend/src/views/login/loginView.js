import { el } from "../../ui/dom/el.js";
import { toast } from "../../ui/components/toast.js";
import { authProviders, login, me } from "../../api/auth.js";
import { getState, setSession } from "../../state/store.js";
import { navigate } from "../../router/router.js";

export async function LoginView() {
  const currentSession = getState()?.session || { token: null, user: null };
  try {
    const fresh = await me();
    setSession({ token: currentSession.token, refreshToken: currentSession.refreshToken, user: fresh });
    navigate("/");
    return null;
  } catch {
    // not authenticated yet
  }

  const usernameInput = el("input", { class: "input", type: "text", autocomplete: "username", placeholder: "Username" });
  const passwordInput = el("input", { class: "input", type: "password", autocomplete: "current-password", placeholder: "Password" });

  const btn = el("button", { class: "btn primary" }, "Log in");

  btn.addEventListener("click", async () => {
    btn.disabled = true;
    btn.textContent = "Logging in\u2026";
    try {
      const username = usernameInput.value.trim();
      const password = passwordInput.value;

      if (!username || !password) {
        toast({ title: "Missing fields", message: "Enter username and password." });
        return;
      }

      const res = await login(username, password);
      setSession({ token: res.token, refreshToken: res.refresh_token || null, user: res.user });

      try {
        const fresh = await me();
        setSession({ token: res.token, refreshToken: res.refresh_token || null, user: fresh });
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
  });

  let showSso = false;
  try {
    const providers = await authProviders();
    showSso = Boolean(providers?.oidc?.enabled);
  } catch {
    showSso = false;
  }

  const ssoButton = showSso
    ? el("button", { class: "btn", onclick: () => (window.location.href = "/api/auth/oidc/login?next=/") }, "Continue with SSO")
    : null;

  const card = el("div", { class: "card", style: "max-width: 420px; margin: 40px auto;" },
    el("h1", { class: "page-title", text: "Log in" }),
    el("p", { class: "muted", text: "Use your UVT credentials." }),
    el("div", { class: "form-grid" },
      usernameInput,
      passwordInput,
      el("div", { class: "form-actions" }, btn)
    ),
    ssoButton ? el("div", { class: "form-actions", style: "margin-top: 16px;" }, ssoButton) : null
  );

  return card;
}
