import { el } from "../../ui/dom/el.js";
import { toast } from "../../ui/components/toast.js";
import { login, me } from "../../api/auth.js";
import { setSession } from "../../state/store.js";
import { navigate } from "../../router/router.js";

export async function LoginView() {
  const usernameInput = el("input", { class: "input", type: "text", autocomplete: "username", placeholder: "Username" });
  const passwordInput = el("input", { class: "input", type: "password", autocomplete: "current-password", placeholder: "Password" });

  const btn = el("button", { class: "btn primary" }, "Log in");

  btn.addEventListener("click", async () => {
    btn.disabled = true;
    try {
      const username = usernameInput.value.trim();
      const password = passwordInput.value;

      if (!username || !password) {
        toast({ title: "Missing fields", message: "Enter username and password." });
        return;
      }

      const res = await login(username, password);
      // res: { token, user }
      setSession({ token: res.token, user: res.user });

      // optional refresh from /me (source of truth)
      try {
        const fresh = await me();
        setSession({ token: res.token, user: fresh });
      } catch {
        // fine if /me not implemented yet
      }

      toast({ title: "Welcome", message: `Logged in as ${username}` });
      navigate("/");
    } catch (e) {
      toast({ title: "Login failed", message: e?.message || "Unknown error" });
    } finally {
      btn.disabled = false;
    }
  });

  const card = el("div", { class: "card", style: "max-width: 420px; margin: 40px auto;" },
    el("h1", { class: "page-title", text: "Log in" }),
    el("p", { class: "muted", text: "Use your UVT credentials." }),
    el("div", { class: "form-grid" },
      usernameInput,
      passwordInput,
      el("div", { class: "form-actions" }, btn)
    )
  );

  return card;
}
