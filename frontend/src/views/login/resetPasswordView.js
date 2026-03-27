import { el } from "../../ui/dom/el.js";
import { toast } from "../../ui/components/toast.js";
import { resetPassword } from "../../api/auth.js";
import { navigate } from "../../router/router.js";

export async function ResetPasswordView(params) {
  const token = params?.token;
  if (!token) {
    toast({ title: "Invalid link", message: "No reset token found." });
    navigate("/login");
    return null;
  }

  const passwordInput = el("input", { class: "input", type: "password", autocomplete: "new-password", placeholder: "New password" });
  const confirmInput = el("input", { class: "input", type: "password", autocomplete: "new-password", placeholder: "Confirm password" });
  const btn = el("button", { class: "btn primary" }, "Set new password");

  btn.addEventListener("click", async () => {
    const password = passwordInput.value;
    const confirm = confirmInput.value;

    if (!password || !confirm) {
      toast({ title: "Missing fields", message: "Enter and confirm your new password." });
      return;
    }
    if (password !== confirm) {
      toast({ title: "Mismatch", message: "Passwords do not match." });
      return;
    }

    btn.disabled = true;
    btn.textContent = "Resetting\u2026";
    try {
      const res = await resetPassword(token, password);
      toast({ title: "Success", message: res.message || "Password has been reset." });
      navigate("/login");
    } catch (e) {
      toast({ title: "Reset failed", message: e?.message || "Invalid or expired token." });
    } finally {
      btn.disabled = false;
      btn.textContent = "Set new password";
    }
  });

  const backLink = el("a", { href: "#/login", class: "link", text: "Back to login" });

  return el("div", { class: "card", style: "max-width: 420px; margin: 40px auto;" },
    el("h1", { class: "page-title", text: "Reset password" }),
    el("p", { class: "muted", text: "Enter your new password (minimum 12 characters)." }),
    el("div", { class: "form-grid" },
      passwordInput,
      confirmInput,
      el("div", { class: "form-actions" }, btn)
    ),
    el("div", { style: "margin-top: 16px; text-align: center;" }, backLink)
  );
}
