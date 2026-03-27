import { el } from "../../ui/dom/el.js";
import { toast } from "../../ui/components/toast.js";
import { forgotPassword } from "../../api/auth.js";
import { navigate } from "../../router/router.js";

export async function ForgotPasswordView() {
  const emailInput = el("input", { class: "input", type: "email", autocomplete: "email", placeholder: "Email address" });
  const btn = el("button", { class: "btn primary" }, "Send reset link");

  btn.addEventListener("click", async () => {
    const email = emailInput.value.trim();
    if (!email) {
      toast({ title: "Missing field", message: "Enter your email address." });
      return;
    }

    btn.disabled = true;
    btn.textContent = "Sending\u2026";
    try {
      const res = await forgotPassword(email);
      toast({ title: "Check your email", message: res.message || "If an account with that email exists, a reset link has been sent." });
    } catch (e) {
      toast({ title: "Error", message: e?.message || "Something went wrong" });
    } finally {
      btn.disabled = false;
      btn.textContent = "Send reset link";
    }
  });

  const backLink = el("a", { href: "#/login", class: "link", text: "Back to login" });

  return el("div", { class: "card", style: "max-width: 420px; margin: 40px auto;" },
    el("h1", { class: "page-title", text: "Forgot password" }),
    el("p", { class: "muted", text: "Enter your email and we'll send a reset link." }),
    el("div", { class: "form-grid" },
      emailInput,
      el("div", { class: "form-actions" }, btn)
    ),
    el("div", { style: "margin-top: 16px; text-align: center;" }, backLink)
  );
}
