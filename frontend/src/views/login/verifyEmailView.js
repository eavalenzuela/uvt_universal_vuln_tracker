import { el } from "../../ui/dom/el.js";
import { toast } from "../../ui/components/toast.js";
import { verifyEmail } from "../../api/auth.js";
import { navigate } from "../../router/router.js";

export async function VerifyEmailView(params) {
  const token = params?.token;

  const status = el("p", { class: "muted", text: "Verifying your email…" });
  const backLink = el("a", { href: "#/login", class: "link", text: "Back to login" });

  const card = el("div", { class: "card", style: "max-width: 420px; margin: 40px auto;" },
    el("h1", { class: "page-title", text: "Verify email" }),
    status,
    el("div", { style: "margin-top: 16px; text-align: center;" }, backLink)
  );

  if (!token) {
    status.textContent = "No verification token found in the link.";
    return card;
  }

  try {
    const res = await verifyEmail(token);
    status.textContent = res.message || "Email verified. You can now log in.";
    toast({ title: "Email verified", message: "You can now log in." });
    setTimeout(() => navigate("/login"), 1500);
  } catch (e) {
    status.textContent = e?.message || "This verification link is invalid or has expired.";
  }

  return card;
}
