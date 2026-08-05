import { mfaConfirm, mfaDisable, mfaEnroll, mfaStatus } from "../../api/auth.js";
import { el } from "../../ui/dom/el.js";
import { toast } from "../../ui/components/toast.js";

/**
 * Two-factor authentication settings.
 *
 * The Admin → Users page has long claimed to help operators manage "MFA
 * posture"; until now nothing in the product implemented a second factor.
 * This is the enrolment side of it.
 */
export function renderMfaSection() {
  const section = el("div", { class: "flex-col-10 card p-16 mt-12" });
  const body = el("div", { class: "flex-col-8" });

  section.append(
    el("h3", { class: "m-0", text: "Two-factor authentication" }),
    el("p", {
      class: "muted",
      text: "Require a code from an authenticator app in addition to your password.",
    }),
    body,
  );

  function showLoading() {
    body.innerHTML = "";
    body.appendChild(el("div", { class: "muted", text: "Checking…" }));
  }

  function showRecoveryCodes(codes) {
    body.innerHTML = "";
    body.append(
      el("div", { class: "pill pill-tone-success", text: "Two-factor authentication is on" }),
      el("p", {
        text: "Save these recovery codes now — they are shown once and cannot be retrieved. "
            + "Each one works a single time if you lose your authenticator.",
      }),
      el("ul", { class: "recovery-codes" }, ...codes.map((c) => el("li", { text: c }))),
      el("button", {
        class: "btn",
        type: "button",
        text: "Copy codes",
        onClick: async () => {
          try {
            await navigator.clipboard.writeText(codes.join("\n"));
            toast({ title: "Copied", message: "Recovery codes copied to your clipboard." });
          } catch {
            toast({ title: "Copy failed", message: "Select the codes and copy them manually." });
          }
        },
      }),
      el("button", {
        class: "btn",
        type: "button",
        text: "Done",
        onClick: () => load(),
      }),
    );
  }

  function showEnrollment(secret, uri) {
    body.innerHTML = "";
    const codeInput = el("input", {
      class: "input max-w-220",
      id: "mfa-confirm-code",
      inputmode: "numeric",
      autocomplete: "one-time-code",
      placeholder: "123456",
    });
    const confirmBtn = el("button", { class: "btn primary", type: "submit", text: "Turn on" });

    const form = el(
      "form",
      { class: "flex-col-8" },
      el("p", { text: "1. Add this key to your authenticator app:" }),
      // The secret is shown as text rather than a QR code so the page needs no
      // image-generation dependency and stays keyboard- and screen-reader-
      // friendly. The otpauth:// link works on mobile.
      el("code", { class: "mfa-secret", text: secret }),
      el("a", { class: "link", href: uri, text: "Open in an authenticator app" }),
      el("p", { text: "2. Enter the six-digit code it shows:" }),
      el("div", { class: "filter-field" },
        el("label", { class: "filter-label", for: "mfa-confirm-code", text: "Verification code" }),
        codeInput,
      ),
      el("div", { class: "row gap-8" },
        confirmBtn,
        el("button", { class: "btn", type: "button", text: "Cancel", onClick: () => load() }),
      ),
    );

    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      confirmBtn.disabled = true;
      try {
        const result = await mfaConfirm(codeInput.value.trim());
        toast({ title: "Two-factor enabled", message: "Your account now requires a code at sign-in." });
        showRecoveryCodes(result.recovery_codes || []);
      } catch (error) {
        toast({ title: "Could not turn on 2FA", message: error?.message || "That code was not accepted." });
        confirmBtn.disabled = false;
      }
    });

    body.appendChild(form);
    codeInput.focus();
  }

  function showEnabled(status) {
    body.innerHTML = "";
    const passwordInput = el("input", {
      class: "input max-w-220",
      id: "mfa-disable-password",
      type: "password",
      autocomplete: "current-password",
    });
    const disableBtn = el("button", { class: "btn", type: "submit", text: "Turn off" });

    const form = el(
      "form",
      { class: "flex-col-8" },
      el("div", { class: "pill pill-tone-success", text: "Two-factor authentication is on" }),
      el("p", {
        class: "muted",
        text: `${status.recovery_codes_remaining ?? 0} recovery code(s) remaining.`,
      }),
      el("div", { class: "filter-field" },
        el("label", { class: "filter-label", for: "mfa-disable-password",
                      text: "Confirm your password to turn it off" }),
        passwordInput,
      ),
      el("div", { class: "row gap-8" }, disableBtn),
    );

    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      disableBtn.disabled = true;
      try {
        await mfaDisable(passwordInput.value);
        toast({ title: "Two-factor disabled", message: "Your account no longer requires a code." });
        load();
      } catch (error) {
        toast({ title: "Could not turn off 2FA", message: error?.message || "Password not accepted." });
        disableBtn.disabled = false;
      }
    });

    body.appendChild(form);
  }

  function showDisabled() {
    body.innerHTML = "";
    const startBtn = el("button", {
      class: "btn primary",
      type: "button",
      text: "Set up two-factor authentication",
    });
    startBtn.addEventListener("click", async () => {
      startBtn.disabled = true;
      try {
        const enrollment = await mfaEnroll();
        showEnrollment(enrollment.secret, enrollment.otpauth_uri);
      } catch (error) {
        toast({ title: "Could not start setup", message: error?.message || "Please try again." });
        startBtn.disabled = false;
      }
    });
    body.append(
      el("div", { class: "pill pill-tone-neutral", text: "Not enabled" }),
      startBtn,
    );
  }

  async function load() {
    showLoading();
    try {
      const status = await mfaStatus();
      if (status.enabled) showEnabled(status);
      else showDisabled();
    } catch {
      body.innerHTML = "";
      body.appendChild(el("div", { class: "muted", text: "Unable to load 2FA settings." }));
    }
  }

  load();
  return section;
}
