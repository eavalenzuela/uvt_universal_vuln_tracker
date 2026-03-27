import { el } from "../../ui/dom/el.js";
import { toast } from "../../ui/components/toast.js";
import { createMyApiToken, listMyApiTokens, revokeMyApiToken } from "../../api/users.js";
import { getState } from "../../state/store.js";

const ROLE_SCOPE_OPTIONS = {
  Admin: [
    "attack_vectors:read",
    "attack_vectors:write",
    "controls:read",
    "controls:write",
    "plugins:read",
    "plugins:write",
    "products:read",
    "products:write",
    "reports:read",
    "reports:write",
    "terminal_impacts:read",
    "terminal_impacts:write",
    "users:read",
    "users:write",
    "vulnerabilities:read",
    "vulnerabilities:write",
  ],
  Analyst: [
    "attack_vectors:read",
    "attack_vectors:write",
    "controls:read",
    "controls:write",
    "plugins:read",
    "plugins:write",
    "products:read",
    "products:write",
    "reports:read",
    "reports:write",
    "terminal_impacts:read",
    "terminal_impacts:write",
    "vulnerabilities:read",
    "vulnerabilities:write",
  ],
  Viewer: [
    "attack_vectors:read",
    "controls:read",
    "plugins:read",
    "products:read",
    "reports:read",
    "terminal_impacts:read",
    "vulnerabilities:read",
  ],
};

function formatDate(value) {
  if (!value) return "Never";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "Unknown";
  return date.toLocaleString();
}

function copyText(text) {
  if (!text) return Promise.reject(new Error("Missing text"));
  if (navigator.clipboard?.writeText) {
    return navigator.clipboard.writeText(text);
  }
  const tmp = el("textarea", { style: "position:fixed; left:-9999px;" });
  tmp.value = text;
  document.body.appendChild(tmp);
  tmp.select();
  document.execCommand("copy");
  tmp.remove();
  return Promise.resolve();
}

function tokenCard(token, onRevoke) {
  const revoked = Boolean(token.revoked_at);
  const revokeBtn = el("button", { class: "btn", disabled: revoked ? "true" : null }, revoked ? "Revoked" : "Revoke");
  revokeBtn.addEventListener("click", () => onRevoke(token));

  return el("div", { class: "card p-12" },
    el("div", { class: "row flex-between items-start gap-10 flex-wrap" },
      el("div", { class: "flex-col-4" },
        el("div", { class: "font-bold", text: token.name || `Token #${token.id}` }),
        el("div", { class: "muted", text: `Scopes: ${(token.scopes || []).join(", ") || "None"}` }),
        el("div", { class: "muted", text: `Created: ${formatDate(token.created_at)}` }),
        el("div", { class: "muted", text: `Expires: ${formatDate(token.expires_at)}` }),
        el("div", { class: "muted", text: `Last used: ${formatDate(token.last_used_at)}` }),
        token.revoked_at ? el("div", { class: "muted", text: `Revoked: ${formatDate(token.revoked_at)}` }) : null,
      ),
      revokeBtn,
    ),
  );
}

export async function AdminApiTokensView() {
  const role = getState()?.session?.user?.role || "Viewer";
  const scopeOptions = ROLE_SCOPE_OPTIONS[role] || ROLE_SCOPE_OPTIONS.Viewer;

  const tokenNameInput = el("input", { class: "input", placeholder: "Token name", required: "true" });
  const expiresInput = el("input", { class: "input", type: "number", min: "1", max: "3650", placeholder: "Expires in days (optional)" });
  const scopesSelect = el("select", { class: "input", multiple: "multiple", size: "8", style: "min-height: 160px;" },
    ...scopeOptions.map((scope) => el("option", { value: scope }, scope)),
  );

  const createBtn = el("button", { class: "btn primary", type: "submit" }, "Create token");
  const createForm = el("form", { class: "flex-col-8" },
    el("div", { class: "muted", text: "Token name" }),
    tokenNameInput,
    el("div", { class: "muted", text: "Scopes (choose one or more)" }),
    scopesSelect,
    el("div", { class: "muted", text: "Expiration" }),
    expiresInput,
    el("div", { class: "row flex-end" }, createBtn),
  );

  const generatedTokenInput = el("input", {
    class: "input text-mono",
    readonly: "true",
    placeholder: "A newly-created token will appear here once",
  });
  const copyBtn = el("button", { class: "btn", type: "button" }, "Copy token");

  const generatedTokenCard = el("div", { class: "card p-12 mt-12" },
    el("h3", { class: "mt-0", text: "New token (shown once)" }),
    el("p", {
      class: "muted",
      text: "This plaintext token is only visible now. Copy and store it securely. You will not be able to view it again after leaving this page.",
    }),
    el("div", { class: "row gap-8" }, generatedTokenInput, copyBtn),
  );

  const listRoot = el("div", { class: "flex-col-10 mt-12" });

  async function loadTokens() {
    listRoot.innerHTML = "";
    listRoot.appendChild(el("div", { class: "muted", text: "Loading tokens..." }));
    try {
      const tokens = await listMyApiTokens();
      listRoot.innerHTML = "";
      if (!tokens?.length) {
        listRoot.appendChild(el("div", { class: "muted", text: "No API tokens yet." }));
        return;
      }
      tokens.forEach((token) => {
        listRoot.appendChild(tokenCard(token, async (selectedToken) => {
          const ok = window.confirm(`Revoke token "${selectedToken.name}"? This cannot be undone.`);
          if (!ok) return;
          try {
            await revokeMyApiToken(selectedToken.id);
            toast({ title: "Token revoked", message: `${selectedToken.name} was revoked.` });
            loadTokens();
          } catch (error) {
            toast({ title: "Revoke failed", message: error?.message || "Unable to revoke token" });
          }
        }));
      });
    } catch (error) {
      listRoot.innerHTML = "";
      listRoot.appendChild(el("div", { class: "muted", text: "Unable to load tokens." }));
      toast({ title: "Failed to load tokens", message: error?.message || "Request failed" });
    }
  }

  copyBtn.addEventListener("click", async () => {
    try {
      await copyText(generatedTokenInput.value);
      toast({ title: "Copied", message: "Token copied to clipboard." });
    } catch {
      toast({ title: "Copy failed", message: "Unable to copy token to clipboard." });
    }
  });

  createForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    const name = tokenNameInput.value.trim();
    const scopes = Array.from(scopesSelect.selectedOptions).map((opt) => opt.value);
    const expiresRaw = expiresInput.value.trim();

    if (!name) {
      toast({ title: "Missing name", message: "Please provide a token name." });
      return;
    }
    if (!scopes.length) {
      toast({ title: "Missing scopes", message: "Select at least one scope." });
      return;
    }

    const payload = { name, scopes };
    if (expiresRaw) payload.expires_in_days = Number(expiresRaw);

    try {
      const created = await createMyApiToken(payload);
      generatedTokenInput.value = created?.token || "";
      tokenNameInput.value = "";
      expiresInput.value = "";
      Array.from(scopesSelect.options).forEach((opt) => {
        opt.selected = false;
      });
      toast({ title: "Token created", message: "Copy the token now. It will not be shown again." });
      loadTokens();
    } catch (error) {
      toast({ title: "Create failed", message: error?.message || "Unable to create token" });
    }
  });

  await loadTokens();

  return el("section", {},
    el("h2", { text: "API Tokens" }),
    el("p", {
      class: "muted",
      text: "Manage personal API tokens for CLI and integrations. Revoke any token that is no longer needed.",
    }),
    el("div", { class: "card p-12" },
      el("h3", { class: "mt-0", text: "Create token" }),
      createForm,
    ),
    generatedTokenCard,
    el("h3", { class: "mt-16", text: "Existing tokens" }),
    listRoot,
  );
}
