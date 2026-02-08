import { el } from "../dom/el.js";
import { logout } from "../../api/auth.js";
import { getState, logoutSession } from "../../state/store.js";
import { isAuthed } from "../../state/permissions.js";
import { navigate } from "../../router/router.js";

export function renderHeader() {
  const root = document.getElementById("app-header");
  if (!root) return;
  root.innerHTML = "";

  const state = getState();
  const authed = isAuthed(state);
  const user = state?.session?.user;

  const left = el("div", { class: "brand" }, "UVT");
  const right = el("div", { class: "row" });

  if (authed) {
    right.appendChild(el("div", { class: "muted" }, `${user?.username || "user"} (${user?.role || "?"})`));
    right.appendChild(el("button", {
      class: "btn",
      onclick: async () => {
        try {
          const refreshToken = getState()?.session?.refreshToken;
          if (refreshToken) {
            await logout(refreshToken);
          }
        } catch {
          // clear local session regardless of backend availability
        }
        logoutSession();
        navigate("/login");
      }
    }, "Logout"));
  } else {
    right.appendChild(el("button", { class: "btn", onclick: () => navigate("/login") }, "Login"));
  }

  root.appendChild(el("div", { class: "row" }, left, el("div", { class: "spacer" }), right));
}
