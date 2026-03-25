import { el } from "../dom/el.js";
import { logout } from "../../api/auth.js";
import { listNotifications, markAllNotificationsRead, markNotificationRead } from "../../api/notifications.js";
import { getState, logoutSession, markAllNotificationsReadLocal, setNotifications } from "../../state/store.js";
import { isAuthed } from "../../state/permissions.js";
import { navigate } from "../../router/router.js";

let dropdownOpen = false;

export function closeNotificationDropdown() {
  dropdownOpen = false;
}

function relativeTime(value) {
  if (!value) return "";
  const delta = Date.now() - new Date(value).getTime();
  if (Number.isNaN(delta)) return "";
  const mins = Math.floor(delta / 60000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.floor(hours / 24)}d ago`;
}

async function refreshNotificationPreview() {
  try {
    const payload = await listNotifications({ page: 1, page_size: 10 });
    setNotifications(payload);
  } catch {
    // Header should remain stable if notifications load fails.
  }
}

export function renderHeader() {
  const root = document.getElementById("app-header");
  if (!root) return;
  root.innerHTML = "";

  const state = getState();
  const authed = isAuthed(state);
  const user = state?.session?.user;

  const left = el("div", { class: "brand" }, "UVT");
  const right = el("div", { class: "row", style: "align-items:center; gap:8px;" });

  if (authed) {
    const unreadCount = state?.notifications?.unreadCount || 0;
    const notificationButton = el(
      "button",
      {
        class: "btn",
        title: "Notifications",
        "aria-label": `Notifications${unreadCount ? `, ${unreadCount} unread` : ""}`,
        "aria-expanded": String(dropdownOpen),
        "aria-haspopup": "true",
        onclick: async () => {
          dropdownOpen = !dropdownOpen;
          if (dropdownOpen) await refreshNotificationPreview();
          renderHeader();
        },
      },
      `Notifications${unreadCount ? ` (${unreadCount})` : ""}`,
    );

    right.appendChild(notificationButton);

    if (dropdownOpen) {
      const items = (state?.notifications?.items || []).slice(0, 5);
      const dropdown = el("div", {
        class: "card",
        role: "menu",
        "aria-label": "Notifications",
        tabindex: "-1",
        style: "position:absolute; right:12px; top:56px; width:360px; z-index:40; max-height:420px; overflow:auto;",
      });
      dropdown.addEventListener("keydown", (e) => {
        if (e.key === "Escape") {
          dropdownOpen = false;
          renderHeader();
          return;
        }
        if (e.key === "ArrowDown" || e.key === "ArrowUp") {
          e.preventDefault();
          const focusable = [...dropdown.querySelectorAll("button")];
          const idx = focusable.indexOf(document.activeElement);
          const next = e.key === "ArrowDown" ? idx + 1 : idx - 1;
          if (focusable[next]) focusable[next].focus();
        }
      });
      requestAnimationFrame(() => {
        const first = dropdown.querySelector("button");
        if (first) first.focus();
      });
      dropdown.appendChild(el("div", { class: "row", style: "padding:10px;" },
        el("strong", {}, "Notification Center"),
        el("div", { class: "spacer" }),
        el("button", {
          class: "btn",
          onclick: async () => {
            await markAllNotificationsRead();
            markAllNotificationsReadLocal();
            renderHeader();
          },
        }, "Mark all read"),
      ));

      if (!items.length) {
        dropdown.appendChild(el("div", { class: "muted", style: "padding: 0 10px 10px;" }, "No notifications."));
      } else {
        items.forEach((item) => {
          dropdown.appendChild(
            el("button", {
              class: "btn",
              role: "menuitem",
              style: `display:block; text-align:left; width:100%; border-radius:0; border-left:3px solid ${item.is_read ? "transparent" : "#2563eb"};`,
              onclick: async () => {
                if (!item.is_read && item.id) {
                  await markNotificationRead(item.id, true);
                  await refreshNotificationPreview();
                }
                dropdownOpen = false;
                renderHeader();
                if (item.vulnerability_id) {
                  navigate(`/vulnerabilities/${item.vulnerability_id}`);
                }
              },
            },
            `${item.message || "Notification"} ${relativeTime(item.created_at) ? `· ${relativeTime(item.created_at)}` : ""}`),
          );
        });
      }

      dropdown.appendChild(el("div", { style: "padding:10px;" },
        el("button", { class: "btn", onclick: () => { dropdownOpen = false; renderHeader(); navigate('/notifications'); } }, "Open full page"),
      ));
      right.appendChild(dropdown);
    }

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
        dropdownOpen = false;
        logoutSession();
        navigate("/login");
      }
    }, "Logout"));
  } else {
    dropdownOpen = false;
    right.appendChild(el("button", { class: "btn", onclick: () => navigate("/login") }, "Login"));
  }

  root.appendChild(el("div", { class: "row" }, left, el("div", { class: "spacer" }), right));
}
