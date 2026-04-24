import { el } from "../dom/el.js";
import { logout } from "../../api/auth.js";
import { listNotifications, markAllNotificationsRead, markNotificationRead } from "../../api/notifications.js";
import { getState, logoutSession, markAllNotificationsReadLocal, setNotifications } from "../../state/store.js";
import { isAuthed } from "../../state/permissions.js";
import { navigate } from "../../router/router.js";
import { toggleTheme } from "../../state/theme.js";
import { globalSearch } from "../../api/search.js";

let dropdownOpen = false;
let searchTimer = null;
let searchDropdownOpen = false;

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

  const sidebarToggle = el("button", {
    class: "sidebar-toggle",
    "aria-label": "Toggle sidebar",
    onclick: () => {
      const sidebar = document.getElementById("app-sidebar");
      if (sidebar) sidebar.classList.toggle("open");
    },
  }, "\u2630");

  const left = el("div", { class: "flex-row-8" }, sidebarToggle, el("div", { class: "brand" }, "UVT"));
  const right = el("div", { class: "row gap-8" });

  const isLight = document.documentElement.getAttribute("data-theme") === "light";
  const themeBtn = el("button", {
    class: "btn theme-toggle",
    title: isLight ? "Switch to dark theme" : "Switch to light theme",
    "aria-label": isLight ? "Switch to dark theme" : "Switch to light theme",
    onclick: () => {
      toggleTheme();
      renderHeader();
    },
  }, isLight ? "\u263E" : "\u2600");
  right.appendChild(themeBtn);

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
        class: "card notification-dropdown",
        role: "menu",
        "aria-label": "Notifications",
        tabindex: "-1",
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
      dropdown.appendChild(el("div", { class: "row p-10" },
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
              role: "menuitem",
              class: `btn w-full text-left ${item.is_read ? "notification-item-read" : "notification-item-unread"}`,
              style: "border-radius:0; display:block;",
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

      dropdown.appendChild(el("div", { class: "p-10" },
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

  const center = el("div", { class: "spacer" });

  if (authed) {
    const searchWrap = el("div", { class: "header-search" });
    const searchInput = el("input", {
      class: "input header-search-input",
      type: "search",
      placeholder: "Search vulnerabilities, products\u2026",
      "aria-label": "Global search",
      "data-global-search": "true",
    });

    const resultsPanel = el("div", { class: "card search-results-dropdown hidden" });

    let currentQuery = "";

    function closeSearchDropdown() {
      searchDropdownOpen = false;
      resultsPanel.classList.add("hidden");
    }

    function renderResults(data) {
      resultsPanel.innerHTML = "";
      const total = data.vulnerabilities.length + data.products.length + data.comments.length;
      if (!total) {
        resultsPanel.appendChild(el("div", { class: "muted p-10" }, "No results found."));
        return;
      }

      if (data.vulnerabilities.length) {
        resultsPanel.appendChild(el("div", { class: "text-label p-8" }, "Vulnerabilities"));
        data.vulnerabilities.forEach((v) => {
          resultsPanel.appendChild(el("button", {
            class: "btn w-full text-left",
            style: "border-radius:0; display:block;",
            onclick: () => { closeSearchDropdown(); navigate(`/vulnerabilities/${v.id}`); },
          }, `${v.cve_id || `#${v.id}`} — ${v.title}`));
        });
      }

      if (data.products.length) {
        resultsPanel.appendChild(el("div", { class: "text-label p-8" }, "Products"));
        data.products.forEach((p) => {
          resultsPanel.appendChild(el("button", {
            class: "btn w-full text-left",
            style: "border-radius:0; display:block;",
            onclick: () => { closeSearchDropdown(); navigate(`/products/${p.id}`); },
          }, p.name));
        });
      }

      if (data.comments.length) {
        resultsPanel.appendChild(el("div", { class: "text-label p-8" }, "Comments"));
        data.comments.forEach((c) => {
          resultsPanel.appendChild(el("button", {
            class: "btn w-full text-left",
            style: "border-radius:0; display:block;",
            onclick: () => { closeSearchDropdown(); navigate(`/vulnerabilities/${c.vulnerability_id}`); },
          }, `${c.author}: ${c.body}`));
        });
      }
    }

    searchInput.addEventListener("input", () => {
      const q = searchInput.value.trim();
      if (searchTimer) clearTimeout(searchTimer);
      if (q.length < 2) { closeSearchDropdown(); return; }
      searchTimer = setTimeout(async () => {
        if (q === currentQuery) return;
        currentQuery = q;
        try {
          const data = await globalSearch(q);
          searchDropdownOpen = true;
          resultsPanel.classList.remove("hidden");
          renderResults(data);
        } catch { /* ignore */ }
      }, 300);
    });

    searchInput.addEventListener("keydown", (e) => {
      if (e.key === "Escape") closeSearchDropdown();
    });

    // Close search results when clicking outside
    document.addEventListener("click", (e) => {
      if (searchDropdownOpen && !searchWrap.contains(e.target)) closeSearchDropdown();
    }, { once: false });

    searchWrap.appendChild(searchInput);
    searchWrap.appendChild(resultsPanel);
    center.appendChild(searchWrap);
  }

  root.appendChild(el("div", { class: "row" }, left, center, right));
}
