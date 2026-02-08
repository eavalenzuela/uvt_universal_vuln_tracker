import { el } from "../../ui/dom/el.js";
import { deleteNotification, listNotifications, markAllNotificationsRead, markNotificationRead } from "../../api/notifications.js";
import { removeNotification, setNotifications } from "../../state/store.js";

export function NotificationsView() {
  const root = el("div", { class: "stack" });
  root.appendChild(el("h2", {}, "Notifications"));

  const actions = el("div", { class: "row", style: "gap:8px;" });
  const tableWrap = el("div", { class: "card" }, el("div", { class: "muted", style: "padding:10px;" }, "Loading..."));

  let page = 1;
  const pageSize = 25;

  async function load() {
    const payload = await listNotifications({ page, page_size: pageSize });
    setNotifications(payload);
    const data = payload?.data || {};
    const items = data.items || [];

    tableWrap.innerHTML = "";
    if (!items.length) {
      tableWrap.appendChild(el("div", { class: "muted", style: "padding:10px;" }, "No notifications."));
      return;
    }

    const list = el("div", { class: "stack", style: "padding:8px;" });
    items.forEach((item) => {
      list.appendChild(el("div", { class: "row", style: `gap:8px; align-items:flex-start; padding:8px; border-left:3px solid ${item.is_read ? "transparent" : "#2563eb"};` },
        el("div", { class: "stack", style: "flex:1;" },
          el("div", {}, item.message || "Notification"),
          el("div", { class: "muted" }, item.created_at ? new Date(item.created_at).toLocaleString() : ""),
        ),
        el("button", {
          class: "btn",
          onclick: async () => {
            await markNotificationRead(item.id, !item.is_read);
            await load();
          },
        }, item.is_read ? "Mark unread" : "Mark read"),
        el("button", {
          class: "btn",
          onclick: async () => {
            await deleteNotification(item.id, "archive");
            removeNotification(item.id);
            await load();
          },
        }, "Archive"),
      ));
    });

    const pagination = el("div", { class: "row", style: "padding:8px;" },
      el("button", {
        class: "btn",
        disabled: !data?.pagination?.has_prev,
        onclick: async () => { page -= 1; await load(); },
      }, "Prev"),
      el("div", { class: "muted" }, `Page ${data?.pagination?.page || 1} of ${data?.pagination?.pages || 1}`),
      el("button", {
        class: "btn",
        disabled: !data?.pagination?.has_next,
        onclick: async () => { page += 1; await load(); },
      }, "Next"),
    );

    tableWrap.append(list, pagination);
  }

  actions.appendChild(el("button", {
    class: "btn",
    onclick: async () => {
      await markAllNotificationsRead();
      await load();
    },
  }, "Mark all as read"));

  actions.appendChild(el("button", { class: "btn", onclick: load }, "Refresh"));

  root.append(actions, tableWrap);
  load().catch((err) => {
    tableWrap.innerHTML = "";
    tableWrap.appendChild(el("div", { class: "muted", style: "padding:10px;" }, `Failed to load notifications: ${err?.message || err}`));
  });

  return root;
}
