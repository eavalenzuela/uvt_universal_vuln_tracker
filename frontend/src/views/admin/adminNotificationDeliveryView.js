import {
  listNotificationDeliveryAttempts,
  replayNotificationDeliveryAttempt,
  retryNotificationDeliveryAttempt,
} from "../../api/notificationDelivery.js";
import { el } from "../../ui/dom/el.js";
import { toast } from "../../ui/components/toast.js";
import { confirmModal } from "../../ui/components/modal.js";
import { createDataTable, createDensityToggle } from "../../ui/components/dataTable.js";

function formatDate(value) {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString();
}

export async function AdminNotificationDeliveryView() {
  let failedOnly = true;
  let attempts = [];
  let density = "comfortable";

  const tableContainer = el("div", {});

  async function refresh() {
    attempts = await listNotificationDeliveryAttempts({ limit: 100, failedOnly });
    render();
  }

  async function onRetry(attempt) {
    if (attempt.status !== "failed") {
      toast({ title: "Retry blocked", message: "Only failed delivery attempts can be retried." });
      return;
    }
    if (!(await confirmModal({ title: "Retry delivery", message: `Retry failed delivery attempt #${attempt.id}?`, confirmText: "Retry" }))) return;
    const result = await retryNotificationDeliveryAttempt(attempt.id);
    toast({ title: "Retry submitted", message: `New attempts: ${result.attempts || 0}` });
    await refresh();
  }

  async function onReplay(attempt) {
    if (!(await confirmModal({ title: "Replay delivery", message: `Replay delivery attempt #${attempt.id}? This triggers the original rule again.`, confirmText: "Replay" }))) return;
    const result = await replayNotificationDeliveryAttempt(attempt.id);
    toast({ title: "Replay submitted", message: `New attempts: ${result.attempts || 0}` });
    await refresh();
  }

  function render() {
    tableContainer.innerHTML = "";

    const columns = [
      { key: "id", label: "ID" },
      { key: "status", label: "Status", render: (row) => row.status || "—" },
      { key: "channel", label: "Channel", render: (row) => row.channel || "—" },
      { key: "error", label: "Error", render: (row) => row.error || "—" },
      { key: "retry_count", label: "Retry Count", render: (row) => `${row.retry_count ?? 0}` },
      { key: "next_retry_at", label: "Next Retry", render: (row) => formatDate(row.next_retry_at) },
      { key: "created_at", label: "Created", render: (row) => formatDate(row.created_at) },
    ];

    const dataTable = createDataTable({
      columns,
      rows: attempts,
      emptyText: "No delivery attempts found.",
      density,
      rowActions: (attempt) =>
        el(
          "div",
          { class: "row gap-6" },
          el(
            "button",
            {
              class: "btn",
              disabled: attempt.status !== "failed",
              onclick: () => onRetry(attempt),
            },
            "Retry",
          ),
          el(
            "button",
            {
              class: "btn",
              onclick: () => onReplay(attempt),
            },
            "Replay",
          ),
        ),
    });

    tableContainer.appendChild(dataTable);
  }

  const failedOnlyToggle = el("input", {
    type: "checkbox",
    checked: failedOnly,
    onchange: async (e) => {
      failedOnly = !!e.target.checked;
      await refresh();
    },
  });

  const densityToggle = createDensityToggle(density, (newDensity) => {
    density = newDensity;
    render();
  });

  const refreshBtn = el("button", { class: "btn", onclick: refresh }, "Refresh");

  try {
    await refresh();
  } catch (e) {
    toast({ title: "Failed to load deliveries", message: e?.message || "Unknown error" });
  }

  return el(
    "div",
    { class: "stack" },
    el("h1", { text: "Admin · Notification Delivery" }),
    el("p", { class: "muted", text: "Monitor recent notification attempts and trigger guarded retry/replay actions." }),
    el("div", { class: "row flex-row-8" }, failedOnlyToggle, el("span", {}, "Show failed only"), densityToggle, refreshBtn),
    tableContainer,
  );
}
