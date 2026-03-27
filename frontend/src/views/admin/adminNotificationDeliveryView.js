import {
  listNotificationDeliveryAttempts,
  replayNotificationDeliveryAttempt,
  retryNotificationDeliveryAttempt,
} from "../../api/notificationDelivery.js";
import { el } from "../../ui/dom/el.js";
import { toast } from "../../ui/components/toast.js";

function formatDate(value) {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString();
}

function attemptRow(attempt, { onRetry, onReplay }) {
  const retryBtn = el(
    "button",
    {
      class: "btn",
      disabled: attempt.status !== "failed",
      onclick: () => onRetry(attempt),
    },
    "Retry",
  );
  const replayBtn = el(
    "button",
    {
      class: "btn",
      onclick: () => onReplay(attempt),
    },
    "Replay",
  );

  return el(
    "tr",
    {},
    el("td", {}, `${attempt.id}`),
    el("td", {}, attempt.status || "—"),
    el("td", {}, attempt.channel || "—"),
    el("td", {}, attempt.error || "—"),
    el("td", {}, `${attempt.retry_count ?? 0}`),
    el("td", {}, formatDate(attempt.next_retry_at)),
    el("td", {}, formatDate(attempt.created_at)),
    el("td", {}, el("div", { class: "row gap-6" }, retryBtn, replayBtn)),
  );
}

export async function AdminNotificationDeliveryView() {
  let failedOnly = true;
  let attempts = [];

  const tbody = el("tbody", {});
  const table = el(
    "table",
    { class: "card w-full", style: "border-collapse:collapse;" },
    el(
      "thead",
      {},
      el(
        "tr",
        {},
        el("th", {}, "ID"),
        el("th", {}, "Status"),
        el("th", {}, "Channel"),
        el("th", {}, "Error"),
        el("th", {}, "Retry Count"),
        el("th", {}, "Next Retry"),
        el("th", {}, "Created"),
        el("th", {}, "Actions"),
      ),
    ),
    tbody,
  );

  async function refresh() {
    attempts = await listNotificationDeliveryAttempts({ limit: 100, failedOnly });
    render();
  }

  async function onRetry(attempt) {
    if (attempt.status !== "failed") {
      toast({ title: "Retry blocked", message: "Only failed delivery attempts can be retried." });
      return;
    }
    if (!window.confirm(`Retry failed delivery attempt #${attempt.id}?`)) return;
    const result = await retryNotificationDeliveryAttempt(attempt.id);
    toast({ title: "Retry submitted", message: `New attempts: ${result.attempts || 0}` });
    await refresh();
  }

  async function onReplay(attempt) {
    if (!window.confirm(`Replay delivery attempt #${attempt.id}? This triggers the original rule again.`)) return;
    const result = await replayNotificationDeliveryAttempt(attempt.id);
    toast({ title: "Replay submitted", message: `New attempts: ${result.attempts || 0}` });
    await refresh();
  }

  function render() {
    tbody.innerHTML = "";
    if (!attempts.length) {
      tbody.appendChild(el("tr", {}, el("td", { colSpan: "8", class: "muted" }, "No delivery attempts found.")));
      return;
    }
    attempts.forEach((attempt) => tbody.appendChild(attemptRow(attempt, { onRetry, onReplay })));
  }

  const failedOnlyToggle = el("input", {
    type: "checkbox",
    checked: failedOnly,
    onchange: async (e) => {
      failedOnly = !!e.target.checked;
      await refresh();
    },
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
    el("div", { class: "row flex-row-8" }, failedOnlyToggle, el("span", {}, "Show failed only"), refreshBtn),
    table,
  );
}
