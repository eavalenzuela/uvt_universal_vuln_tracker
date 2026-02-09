import {
  createReportSchedule,
  deleteReportSchedule,
  listReportSchedules,
  runReportSchedule,
  updateReportSchedule,
} from "../../api/reports.js";
import { el } from "../../ui/dom/el.js";
import { toast } from "../../ui/components/toast.js";

const REPORT_TYPES = ["vulnerabilities", "dashboard_summary"];
const FREQUENCIES = ["daily", "weekly"];
const CHANNELS = ["email", "slack"];

function textInput(value = "") {
  return el("input", { class: "input", value });
}

function scheduleCard(schedule, handlers) {
  const name = textInput(schedule.name || "");
  const filterPreset = textInput(schedule.filter_preset || "");
  const timezone = textInput(schedule.timezone || "UTC");
  const recipients = textInput((schedule.recipients || []).join(", "));
  const filters = el("textarea", { class: "input", rows: "3" }, JSON.stringify(schedule.filters || {}, null, 2));
  const preferences = el("textarea", { class: "input", rows: "3" }, JSON.stringify(schedule.delivery_preferences || {}, null, 2));

  const reportType = el("select", { class: "input" }, ...REPORT_TYPES.map((value) => el("option", { value, selected: schedule.report_type === value }, value)));
  const frequency = el("select", { class: "input" }, ...FREQUENCIES.map((value) => el("option", { value, selected: schedule.frequency === value }, value)));
  const channel = el("select", { class: "input" }, ...CHANNELS.map((value) => el("option", { value, selected: schedule.delivery_channel === value }, value)));

  const saveBtn = el("button", { class: "btn primary" }, "Save");
  saveBtn.onclick = async () => {
    try {
      const payload = {
        name: name.value,
        report_type: reportType.value,
        frequency: frequency.value,
        delivery_channel: channel.value,
        recipients: recipients.value.split(",").map((entry) => entry.trim()).filter(Boolean),
        timezone: timezone.value,
        filter_preset: filterPreset.value || null,
        filters: JSON.parse(filters.value || "{}"),
        delivery_preferences: JSON.parse(preferences.value || "{}"),
      };
      await handlers.onSave(schedule.id, payload);
    } catch (error) {
      toast({ title: "Save failed", message: error?.message || "Invalid JSON input" });
    }
  };

  const runBtn = el("button", { class: "btn" }, "Run now");
  runBtn.onclick = async () => {
    await handlers.onRun(schedule.id);
  };

  const deleteBtn = el("button", { class: "btn" }, "Delete");
  deleteBtn.onclick = async () => {
    await handlers.onDelete(schedule.id);
  };

  return el("div", { class: "card", style: "padding:12px; display:flex; flex-direction:column; gap:8px;" },
    el("h3", { text: `${schedule.name} (#${schedule.id})` }),
    el("div", { class: "muted", text: `Last run: ${schedule.last_run_at || "Never"} · Status: ${schedule.last_run_status || "never"}` }),
    schedule.last_failure_reason ? el("div", { class: "muted", text: `Failure reason: ${schedule.last_failure_reason}` }) : null,
    el("div", { class: "muted", text: `Retry count: ${schedule.retry_count || 0}${schedule.next_retry_at ? ` · Next retry: ${schedule.next_retry_at}` : ""}` }),
    el("label", {}, "Name", name),
    el("label", {}, "Report type", reportType),
    el("label", {}, "Filter preset", filterPreset),
    el("label", {}, "Frequency", frequency),
    el("label", {}, "Channel", channel),
    el("label", {}, "Recipients (comma-separated)", recipients),
    el("label", {}, "Timezone", timezone),
    el("label", {}, "Filters (JSON)", filters),
    el("label", {}, "Delivery preferences (JSON)", preferences),
    el("div", { class: "row", style: "gap:8px;" }, saveBtn, runBtn, deleteBtn),
  );
}

export async function AdminReportsView() {
  const list = el("div", { style: "display:flex; flex-direction:column; gap:10px;" });

  async function refresh() {
    const schedules = await listReportSchedules();
    list.innerHTML = "";
    if (!schedules.length) {
      list.appendChild(el("div", { class: "muted", text: "No report subscriptions configured." }));
      return;
    }

    schedules.forEach((schedule) => {
      list.appendChild(scheduleCard(schedule, {
        onSave: async (id, payload) => {
          await updateReportSchedule(id, payload);
          toast({ title: "Subscription updated" });
          await refresh();
        },
        onRun: async (id) => {
          const result = await runReportSchedule(id);
          toast({ title: "Execution complete", message: `Status: ${result.status}` });
          await refresh();
        },
        onDelete: async (id) => {
          await deleteReportSchedule(id);
          toast({ title: "Subscription removed" });
          await refresh();
        },
      }));
    });
  }

  const addBtn = el("button", { class: "btn primary" }, "Create subscription");
  addBtn.onclick = async () => {
    await createReportSchedule({
      name: "New report subscription",
      report_type: "vulnerabilities",
      frequency: "daily",
      delivery_channel: "email",
      recipients: ["team@example.com"],
      timezone: "UTC",
      filter_preset: "default-open",
      filters: {},
      delivery_preferences: {},
    });
    toast({ title: "Subscription created" });
    await refresh();
  };

  try {
    await refresh();
  } catch (error) {
    toast({ title: "Failed to load subscriptions", message: error?.message || "Unknown error" });
  }

  return el("div", { class: "stack" },
    el("h1", { text: "Admin · Report Subscriptions" }),
    el("p", { class: "muted", text: "Create and manage report subscriptions, delivery channels, and recipients." }),
    addBtn,
    list,
  );
}
