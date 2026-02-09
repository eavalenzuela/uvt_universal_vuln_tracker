import {
  createReportSchedule,
  createReportTemplate,
  deleteReportSchedule,
  deleteReportTemplate,
  listReportSchedules,
  listReportTemplates,
  runReportSchedule,
  updateReportSchedule,
  updateReportTemplate,
} from "../../api/reports.js";
import { el } from "../../ui/dom/el.js";
import { toast } from "../../ui/components/toast.js";

const REPORT_TYPES = ["vulnerabilities", "dashboard_summary"];
const FREQUENCIES = ["daily", "weekly"];
const CHANNELS = ["email", "slack"];
const FORMATS = ["csv", "json", "pdf"];
const VISIBILITY = ["private", "team"];

function textInput(value = "") {
  return el("input", { class: "input", value });
}

function templateCard(template, handlers) {
  const name = textInput(template.name || "");
  const reportType = el("select", { class: "input" }, ...REPORT_TYPES.map((value) => el("option", { value, selected: template.report_type === value }, value)));
  const format = el("select", { class: "input" }, ...FORMATS.map((value) => el("option", { value, selected: template.format === value }, value)));
  const channel = el("select", { class: "input" }, ...CHANNELS.map((value) => el("option", { value, selected: template.delivery_channel === value }, value)));
  const visibility = el("select", { class: "input" }, ...VISIBILITY.map((value) => el("option", { value, selected: template.visibility === value }, value)));
  const recipients = textInput((template.recipients || []).join(", "));
  const fields = textInput((template.fields || []).join(", "));
  const filters = el("textarea", { class: "input", rows: "3" }, JSON.stringify(template.filters || {}, null, 2));
  const preferences = el("textarea", { class: "input", rows: "3" }, JSON.stringify(template.delivery_preferences || {}, null, 2));

  const saveBtn = el("button", { class: "btn primary" }, "Save");
  saveBtn.onclick = async () => {
    try {
      await handlers.onSave(template.id, {
        name: name.value,
        report_type: reportType.value,
        format: format.value,
        delivery_channel: channel.value,
        visibility: visibility.value,
        recipients: recipients.value.split(",").map((entry) => entry.trim()).filter(Boolean),
        fields: fields.value.split(",").map((entry) => entry.trim()).filter(Boolean),
        filters: JSON.parse(filters.value || "{}"),
        delivery_preferences: JSON.parse(preferences.value || "{}"),
      });
    } catch (error) {
      toast({ title: "Save template failed", message: error?.message || "Invalid JSON input" });
    }
  };

  const deleteBtn = el("button", { class: "btn" }, "Delete");
  deleteBtn.onclick = async () => handlers.onDelete(template.id);

  return el("div", { class: "card", style: "padding:12px; display:flex; flex-direction:column; gap:8px;" },
    el("h3", { text: `${template.name} (#${template.id})` }),
    el("div", { class: "muted", text: `Owner: ${template.owner?.username || "unknown"} · Visibility: ${template.visibility}` }),
    el("label", {}, "Name", name),
    el("label", {}, "Report type", reportType),
    el("label", {}, "Format", format),
    el("label", {}, "Channel", channel),
    el("label", {}, "Visibility", visibility),
    el("label", {}, "Recipients (comma-separated)", recipients),
    el("label", {}, "Fields (comma-separated)", fields),
    el("label", {}, "Filters (JSON)", filters),
    el("label", {}, "Delivery preferences (JSON)", preferences),
    el("div", { class: "row", style: "gap:8px;" }, saveBtn, deleteBtn),
  );
}

function scheduleCard(schedule, templates, handlers) {
  const name = textInput(schedule.name || "");
  const filterPreset = textInput(schedule.filter_preset || "");
  const timezone = textInput(schedule.timezone || "UTC");
  const recipients = textInput((schedule.recipients || []).join(", "));
  const filters = el("textarea", { class: "input", rows: "3" }, JSON.stringify(schedule.filters || {}, null, 2));
  const preferences = el("textarea", { class: "input", rows: "3" }, JSON.stringify(schedule.delivery_preferences || {}, null, 2));

  const reportType = el("select", { class: "input" }, ...REPORT_TYPES.map((value) => el("option", { value, selected: schedule.report_type === value }, value)));
  const frequency = el("select", { class: "input" }, ...FREQUENCIES.map((value) => el("option", { value, selected: schedule.frequency === value }, value)));
  const channel = el("select", { class: "input" }, ...CHANNELS.map((value) => el("option", { value, selected: schedule.delivery_channel === value }, value)));
  const templateSelect = el("select", { class: "input" },
    el("option", { value: "", selected: !schedule.report_template_id }, "No template"),
    ...templates.map((item) => el("option", { value: String(item.id), selected: schedule.report_template_id === item.id }, `${item.name} (#${item.id})`)),
  );

  const saveBtn = el("button", { class: "btn primary" }, "Save");
  saveBtn.onclick = async () => {
    try {
      const payload = {
        name: name.value,
        report_template_id: templateSelect.value ? Number(templateSelect.value) : null,
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
  runBtn.onclick = async () => handlers.onRun(schedule.id);

  const deleteBtn = el("button", { class: "btn" }, "Delete");
  deleteBtn.onclick = async () => handlers.onDelete(schedule.id);

  return el("div", { class: "card", style: "padding:12px; display:flex; flex-direction:column; gap:8px;" },
    el("h3", { text: `${schedule.name} (#${schedule.id})` }),
    el("div", { class: "muted", text: `Last run: ${schedule.last_run_at || "Never"} · Status: ${schedule.last_run_status || "never"}` }),
    schedule.report_template ? el("div", { class: "muted", text: `Template: ${schedule.report_template.name} (#${schedule.report_template.id})` }) : null,
    schedule.last_failure_reason ? el("div", { class: "muted", text: `Failure reason: ${schedule.last_failure_reason}` }) : null,
    el("div", { class: "muted", text: `Retry count: ${schedule.retry_count || 0}${schedule.next_retry_at ? ` · Next retry: ${schedule.next_retry_at}` : ""}` }),
    el("label", {}, "Name", name),
    el("label", {}, "Template", templateSelect),
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
  const templateList = el("div", { style: "display:flex; flex-direction:column; gap:10px;" });
  const scheduleList = el("div", { style: "display:flex; flex-direction:column; gap:10px;" });

  async function refresh() {
    const [templates, schedules] = await Promise.all([listReportTemplates(), listReportSchedules()]);
    templateList.innerHTML = "";
    scheduleList.innerHTML = "";

    if (!templates.length) {
      templateList.appendChild(el("div", { class: "muted", text: "No report templates configured." }));
    }
    templates.forEach((template) => {
      templateList.appendChild(templateCard(template, {
        onSave: async (id, payload) => {
          await updateReportTemplate(id, payload);
          toast({ title: "Template updated" });
          await refresh();
        },
        onDelete: async (id) => {
          await deleteReportTemplate(id);
          toast({ title: "Template deleted" });
          await refresh();
        },
      }));
    });

    if (!schedules.length) {
      scheduleList.appendChild(el("div", { class: "muted", text: "No report subscriptions configured." }));
    }
    schedules.forEach((schedule) => {
      scheduleList.appendChild(scheduleCard(schedule, templates, {
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

  const addTemplateBtn = el("button", { class: "btn" }, "Create template");
  addTemplateBtn.onclick = async () => {
    await createReportTemplate({
      name: "New report template",
      report_type: "vulnerabilities",
      format: "csv",
      delivery_channel: "email",
      recipients: ["team@example.com"],
      fields: ["id", "cve_id", "title", "severity", "status"],
      filters: {},
      delivery_preferences: {},
      visibility: "private",
    });
    toast({ title: "Template created" });
    await refresh();
  };

  const addScheduleBtn = el("button", { class: "btn primary" }, "Create subscription");
  addScheduleBtn.onclick = async () => {
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
    toast({ title: "Failed to load report admin data", message: error?.message || "Unknown error" });
  }

  return el("div", { class: "stack" },
    el("h1", { text: "Admin · Report Subscriptions" }),
    el("p", { class: "muted", text: "Manage reusable report templates and scheduled report subscriptions." }),
    el("h2", { text: "Templates" }),
    addTemplateBtn,
    templateList,
    el("h2", { text: "Schedules" }),
    addScheduleBtn,
    scheduleList,
  );
}
