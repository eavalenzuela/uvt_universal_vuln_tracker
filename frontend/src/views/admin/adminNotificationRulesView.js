import {
  createNotificationRule,
  deleteNotificationRule,
  listNotificationDeliveryLogs,
  listNotificationRules,
  testSendNotificationRule,
  updateNotificationRule,
} from "../../api/notificationRules.js";
import { listProducts } from "../../api/products.js";
import { el } from "../../ui/dom/el.js";
import { toast } from "../../ui/components/toast.js";

const SEVERITIES = ["None", "Low", "Medium", "High", "Critical"];
const ADAPTERS = ["slack", "jira", "webhook", "email"];

function parseJson(input) {
  if (!input.trim()) return {};
  try {
    return JSON.parse(input);
  } catch (_e) {
    return null;
  }
}

function ruleCard(rule, products, { onSave, onDelete, onTestSend }) {
  const nameInput = el("input", { class: "input", value: rule.name || "" });
  const adapterSelect = el("select", { class: "input" }, ...ADAPTERS.map((a) => el("option", { value: a, selected: rule.delivery_adapter === a }, a)));
  const severitySelect = el("select", { class: "input" }, ...SEVERITIES.map((s) => el("option", { value: s, selected: rule.severity_threshold === s }, s)));
  const enabled = el("input", { type: "checkbox", checked: !!rule.is_enabled });
  const onStatus = el("input", { type: "checkbox", checked: !!rule.notify_on_status_change });
  const onAssignment = el("input", { type: "checkbox", checked: !!rule.notify_on_assignment_change });

  const frequencyDaysInput = el("input", { class: "input", type: "number", min: "1", value: String(rule.frequency_days || 3) });
  const escalationAfterDaysInput = el("input", { class: "input", type: "number", min: "0", value: String(rule.escalation_after_days || 7) });
  const channelsInput = el("input", { class: "input", value: (rule.channels || []).join(",") });
  const recipientsInput = el("input", { class: "input", value: (rule.recipients || []).join(",") });

  const configInput = el("textarea", {
    class: "input",
    rows: "4",
  }, JSON.stringify(rule.delivery_config || {}, null, 2));

  const scopeSelect = el("select", { class: "input", multiple: "multiple", size: "4" },
    ...products.map((p) => el("option", { value: p.id, selected: (rule.product_scope || []).includes(p.id) }, p.name)),
  );

  const saveBtn = el("button", { class: "btn primary" }, "Save");
  saveBtn.addEventListener("click", () => {
    const parsed = parseJson(configInput.value);
    if (parsed === null) {
      toast({ title: "Invalid JSON", message: "delivery_config must be valid JSON" });
      return;
    }
    const productScope = Array.from(scopeSelect.selectedOptions).map((opt) => Number(opt.value));
    onSave(rule.id, {
      frequency_days: Number(frequencyDaysInput.value || 3),
      escalation_after_days: Number(escalationAfterDaysInput.value || 7),
      channels: channelsInput.value.split(",").map((v) => v.trim()).filter(Boolean),
      recipients: recipientsInput.value.split(",").map((v) => v.trim()).filter(Boolean),
      name: nameInput.value,
      is_enabled: enabled.checked,
      delivery_adapter: adapterSelect.value,
      severity_threshold: severitySelect.value,
      notify_on_status_change: onStatus.checked,
      notify_on_assignment_change: onAssignment.checked,
      delivery_config: parsed,
      product_scope: productScope,
    });
  });

  const deleteBtn = el("button", { class: "btn" }, "Delete");
  deleteBtn.addEventListener("click", () => onDelete(rule.id));

  const testBtn = el("button", { class: "btn" }, "Test send");
  testBtn.addEventListener("click", () => onTestSend(rule.id));

  return el("div", { class: "card", style: "padding:12px; display:flex; flex-direction:column; gap:8px;" },
    el("h3", { text: `Rule #${rule.id}` }),
    el("label", {}, "Name", nameInput),
    el("label", {}, "Delivery adapter", adapterSelect),
    el("label", {}, "Severity threshold", severitySelect),
    el("label", {}, enabled, " Enabled"),
    el("label", {}, onStatus, " Notify on status change"),
    el("label", {}, onAssignment, " Notify on assignment change"),
    el("label", {}, "Reminder cadence (days)", frequencyDaysInput),
    el("label", {}, "Escalation step size (days)", escalationAfterDaysInput),
    el("label", {}, "Channels (comma-separated)", channelsInput),
    el("label", {}, "Recipients (comma-separated)", recipientsInput),
    el("label", {}, "Delivery config (JSON)", configInput),
    el("label", {}, "Product scope", scopeSelect),
    el("div", { class: "row", style: "gap:8px;" }, saveBtn, testBtn, deleteBtn),
  );
}

export async function AdminNotificationRulesView() {
  let rules = [];
  let products = [];
  let logs = [];

  const list = el("div", { style: "display:flex; flex-direction:column; gap:10px;" });
  const logList = el("div", { style: "display:flex; flex-direction:column; gap:6px;" });

  async function refresh() {
    [rules, products, logs] = await Promise.all([
      listNotificationRules(),
      listProducts(),
      listNotificationDeliveryLogs(25),
    ]);
    render();
  }

  async function createNew() {
    await createNotificationRule({
      name: "New notification rule",
      delivery_adapter: "slack",
      severity_threshold: "High",
      notify_on_status_change: true,
      notify_on_assignment_change: true,
      is_enabled: true,
      delivery_config: {},
      product_scope: [],
      frequency_days: 3,
      escalation_after_days: 7,
      channels: [],
      recipients: [],
    });
    toast({ title: "Rule created" });
    await refresh();
  }

  async function onSave(ruleId, payload) {
    await updateNotificationRule(ruleId, payload);
    toast({ title: "Rule saved" });
    await refresh();
  }

  async function onDelete(ruleId) {
    await deleteNotificationRule(ruleId);
    toast({ title: "Rule deleted" });
    await refresh();
  }

  async function onTestSend(ruleId) {
    const result = await testSendNotificationRule(ruleId);
    toast({ title: "Test send complete", message: `Attempts: ${result.sent}` });
    await refresh();
  }

  function render() {
    list.innerHTML = "";
    if (!rules.length) {
      list.appendChild(el("div", { class: "muted", text: "No notification rules configured." }));
    } else {
      rules.forEach((rule) => {
        list.appendChild(ruleCard(rule, products, { onSave, onDelete, onTestSend }));
      });
    }

    logList.innerHTML = "";
    if (!logs.length) {
      logList.appendChild(el("div", { class: "muted", text: "No delivery logs yet." }));
    } else {
      logs.forEach((log) => {
        logList.appendChild(el("div", { class: "card", style: "padding:8px;" },
          el("div", { text: `Rule ${log.rule_id} · Vuln ${log.vulnerability_id} · ${log.event_type}` }),
          el("div", { class: "muted", text: `${log.delivery_adapter} · ${log.success ? "success" : "failed"}` }),
          log.error_message ? el("div", { class: "muted", text: log.error_message }) : null,
        ));
      });
    }
  }

  try {
    await refresh();
  } catch (e) {
    toast({ title: "Failed to load notification rules", message: e?.message || "Unknown error" });
  }

  const addBtn = el("button", { class: "btn primary" }, "Add notification rule");
  addBtn.addEventListener("click", createNew);

  return el("div", { class: "stack" },
    el("h1", { text: "Admin · Notification Rules" }),
    el("p", { class: "muted", text: "Configure event and scheduled reminder notifications, cadence, and escalation targets." }),
    addBtn,
    list,
    el("h2", { text: "Recent delivery logs" }),
    logList,
  );
}
