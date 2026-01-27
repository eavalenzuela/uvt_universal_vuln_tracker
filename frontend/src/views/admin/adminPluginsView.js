import { listPlugins, updatePluginConfig } from "../../api/plugins.js";
import { el } from "../../ui/dom/el.js";
import { toast } from "../../ui/components/toast.js";

const MASKED_VALUES = new Set(["****", "******"]);

function isMaskedValue(value) {
  return typeof value === "string" && MASKED_VALUES.has(value.trim());
}

function normalizeFields(schema) {
  if (!schema) return [];
  const fields = schema.fields ?? schema;
  if (Array.isArray(fields)) {
    return fields.map((field) => ({
      name: field.name,
      label: field.label || field.name,
      type: field.type || "string",
      secret: Boolean(field.secret),
      required: Boolean(field.required),
      defaultValue: field.default,
    }));
  }
  if (fields && typeof fields === "object") {
    return Object.entries(fields).map(([name, value]) => {
      const spec = typeof value === "object" ? value : { type: value };
      return {
        name,
        label: spec.label || name,
        type: spec.type || "string",
        secret: Boolean(spec.secret),
        required: Boolean(spec.required),
        defaultValue: spec.default,
      };
    });
  }
  return [];
}

function formatFieldValue(field, value) {
  if (value === undefined || value === null || value === "") {
    if (field.defaultValue !== undefined) {
      return `${field.defaultValue}`;
    }
    return "Not configured";
  }
  if (field.type === "boolean") {
    return value ? "Enabled" : "Disabled";
  }
  if (field.secret || isMaskedValue(value)) {
    return "••••••••";
  }
  return `${value}`;
}

function formatLastRun(lastRun) {
  if (!lastRun) return "Not run yet";
  if (lastRun.finished_at) {
    const timestamp = new Date(lastRun.finished_at);
    if (!Number.isNaN(timestamp.valueOf())) {
      return `${lastRun.status || "Run"} · ${timestamp.toLocaleString()}`;
    }
  }
  return lastRun.status || "Run in progress";
}

function healthLabel(lastRun) {
  if (!lastRun) return "Not run";
  return lastRun.status ? lastRun.status.replace(/_/g, " ") : "Unknown";
}

function healthColor(lastRun) {
  if (!lastRun || !lastRun.status) return "#6b7280";
  if (["success", "healthy", "ok"].includes(lastRun.status)) return "#059669";
  if (["failed", "error"].includes(lastRun.status)) return "#dc2626";
  return "#d97706";
}

function pill(label, color, subtle = false) {
  const baseColor = color || "#1f2937";
  const bg = subtle ? `${baseColor}15` : `${baseColor}22`;
  return el("span", {
    class: "pill",
    style: `display:inline-flex; align-items:center; gap:6px; padding:4px 8px; border-radius:12px; font-size:12px; background:${bg}; color:${baseColor}; border:1px solid ${baseColor}33; font-weight:600;`,
    text: label,
  });
}

function pluginCard(plugin, { onToggle, onConfigure }) {
  const statusLabel = plugin.enabled ? "Enabled" : "Disabled";
  const statusColor = plugin.enabled ? "#16a34a" : "#dc2626";
  const healthState = healthLabel(plugin.last_run);
  const healthStateColor = healthColor(plugin.last_run);
  const configFields = normalizeFields(plugin.config_schema);

  const toggleBtn = el("button", { class: "btn" }, plugin.enabled ? "Disable" : "Enable");
  toggleBtn.addEventListener("click", () => onToggle(plugin));

  const configBtn = el("button", { class: "btn" }, "Configure");
  configBtn.addEventListener("click", () => onConfigure(plugin));

  return el("div", { class: "card", style: "padding: 12px; display:flex; flex-direction:column; gap:10px;" },
    el("div", { class: "row", style: "align-items:flex-start; gap:12px; flex-wrap:wrap;" },
      el("div", { style: "flex:1; min-width: 220px;" },
        el("div", { class: "row", style: "align-items:center; gap:8px; flex-wrap:wrap;" },
          el("div", { style: "font-weight:700;", text: plugin.display_name || plugin.plugin_id }),
          pill(statusLabel, statusColor, true),
          pill(healthState, healthStateColor, true),
        ),
        el("div", { class: "row", style: "gap: 8px; margin-top: 8px; flex-wrap:wrap;" },
          plugin.version ? el("div", { class: "muted", text: `Version ${plugin.version}` }) : null,
          el("div", { class: "muted", text: `ID: ${plugin.plugin_id}` }),
          el("div", { class: "muted", text: formatLastRun(plugin.last_run) }),
        ),
      ),
      el("div", { class: "row", style: "gap: 6px; flex-wrap:wrap;" },
        configBtn,
        toggleBtn,
      ),
    ),
    plugin.capabilities?.length
      ? el("div", { class: "row", style: "gap: 6px; flex-wrap:wrap;" },
        el("div", { class: "muted", text: "Capabilities:" }),
        ...plugin.capabilities.map((scope) => pill(scope, "#2563eb", true)),
      )
      : null,
    configFields.length
      ? el("div", { style: "display:flex; flex-direction:column; gap:6px;" },
        el("div", { class: "muted", text: "Configuration:" }),
        ...configFields.map((field) => el("div", { class: "row", style: "gap:8px; flex-wrap:wrap;" },
          el("div", { style: "min-width: 140px; font-weight:600;", text: field.label }),
          el("div", { class: "muted", text: formatFieldValue(field, plugin.config?.[field.name]) }),
        )),
      )
      : null,
    plugin.schedule_cron || plugin.interval_minutes
      ? el("div", { class: "muted", text: plugin.schedule_cron ? `Schedule: ${plugin.schedule_cron}` : `Interval: ${plugin.interval_minutes} minutes` })
      : null,
  );
}

export async function AdminPluginsView() {
  let plugins = [];
  let isLoading = true;

  const list = el("div", { style: "display:flex; flex-direction:column; gap:10px;" });
  const addBtn = el("button", { class: "btn primary" }, "Add plugin");

  function renderList() {
    list.innerHTML = "";
    if (isLoading) {
      list.appendChild(el("div", { class: "muted", text: "Loading plugins..." }));
      return;
    }
    if (!plugins.length) {
      list.appendChild(el("div", { class: "muted", text: "No plugins available." }));
      return;
    }
    plugins.forEach((plugin) => {
      list.appendChild(pluginCard(plugin, {
        onToggle: async (target) => {
          const nextEnabled = !target.enabled;
          try {
            await updatePluginConfig(target.plugin_id, { enabled: nextEnabled });
            toast({
              title: nextEnabled ? "Plugin enabled" : "Plugin disabled",
              message: `${target.display_name || target.plugin_id} is now ${nextEnabled ? "active" : "inactive"}.`,
            });
            await loadPlugins();
          } catch (error) {
            toast({
              title: "Update failed",
              message: error?.message || "Unable to update plugin status.",
              variant: "error",
            });
          }
        },
        onConfigure: (target) => openConfigModal(target),
      }));
    });
  }

  addBtn.addEventListener("click", () => {
    toast({ title: "Coming soon", message: "Plugin marketplace access is not configured yet." });
  });

  async function loadPlugins() {
    isLoading = true;
    renderList();
    try {
      plugins = await listPlugins();
    } catch (error) {
      toast({
        title: "Unable to load plugins",
        message: error?.message || "Please try again later.",
        variant: "error",
      });
    } finally {
      isLoading = false;
      renderList();
    }
  }

  function openConfigModal(plugin) {
    const fields = normalizeFields(plugin.config_schema);
    const overlay = el("div", {
      style:
        "position:fixed; inset:0; background:rgba(15, 23, 42, 0.55); display:flex; align-items:center; justify-content:center; z-index:40;",
      onClick: (event) => {
        if (event.target === overlay) closeModal();
      },
    });

    const modal = el(
      "div",
      {
        style:
          "background:#0f172a; color:#e6e8ee; border-radius:12px; width:min(560px, 92vw); padding:20px; display:flex; flex-direction:column; gap:16px; border:1px solid rgba(148, 163, 184, 0.25); box-shadow:0 20px 40px rgba(2,6,23,0.6);",
        role: "dialog",
        "aria-modal": "true",
        "aria-label": `Configure ${plugin.display_name || plugin.plugin_id}`,
      },
      el("h2", { text: `Configure ${plugin.display_name || plugin.plugin_id}` }),
    );

    const fieldInputs = new Map();
    const form = el("div", { style: "display:flex; flex-direction:column; gap:12px;" });

    if (!fields.length) {
      form.appendChild(el("div", { class: "muted", text: "This plugin does not expose configurable fields." }));
    } else {
      fields.forEach((field) => {
        const currentValue = plugin.config?.[field.name];
        if (field.type === "boolean") {
          const checkbox = el("input", {
            type: "checkbox",
            checked: currentValue !== undefined ? Boolean(currentValue) : Boolean(field.defaultValue),
          });
          fieldInputs.set(field.name, { type: "boolean", input: checkbox, masked: false, secret: field.secret });
          form.appendChild(el("label", { style: "display:flex; align-items:center; gap:8px;" },
            checkbox,
            el("span", { text: field.label }),
          ));
          return;
        }

        const isMasked = isMaskedValue(currentValue);
        const input = el("input", {
          class: "input",
          type: field.secret ? "password" : "text",
          value: isMasked ? "" : (currentValue ?? field.defaultValue ?? ""),
          placeholder: isMasked ? "Configured" : "",
        });
        fieldInputs.set(field.name, { type: "string", input, masked: isMasked, secret: field.secret });
        form.appendChild(el("div", { style: "display:flex; flex-direction:column; gap:6px;" },
          el("label", { text: field.label }),
          input,
        ));
      });
    }

    const statusRow = el("div", { class: "muted" });
    const saveBtn = el("button", { class: "btn primary", text: "Save" });
    const cancelBtn = el("button", { class: "btn", text: "Cancel", onClick: closeModal });

    saveBtn.addEventListener("click", async () => {
      if (!fields.length) {
        closeModal();
        return;
      }
      saveBtn.disabled = true;
      cancelBtn.disabled = true;
      statusRow.textContent = "Saving configuration...";
      const configPayload = {};
      fields.forEach((field) => {
        const entry = fieldInputs.get(field.name);
        if (!entry) return;
        if (entry.type === "boolean") {
          configPayload[field.name] = entry.input.checked;
          return;
        }
        const rawValue = entry.input.value;
        if (entry.secret && rawValue === "" && entry.masked) {
          configPayload[field.name] = "****";
        } else {
          configPayload[field.name] = rawValue;
        }
      });
      try {
        await updatePluginConfig(plugin.plugin_id, { config: configPayload });
        toast({ title: "Settings saved", message: `${plugin.display_name || plugin.plugin_id} updated.` });
        closeModal();
        await loadPlugins();
      } catch (error) {
        toast({
          title: "Save failed",
          message: error?.message || "Unable to update plugin configuration.",
          variant: "error",
        });
        saveBtn.disabled = false;
        cancelBtn.disabled = false;
        statusRow.textContent = "Save failed. Please review inputs and try again.";
      }
    });

    modal.append(
      form,
      statusRow,
      el("div", { style: "display:flex; justify-content:flex-end; gap:8px;" },
        cancelBtn,
        saveBtn,
      ),
    );

    function closeModal() {
      overlay.remove();
    }

    overlay.append(modal);
    document.body.append(overlay);
  }

  await loadPlugins();

  return el("div", { style: "display:flex; flex-direction:column; gap:12px;" },
    el("div", { class: "card" },
      el("h1", { class: "page-title", text: "Admin: Plugins" }),
      el("p", { class: "muted", text: "Enable integrations, set up automation, and manage plugin health checks." }),
    ),
    el("div", { class: "card" },
      el("div", { class: "row", style: "align-items:center; gap:8px; flex-wrap:wrap;" },
        el("div", { style: "font-weight:700;", text: "Configured plugins" }),
        el("div", { class: "muted", text: "Admin-only integrations" }),
        el("div", { class: "spacer" }),
        addBtn,
      ),
      list,
    ),
  );
}
