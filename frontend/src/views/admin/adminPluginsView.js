import {
  listPluginImportSources,
  listPlugins,
  registerPluginImport,
  updatePluginConfig,
  validatePluginImport,
} from "../../api/plugins.js";
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

  return el("div", { class: "card flex-col-10 p-12" },
    el("div", { class: "row items-start gap-12 flex-wrap" },
      el("div", { class: "flex-1", style: "min-width: 220px;" },
        el("div", { class: "row flex-wrap gap-8" },
          el("div", { class: "font-bold", text: plugin.display_name || plugin.plugin_id }),
          pill(statusLabel, statusColor, true),
          pill(healthState, healthStateColor, true),
        ),
        el("div", { class: "row gap-8 mt-8 flex-wrap" },
          plugin.version ? el("div", { class: "muted", text: `Version ${plugin.version}` }) : null,
          el("div", { class: "muted", text: `ID: ${plugin.plugin_id}` }),
          el("div", { class: "muted", text: formatLastRun(plugin.last_run) }),
        ),
      ),
      el("div", { class: "row gap-6 flex-wrap" },
        configBtn,
        toggleBtn,
      ),
    ),
    plugin.capabilities?.length
      ? el("div", { class: "row gap-6 flex-wrap" },
        el("div", { class: "muted", text: "Capabilities:" }),
        ...plugin.capabilities.map((scope) => pill(scope, "#2563eb", true)),
      )
      : null,
    configFields.length
      ? el("div", { class: "flex-col-6" },
        el("div", { class: "muted", text: "Configuration:" }),
        ...configFields.map((field) => el("div", { class: "row gap-8 flex-wrap" },
          el("div", { class: "font-semibold", style: "min-width: 140px;", text: field.label }),
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

  const list = el("div", { class: "flex-col-10" });
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

  addBtn.addEventListener("click", () => openImportWizard());

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

  function openImportWizard() {
    const overlay = el("div", {
      class: "modal-backdrop",
      onClick: (event) => {
        if (event.target === overlay) closeModal();
      },
    });

    const modal = el("div", {
      class: "modal-panel modal-lg",
      role: "dialog",
      "aria-modal": "true",
      "aria-label": "Import plugin",
    });

    const title = el("h2", { text: "Import plugin" });
    const stepHint = el("div", { class: "muted", text: "Step 1 of 3 · Select plugin source/type" });
    const body = el("div", { class: "flex-col-10" });
    const statusRow = el("div", { class: "muted" });

    const sourceSelect = el("select", { class: "input" });
    const moduleInput = el("input", { class: "input", placeholder: "backend.plugins.my_plugin" });
    const classInput = el("input", { class: "input", placeholder: "MyPluginClass" });
    const enabledInput = el("input", { type: "checkbox", checked: true });

    let currentStep = 1;
    let importSources = [];
    let introspection = null;
    let configInputs = new Map();

    const nextBtn = el("button", { class: "btn primary", text: "Validate" });
    const backBtn = el("button", { class: "btn", text: "Back" });
    const cancelBtn = el("button", { class: "btn", text: "Cancel", onClick: closeModal });

    function setButtonsLoading(loading) {
      nextBtn.disabled = loading;
      backBtn.disabled = loading;
      cancelBtn.disabled = loading;
    }

    function renderStep() {
      body.innerHTML = "";
      configInputs = new Map();
      if (currentStep === 1) {
        stepHint.textContent = "Step 1 of 3 · Select plugin source/type";
        nextBtn.textContent = "Validate";
        backBtn.style.display = "none";
        body.append(
          el("div", { class: "muted", text: "Choose an allowed import path and provide the module/class for the plugin." }),
          el("div", { class: "flex-col-6" },
            el("label", { text: "Plugin source root" }),
            sourceSelect,
          ),
          el("div", { class: "flex-col-6" },
            el("label", { text: "Module path" }),
            moduleInput,
          ),
          el("div", { class: "flex-col-6" },
            el("label", { text: "Class name" }),
            classInput,
          ),
        );
      } else if (currentStep === 2) {
        stepHint.textContent = "Step 2 of 3 · Validate schema/capabilities";
        nextBtn.textContent = "Continue";
        backBtn.style.display = "";
        body.append(
          el("div", { class: "muted", text: introspection?.already_registered ? "Plugin already registered. Continuing will update initial config." : "Plugin validated and ready to import." }),
          el("div", { class: "row gap-8 flex-wrap" },
            pill(introspection.plugin_id, "#1d4ed8", true),
            pill(introspection.version || "0.0.0", "#475569", true),
            ...(introspection.capabilities || []).map((cap) => pill(cap, "#2563eb", true)),
          ),
          el("div", { class: "muted", text: `Name: ${introspection.display_name || introspection.plugin_id}` }),
          el("div", { class: "muted", text: `Schema fields: ${normalizeFields(introspection.config_schema).map((f) => f.name).join(", ") || "none"}` }),
        );
      } else {
        stepHint.textContent = "Step 3 of 3 · Save initial config and enable state";
        nextBtn.textContent = "Import plugin";
        backBtn.style.display = "";

        const fields = normalizeFields(introspection?.config_schema);
        body.append(el("label", { class: "label-row" },
          enabledInput,
          el("span", { text: "Enable plugin after import" }),
        ));

        if (!fields.length) {
          body.appendChild(el("div", { class: "muted", text: "No configurable fields exposed." }));
        } else {
          fields.forEach((field) => {
            if (field.type === "boolean") {
              const checkbox = el("input", { type: "checkbox", checked: Boolean(field.defaultValue) });
              configInputs.set(field.name, { type: "boolean", input: checkbox, required: field.required });
              body.append(el("label", { class: "label-row" },
                checkbox,
                el("span", { text: `${field.label}${field.required ? " *" : ""}` }),
              ));
              return;
            }
            const input = el("input", {
              class: "input",
              type: field.secret ? "password" : "text",
              value: field.defaultValue ?? "",
              placeholder: field.required ? "Required" : "Optional",
            });
            configInputs.set(field.name, { type: "string", input, required: field.required });
            body.append(el("div", { class: "flex-col-6" },
              el("label", { text: `${field.label}${field.required ? " *" : ""}` }),
              input,
            ));
          });
        }
      }
    }

    async function initializeSources() {
      try {
        const payload = await listPluginImportSources();
        importSources = payload?.paths || [];
        sourceSelect.innerHTML = "";
        importSources.forEach((source) => {
          sourceSelect.appendChild(el("option", { value: source, text: source }));
        });
        if (importSources.length) {
          moduleInput.value = importSources[0];
        }
      } catch (error) {
        statusRow.textContent = error?.message || "Unable to load import paths.";
      }
    }

    sourceSelect.addEventListener("change", () => {
      if (!moduleInput.value.trim()) {
        moduleInput.value = sourceSelect.value;
      }
    });

    backBtn.addEventListener("click", () => {
      if (currentStep <= 1) return;
      currentStep -= 1;
      statusRow.textContent = "";
      renderStep();
    });

    nextBtn.addEventListener("click", async () => {
      statusRow.textContent = "";
      if (currentStep === 1) {
        const modulePath = moduleInput.value.trim();
        const className = classInput.value.trim();
        if (!modulePath || !className) {
          statusRow.textContent = "Module path and class name are required.";
          return;
        }
        setButtonsLoading(true);
        try {
          introspection = await validatePluginImport({ module_path: modulePath, class_name: className });
          currentStep = 2;
          renderStep();
          statusRow.textContent = "Validation successful.";
        } catch (error) {
          statusRow.textContent = error?.message || "Validation failed.";
        } finally {
          setButtonsLoading(false);
        }
        return;
      }

      if (currentStep === 2) {
        currentStep = 3;
        renderStep();
        return;
      }

      const config = {};
      for (const [name, entry] of configInputs.entries()) {
        if (entry.type === "boolean") {
          config[name] = entry.input.checked;
          continue;
        }
        const value = entry.input.value;
        if (entry.required && !String(value || "").trim()) {
          statusRow.textContent = `Required field missing: ${name}`;
          return;
        }
        config[name] = value;
      }

      setButtonsLoading(true);
      statusRow.textContent = "Importing plugin...";
      try {
        const result = await registerPluginImport({
          module_path: moduleInput.value.trim(),
          class_name: classInput.value.trim(),
          config,
          enabled: enabledInput.checked,
        });
        await loadPlugins();
        toast({
          title: "Plugin imported",
          message: result?.message || "Plugin registration completed.",
        });
        closeModal();
      } catch (error) {
        statusRow.textContent = error?.message || "Import failed.";
      } finally {
        setButtonsLoading(false);
      }
    });

    modal.append(
      title,
      stepHint,
      body,
      statusRow,
      el("div", { class: "flex-end gap-8" },
        backBtn,
        cancelBtn,
        nextBtn,
      ),
    );

    function closeModal() {
      overlay.remove();
    }

    overlay.append(modal);
    document.body.append(overlay);
    renderStep();
    initializeSources();
  }

  function openConfigModal(plugin) {
    const fields = normalizeFields(plugin.config_schema);
    const overlay = el("div", {
      class: "modal-backdrop",
      onClick: (event) => {
        if (event.target === overlay) closeModal();
      },
    });

    const modal = el(
      "div",
      {
        class: "modal-panel modal-md",
        role: "dialog",
        "aria-modal": "true",
        "aria-label": `Configure ${plugin.display_name || plugin.plugin_id}`,
      },
      el("h2", { text: `Configure ${plugin.display_name || plugin.plugin_id}` }),
    );

    const fieldInputs = new Map();
    const form = el("div", { class: "flex-col-12" });

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
          form.appendChild(el("label", { class: "label-row" },
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
        form.appendChild(el("div", { class: "flex-col-6" },
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
      el("div", { class: "flex-end gap-8" },
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

  return el("div", { class: "flex-col-12" },
    el("div", { class: "card" },
      el("h1", { class: "page-title", text: "Admin: Plugins" }),
      el("p", { class: "muted", text: "Enable integrations, set up automation, and manage plugin health checks." }),
    ),
    el("div", { class: "card" },
      el("div", { class: "row flex-wrap gap-8" },
        el("div", { class: "font-bold", text: "Configured plugins" }),
        el("div", { class: "muted", text: "Admin-only integrations" }),
        el("div", { class: "spacer" }),
        addBtn,
      ),
      list,
    ),
  );
}
