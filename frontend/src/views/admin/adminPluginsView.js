import { el } from "../../ui/dom/el.js";
import { toast } from "../../ui/components/toast.js";

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
  const healthColor = plugin.health === "Healthy" ? "#059669" : "#d97706";

  const toggleBtn = el("button", { class: "btn" }, plugin.enabled ? "Disable" : "Enable");
  toggleBtn.addEventListener("click", () => onToggle(plugin));

  const configBtn = el("button", { class: "btn" }, "Configure");
  configBtn.addEventListener("click", () => onConfigure(plugin));

  return el("div", { class: "card", style: "padding: 12px; display:flex; flex-direction:column; gap:10px;" },
    el("div", { class: "row", style: "align-items:flex-start; gap:12px; flex-wrap:wrap;" },
      el("div", { style: "flex:1; min-width: 220px;" },
        el("div", { class: "row", style: "align-items:center; gap:8px; flex-wrap:wrap;" },
          el("div", { style: "font-weight:700;", text: plugin.name }),
          pill(statusLabel, statusColor, true),
          pill(plugin.health, healthColor, true),
        ),
        el("div", { class: "muted", style: "margin-top: 4px;", text: plugin.description }),
        el("div", { class: "row", style: "gap: 8px; margin-top: 8px; flex-wrap:wrap;" },
          el("div", { class: "muted", text: `Version ${plugin.version}` }),
          el("div", { class: "muted", text: `Category: ${plugin.category}` }),
          plugin.lastSync ? el("div", { class: "muted", text: `Last sync: ${plugin.lastSync}` }) : null,
        ),
      ),
      el("div", { class: "row", style: "gap: 6px; flex-wrap:wrap;" },
        configBtn,
        toggleBtn,
      ),
    ),
    plugin.scopes?.length
      ? el("div", { class: "row", style: "gap: 6px; flex-wrap:wrap;" },
        el("div", { class: "muted", text: "Scopes:" }),
        ...plugin.scopes.map((scope) => pill(scope, "#2563eb", true)),
      )
      : null,
    plugin.notes ? el("div", { class: "muted", text: plugin.notes }) : null,
  );
}

export async function AdminPluginsView() {
  const plugins = [
    {
      id: "slack",
      name: "Slack Alerts",
      description: "Route high severity vulnerability alerts into Slack channels.",
      enabled: true,
      version: "1.4.2",
      category: "Notifications",
      health: "Healthy",
      lastSync: "Today at 09:42",
      scopes: ["Alerts", "Incidents"],
      notes: "Default channel: #security-triage",
    },
    {
      id: "jira",
      name: "Jira Sync",
      description: "Create Jira issues automatically for confirmed vulnerabilities.",
      enabled: false,
      version: "2.1.0",
      category: "Ticketing",
      health: "Needs setup",
      lastSync: "Never",
      scopes: ["Cases", "Assignments"],
      notes: "Project: UVT · Issue type: Bug",
    },
    {
      id: "snyk",
      name: "Snyk Import",
      description: "Import SBOM findings from Snyk to enrich vulnerability context.",
      enabled: true,
      version: "0.9.7",
      category: "Integrations",
      health: "Healthy",
      lastSync: "Yesterday at 16:10",
      scopes: ["SBOM", "Advisories"],
      notes: "Sync interval: Every 6 hours",
    },
  ];

  const list = el("div", { style: "display:flex; flex-direction:column; gap:10px;" });
  const addBtn = el("button", { class: "btn primary" }, "Add plugin");

  function renderList() {
    list.innerHTML = "";
    plugins.forEach((plugin) => {
      list.appendChild(pluginCard(plugin, {
        onToggle: (target) => {
          target.enabled = !target.enabled;
          toast({
            title: target.enabled ? "Plugin enabled" : "Plugin disabled",
            message: `${target.name} is now ${target.enabled ? "active" : "inactive"}.`,
          });
          renderList();
        },
        onConfigure: (target) => {
          const nextNotes = window.prompt(`Update notes for ${target.name}`, target.notes || "") ?? target.notes;
          if (nextNotes !== null) {
            target.notes = nextNotes;
            toast({ title: "Settings saved", message: `${target.name} configuration updated.` });
            renderList();
          }
        },
      }));
    });
  }

  addBtn.addEventListener("click", () => {
    toast({ title: "Coming soon", message: "Plugin marketplace access is not configured yet." });
  });

  renderList();

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
