import { el } from "../../ui/dom/el.js";
import { toast } from "../../ui/components/toast.js";
import { navigate } from "../../router/router.js";
import { getVulnerability, listVulnerabilityActivity } from "../../api/vulnerabilities.js";

function formatDate(value) {
  return value ? value.slice(0, 10) : "-";
}

function formatDateTime(value) {
  if (!value) return "-";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "-" : date.toLocaleString();
}

function field(label, value) {
  return el("div", {}, el("div", { class: "muted", text: label }), el("div", { text: value ?? "-" }));
}

function renderList(title, items, renderItem) {
  return el(
    "div",
    { class: "card", style: "margin-top: 12px;" },
    el("h3", { style: "margin-top: 0;", text: title }),
    !items?.length
      ? el("div", { class: "muted", text: "None" })
      : el("div", { style: "display:flex; flex-direction:column; gap:8px;" }, ...items.map(renderItem)),
  );
}

function renderActivityItem(item) {
  const actor = item?.user?.username || "system";
  const summary = `${item.action} • ${item.table_name}`;
  const delta = item.new_values || item.old_values
    ? JSON.stringify({ old: item.old_values || null, new: item.new_values || null })
    : "No field data";

  return el(
    "div",
    { style: "padding:10px; border:1px solid #e2e8f0; border-radius:10px;" },
    el("div", { style: "font-weight:600;", text: summary }),
    el("div", { class: "muted", text: `${formatDateTime(item.created_at)} by ${actor}` }),
    el("pre", { style: "white-space:pre-wrap; margin:8px 0 0; background:#f8fafc; padding:8px; border-radius:8px;" }, delta),
  );
}

export async function VulnDetailView(params = {}) {
  const vulnId = Number(params?.id);
  if (!Number.isFinite(vulnId) || vulnId <= 0) {
    return el("div", { class: "card" }, el("h1", { class: "page-title", text: "Vulnerability detail" }), el("p", { text: "Invalid vulnerability id." }));
  }

  const container = el("div", { class: "card" }, el("h1", { class: "page-title", text: "Vulnerability detail" }), el("p", { class: "muted", text: "Loading vulnerability..." }));

  try {
    const [vuln, activity] = await Promise.all([
      getVulnerability(vulnId),
      listVulnerabilityActivity(vulnId).catch(() => []),
    ]);

    container.innerHTML = "";
    container.append(
      el(
        "div",
        { class: "row", style: "justify-content:space-between; align-items:center; margin-bottom:8px;" },
        el("h1", { class: "page-title", text: vuln.title || `Vulnerability ${vuln.id}` }),
        el("button", { class: "btn", onClick: () => navigate("/vulnerabilities") }, "Back to list"),
      ),
      vuln.cve_id ? el("p", { class: "muted", text: vuln.cve_id }) : null,
      el("p", { text: vuln.description || "No description provided." }),
      el(
        "div",
        { class: "card", style: "padding:10px;" },
        el("h3", { style: "margin-top:0;", text: "Core fields" }),
        el(
          "div",
          { class: "row", style: "gap:12px; flex-wrap:wrap;" },
          field("Severity", vuln.severity),
          field("Status", vuln.status),
          field("SLA state", vuln.sla_state),
          field("SLA due", formatDateTime(vuln.sla_due_at)),
          field("CVSS", vuln.cvss_score ?? "-"),
          field("Attack complexity", vuln.attack_complexity),
          field("Confidentiality impact", vuln.confidentiality_impact),
          field("Integrity impact", vuln.integrity_impact),
          field("Availability impact", vuln.availability_impact),
          field("Published", formatDate(vuln.published_date)),
          field("Last modified", formatDate(vuln.last_modified_date)),
          field("Assigned to", vuln.assigned_to ?? "Unassigned"),
          field("Created by", vuln.created_by ?? "-"),
        ),
      ),
      renderList("Linked product versions", vuln.affected_versions, (item) =>
        el("div", { style: "padding:10px; border:1px solid #e2e8f0; border-radius:10px;" },
          el("div", { style: "font-weight:600;", text: `${item.product_name || "Product"} ${item.version || ""}` }),
          el("div", { class: "muted", text: `Affected: ${item.affected ? "Yes" : "No"} • Mitigation: ${item.mitigation_status || "-"}` }),
          item.fixed_in_version ? el("div", { text: `Fixed in: ${item.fixed_in_version}` }) : null,
          item.notes ? el("div", { class: "muted", text: item.notes }) : null,
        )
      ),
      renderList("Attack vectors", vuln.attack_vectors, (item) =>
        el("div", { style: "padding:10px; border:1px solid #e2e8f0; border-radius:10px;" },
          el("div", { style: "font-weight:600;", text: item.attack_vector_name || "Unnamed vector" }),
          item.product_name ? el("div", { class: "muted", text: `${item.product_name} ${item.version || ""}` }) : null,
          item.attack_vector_description ? el("div", { class: "muted", text: item.attack_vector_description }) : null,
        )
      ),
      renderList("Terminal impacts", vuln.terminal_impacts, (item) =>
        el("div", { style: "padding:10px; border:1px solid #e2e8f0; border-radius:10px;" },
          el("div", { style: "font-weight:600;", text: item.terminal_impact_name || "Unnamed impact" }),
          item.terminal_impact_description ? el("div", { class: "muted", text: item.terminal_impact_description }) : null,
        )
      ),
      renderList("Activity timeline", activity, renderActivityItem),
    );
  } catch (err) {
    toast({ title: "Failed to load vulnerability", message: err?.message || "Unable to fetch vulnerability detail" });
    container.innerHTML = "";
    container.append(
      el("h1", { class: "page-title", text: "Vulnerability detail" }),
      el("p", { class: "muted", text: "Unable to load this vulnerability." }),
      el("button", { class: "btn", onClick: () => navigate("/vulnerabilities") }, "Back to list"),
    );
  }

  return container;
}
