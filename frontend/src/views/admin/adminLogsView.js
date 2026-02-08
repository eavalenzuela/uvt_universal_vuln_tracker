import { el } from "../../ui/dom/el.js";
import { toast } from "../../ui/components/toast.js";
import { listAuditLogs } from "../../api/auditLogs.js";

function logCard(log) {
  const actor = log.user?.username || "Unknown";
  const timestamp = (log.created_at || "").replace("T", " ").slice(0, 19);
  const detail = [];
  if (log.new_values?.reason) detail.push(`Reason: ${log.new_values.reason}`);
  if (log.new_values?.impersonated) detail.push(`Impersonated: ${log.new_values.impersonated}`);
  if (log.old_values?.password_reset || log.action === "RESET_PASSWORD") detail.push("Password reset");
  if (log.action === "TOGGLE_ACTIVE") detail.push(`Active: ${log.new_values?.is_active}`);

  return el("div", { class: "card", style: "padding: 12px; display:flex; flex-direction:column; gap:6px;" },
    el("div", { class: "row", style: "align-items:center; gap:8px;" },
      el("div", { style: "font-weight:700;", text: log.action || "(unknown)" }),
      el("div", { class: "pill muted", text: log.table_name || "n/a" }),
      el("div", { class: "muted", text: timestamp || "" }),
      el("div", { class: "muted", text: `Actor: ${actor}` }),
    ),
    el("div", { class: "muted", text: `Record ID: ${log.record_id ?? "-"}` }),
    detail.length ? el("div", { text: detail.join(" • "), style: "font-weight:600;" }) : null,
    log.old_values ? el("pre", { style: "white-space: pre-wrap; background:#f8fafc; padding:8px; border-radius:6px;", text: JSON.stringify(log.old_values, null, 2) }) : null,
    log.new_values ? el("pre", { style: "white-space: pre-wrap; background:#f8fafc; padding:8px; border-radius:6px;", text: JSON.stringify(log.new_values, null, 2) }) : null,
  );
}

export async function AdminLogsView() {
  const limitInput = el("input", { class: "input", type: "number", min: 1, max: 500, value: 100 });
  const refreshBtn = el("button", { class: "btn" }, "Refresh logs");
  const list = el("div", { style: "display:flex; flex-direction:column; gap:8px;" });

  async function load() {
    list.innerHTML = "";
    list.appendChild(el("div", { class: "muted", text: "Loading audit logs..." }));
    try {
      const limit = Math.min(Math.max(parseInt(limitInput.value || "0", 10) || 100, 1), 500);
      const logs = await listAuditLogs({ limit });
      list.innerHTML = "";
      if (!logs?.length) {
        list.appendChild(el("div", { class: "muted", text: "No audit logs yet." }));
        return;
      }
      logs.forEach((log) => list.appendChild(logCard(log)));
    } catch (e) {
      list.innerHTML = "";
      toast({ title: "Failed to load logs", message: e?.message || "Unable to fetch audit logs" });
      list.appendChild(el("div", { class: "muted", text: "Unable to load audit logs." }));
    }
  }

  refreshBtn.addEventListener("click", load);
  await load();

  return el("div", { style: "display:flex; flex-direction:column; gap:12px;" },
    el("div", { class: "card" },
      el("h1", { class: "page-title", text: "Admin: Logs" }),
      el("p", { class: "muted", text: "Review sensitive admin actions including impersonation, access changes, and password resets." }),
    ),
    el("div", { class: "card" },
      el("div", { class: "row", style: "align-items:center; gap:8px; flex-wrap:wrap;" },
        el("div", { style: "font-weight:700;", text: "Audit log feed" }),
        el("div", { class: "muted", text: "Latest entries from audit_logs" }),
        el("div", { class: "spacer" }),
        el("label", { class: "muted", text: "Max rows" }),
        limitInput,
        refreshBtn,
      ),
      list,
    ),
  );
}
