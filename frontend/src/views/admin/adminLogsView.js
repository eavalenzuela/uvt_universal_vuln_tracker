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

  return el("div", { class: "card p-12 flex-col-6" },
    el("div", { class: "row items-center gap-8" },
      el("div", { class: "font-bold", text: log.action || "(unknown)" }),
      el("div", { class: "pill muted", text: log.table_name || "n/a" }),
      el("div", { class: "muted", text: timestamp || "" }),
      el("div", { class: "muted", text: `Actor: ${actor}` }),
    ),
    el("div", { class: "muted", text: `Record ID: ${log.record_id ?? "-"}` }),
    detail.length ? el("div", { text: detail.join(" • "), class: "font-semibold" }) : null,
    log.old_values ? el("pre", { class: "text-pre-wrap code-block", text: JSON.stringify(log.old_values, null, 2) }) : null,
    log.new_values ? el("pre", { class: "text-pre-wrap code-block", text: JSON.stringify(log.new_values, null, 2) }) : null,
  );
}

export async function AdminLogsView() {
  const pageSizeInput = el("input", { class: "input", type: "number", min: 1, max: 500, value: 100, "aria-label": "Page size" });
  const actionInput = el("input", { class: "input", placeholder: "Action (optional)", "aria-label": "Filter by action" });
  const tableInput = el("input", { class: "input", placeholder: "Table (optional)", "aria-label": "Filter by table" });
  const refreshBtn = el("button", { class: "btn" }, "Refresh logs");
  const list = el("div", { class: "flex-col-8" });
  const pageInfo = el("div", { class: "muted", text: "Page 1" });
  const prevBtn = el("button", { class: "btn" }, "Previous");
  const nextBtn = el("button", { class: "btn" }, "Next");

  let currentPage = 1;
  let lastTotal = 0;

  async function load() {
    list.innerHTML = "";
    list.appendChild(el("div", { class: "muted", text: "Loading audit logs..." }));
    try {
      const pageSize = Math.min(Math.max(parseInt(pageSizeInput.value || "0", 10) || 100, 1), 500);
      const res = await listAuditLogs({
        page: currentPage,
        page_size: pageSize,
        action: actionInput.value.trim() || undefined,
        table: tableInput.value.trim() || undefined,
      });

      const items = res?.items || [];
      const total = res?.total || 0;
      const page = res?.page || currentPage;
      const effectiveSize = res?.page_size || pageSize;
      const totalPages = Math.max(1, Math.ceil(total / effectiveSize));

      list.innerHTML = "";
      if (!items.length) {
        list.appendChild(el("div", { class: "muted", text: "No audit logs yet." }));
      } else {
        items.forEach((log) => list.appendChild(logCard(log)));
      }

      lastTotal = total;
      currentPage = page;
      pageInfo.textContent = `Page ${page} of ${totalPages} • ${total} total`;
      prevBtn.disabled = page <= 1;
      nextBtn.disabled = page >= totalPages;
    } catch (e) {
      list.innerHTML = "";
      toast({ title: "Failed to load logs", message: e?.message || "Unable to fetch audit logs" });
      list.appendChild(el("div", { class: "muted", text: "Unable to load audit logs." }));
    }
  }

  refreshBtn.addEventListener("click", () => {
    currentPage = 1;
    load();
  });
  prevBtn.addEventListener("click", () => {
    if (currentPage > 1) {
      currentPage -= 1;
      load();
    }
  });
  nextBtn.addEventListener("click", () => {
    const pageSize = Math.min(Math.max(parseInt(pageSizeInput.value || "0", 10) || 100, 1), 500);
    const totalPages = Math.max(1, Math.ceil(lastTotal / pageSize));
    if (currentPage < totalPages) {
      currentPage += 1;
      load();
    }
  });

  await load();

  return el("div", { class: "flex-col-12" },
    el("div", { class: "card" },
      el("h1", { class: "page-title", text: "Admin: Logs" }),
      el("p", { class: "muted", text: "Review sensitive admin actions including impersonation, access changes, and password resets." }),
    ),
    el("div", { class: "card" },
      el("div", { class: "row items-center gap-8 flex-wrap" },
        el("div", { class: "font-bold", text: "Audit log feed" }),
        el("div", { class: "muted", text: "Latest entries from audit_logs" }),
        el("div", { class: "spacer" }),
        actionInput,
        tableInput,
        el("label", { class: "muted", text: "Rows/page" }),
        pageSizeInput,
        refreshBtn,
      ),
      list,
      el("div", { class: "row gap-8 items-center mt-12" },
        pageInfo,
        el("div", { class: "spacer" }),
        prevBtn,
        nextBtn,
      ),
    ),
  );
}
