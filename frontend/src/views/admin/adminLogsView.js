import { el } from "../../ui/dom/el.js";
import { toast } from "../../ui/components/toast.js";
import { listAuditLogs } from "../../api/auditLogs.js";
import { createDataTable, createDensityToggle, createTablePagination } from "../../ui/components/dataTable.js";

export async function AdminLogsView() {
  const pageSizeInput = el("input", { class: "input", type: "number", min: 1, max: 500, value: 100, "aria-label": "Page size" });
  const actionInput = el("input", { class: "input", placeholder: "Action (optional)", "aria-label": "Filter by action" });
  const tableInput = el("input", { class: "input", placeholder: "Table (optional)", "aria-label": "Filter by table" });
  const refreshBtn = el("button", { class: "btn" }, "Refresh logs");
  const tableContainer = el("div", { class: "flex-col-8" });
  const paginationContainer = el("div");

  let currentPage = 1;
  let lastTotal = 0;
  let density = "comfortable";

  const columns = [
    {
      key: "action",
      label: "Action",
      render: (log) => el("span", { class: "font-bold", text: log.action || "(unknown)" }),
    },
    {
      key: "table_name",
      label: "Table",
      render: (log) => log.table_name || "n/a",
    },
    {
      key: "record_id",
      label: "Record ID",
      render: (log) => String(log.record_id ?? "-"),
    },
    {
      key: "actor",
      label: "Actor",
      render: (log) => log.user?.username || "Unknown",
    },
    {
      key: "created_at",
      label: "Timestamp",
      render: (log) => (log.created_at || "").replace("T", " ").slice(0, 19),
    },
    {
      key: "details",
      label: "Details",
      sortable: false,
      render: (log) => {
        const detail = [];
        if (log.new_values?.reason) detail.push(`Reason: ${log.new_values.reason}`);
        if (log.new_values?.impersonated) detail.push(`Impersonated: ${log.new_values.impersonated}`);
        if (log.old_values?.password_reset || log.action === "RESET_PASSWORD") detail.push("Password reset");
        if (log.action === "TOGGLE_ACTIVE") detail.push(`Active: ${log.new_values?.is_active}`);
        if (!detail.length) return "\u2014";
        return el("span", { class: "font-semibold", text: detail.join(" \u2022 ") });
      },
    },
  ];

  const densityToggle = createDensityToggle(density, (newDensity) => {
    density = newDensity;
    load();
  });

  async function load() {
    tableContainer.innerHTML = "";
    tableContainer.appendChild(
      createDataTable({ columns, rows: [], loading: true, density }),
    );
    paginationContainer.innerHTML = "";

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

      lastTotal = total;
      currentPage = page;

      tableContainer.innerHTML = "";
      tableContainer.appendChild(
        createDataTable({
          columns,
          rows: items,
          emptyText: "No audit logs yet.",
          density,
        }),
      );

      paginationContainer.innerHTML = "";
      paginationContainer.appendChild(
        createTablePagination({
          page,
          totalPages,
          total,
          onPage: (newPage) => {
            currentPage = newPage;
            load();
          },
        }),
      );
    } catch (e) {
      tableContainer.innerHTML = "";
      toast({ title: "Failed to load logs", message: e?.message || "Unable to fetch audit logs" });
      tableContainer.appendChild(el("div", { class: "muted", text: "Unable to load audit logs." }));
    }
  }

  refreshBtn.addEventListener("click", () => {
    currentPage = 1;
    load();
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
        densityToggle,
        refreshBtn,
      ),
      tableContainer,
      paginationContainer,
    ),
  );
}
