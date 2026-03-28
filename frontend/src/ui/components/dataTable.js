import { el } from "../dom/el.js";

/**
 * Reusable data table component with sortable columns, row striping,
 * sticky header, compact/comfortable density toggle, and loading/empty states.
 *
 * @param {object} options
 * @param {Array<{key: string, label: string, sortable?: boolean, render?: function, width?: string}>} options.columns
 * @param {Array<object>} options.rows - Data rows
 * @param {string} [options.emptyText] - Text when no rows
 * @param {boolean} [options.loading] - Show loading state
 * @param {string} [options.density] - "comfortable" (default) or "compact"
 * @param {string} [options.sortKey] - Currently sorted column key
 * @param {string} [options.sortDir] - "asc" or "desc"
 * @param {function} [options.onSort] - Called with (key, direction) when a sortable header is clicked
 * @param {function} [options.onRowClick] - Called with (row) when a row is clicked
 * @param {function} [options.rowActions] - Called with (row) to return action elements for last column
 * @returns {HTMLElement}
 */
export function createDataTable(options) {
  const {
    columns = [],
    rows = [],
    emptyText = "No data found.",
    loading = false,
    density = "comfortable",
    sortKey = null,
    sortDir = "asc",
    onSort = null,
    onRowClick = null,
    rowActions = null,
  } = options;

  const allColumns = rowActions
    ? [...columns, { key: "__actions", label: "Actions", sortable: false }]
    : columns;

  // Build header
  const headerCells = allColumns.map((col) => {
    const classes = [];
    if (col.sortable !== false && col.key !== "__actions") classes.push("sortable");
    if (sortKey === col.key) classes.push(sortDir === "asc" ? "sort-asc" : "sort-desc");

    const indicator = (col.sortable !== false && col.key !== "__actions")
      ? el("span", { class: "sort-indicator", text: sortKey === col.key ? (sortDir === "asc" ? "\u25B2" : "\u25BC") : "\u25B2" })
      : null;

    const th = el("th", {
      class: classes.join(" ") || undefined,
      style: col.width ? `width:${col.width}` : undefined,
    }, col.label, indicator);

    if (col.sortable !== false && col.key !== "__actions" && onSort) {
      th.addEventListener("click", () => {
        const newDir = sortKey === col.key && sortDir === "asc" ? "desc" : "asc";
        onSort(col.key, newDir);
      });
    }

    return th;
  });

  const thead = el("thead", {}, el("tr", {}, ...headerCells));

  // Build body
  const tbody = el("tbody", {});

  if (loading) {
    const loadingRow = el("tr", {},
      el("td", { colSpan: String(allColumns.length), class: "data-table-empty" },
        el("div", { class: "loading-block" },
          el("div", { class: "loading-spinner-sm" }),
          "Loading...",
        ),
      ),
    );
    tbody.appendChild(loadingRow);
  } else if (!rows.length) {
    tbody.appendChild(
      el("tr", {},
        el("td", { colSpan: String(allColumns.length), class: "data-table-empty" }, emptyText),
      ),
    );
  } else {
    rows.forEach((row) => {
      const cells = allColumns.map((col) => {
        if (col.key === "__actions") {
          return el("td", {}, rowActions(row));
        }
        if (col.render) {
          const content = col.render(row);
          if (typeof content === "string" || typeof content === "number") {
            return el("td", { text: String(content) });
          }
          return el("td", {}, content);
        }
        const value = row[col.key];
        return el("td", { text: value != null ? String(value) : "\u2014" });
      });

      const tr = el("tr", {}, ...cells);
      if (onRowClick) {
        tr.style.cursor = "pointer";
        tr.addEventListener("click", (e) => {
          // Don't trigger row click when clicking buttons/links inside
          if (e.target.closest("button, a, input, select")) return;
          onRowClick(row);
        });
      }
      tbody.appendChild(tr);
    });
  }

  const tableClasses = ["data-table"];
  if (density === "compact") tableClasses.push("compact");

  const table = el("table", { class: tableClasses.join(" ") }, thead, tbody);
  return el("div", { class: "data-table-wrap" }, table);
}

/**
 * Creates a density toggle (comfortable / compact) button group.
 *
 * @param {string} current - "comfortable" or "compact"
 * @param {function} onChange - Called with new density value
 * @returns {HTMLElement}
 */
export function createDensityToggle(current, onChange) {
  const comfortBtn = el("button", {
    class: current === "comfortable" ? "active" : undefined,
    text: "Comfortable",
    onclick: () => onChange("comfortable"),
  });
  const compactBtn = el("button", {
    class: current === "compact" ? "active" : undefined,
    text: "Compact",
    onclick: () => onChange("compact"),
  });
  return el("div", { class: "density-toggle" }, comfortBtn, compactBtn);
}

/**
 * Creates a pagination bar for use with DataTable.
 *
 * @param {object} options
 * @param {number} options.page - Current page (1-based)
 * @param {number} options.totalPages - Total number of pages
 * @param {number} options.total - Total number of items
 * @param {function} options.onPage - Called with new page number
 * @returns {HTMLElement}
 */
export function createTablePagination({ page, totalPages, total, onPage }) {
  const pageInfo = el("div", { class: "muted", text: `Page ${page} of ${totalPages} \u2022 ${total} total` });
  const prevBtn = el("button", {
    class: "btn",
    disabled: page <= 1,
    onclick: () => onPage(page - 1),
  }, "Previous");
  const nextBtn = el("button", {
    class: "btn",
    disabled: page >= totalPages,
    onclick: () => onPage(page + 1),
  }, "Next");

  return el("div", { class: "row gap-8 mt-12" }, pageInfo, el("div", { class: "spacer" }), prevBtn, nextBtn);
}
