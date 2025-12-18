import { el } from "../../ui/dom/el.js";
import { toast } from "../../ui/components/toast.js";
import { listVulnerabilities } from "../../api/vulnerabilities.js";

function renderRow(vuln) {
  return el("div", { class: "card", style: "padding: 12px;" },
    el("div", { class: "row", style: "align-items: center; gap: 12px;" },
      el("div", { style: "flex: 1;" },
        el("div", { class: "row", style: "justify-content: space-between; align-items: baseline; gap: 8px;" },
          el("div", {},
            el("div", { class: "muted", text: vuln.cve_id || `VULN-${vuln.id}` }),
            el("div", { style: "font-weight: 600;", text: vuln.title }),
          ),
          el("div", { class: "row", style: "gap: 6px;" },
            el("button", { class: "btn" }, "View"),
            el("button", { class: "btn" }, "Edit"),
          ),
        ),
        el("div", { class: "row", style: "gap: 12px; flex-wrap: wrap; margin-top: 6px;" },
          el("div", {}, el("div", { class: "muted", text: "Severity" }), el("div", { text: vuln.severity || "-" })),
          el("div", {}, el("div", { class: "muted", text: "Status" }), el("div", { text: vuln.status || "-" })),
          el("div", {}, el("div", { class: "muted", text: "Last updated" }), el("div", { text: vuln.updated_at ? vuln.updated_at.slice(0, 10) : "-" })),
        ),
      ),
    ),
  );
}

export async function VulnListView() {
  const searchInput = el("input", { class: "input", type: "search", placeholder: "Search by title or CVE" });
  const statusSelect = el("select", { class: "input" },
    el("option", { value: "", text: "Status" }),
    el("option", { value: "Open", text: "Open" }),
    el("option", { value: "In Review", text: "In review" }),
    el("option", { value: "Triaged", text: "Triaged" }),
    el("option", { value: "Resolved", text: "Resolved" }),
    el("option", { value: "Closed", text: "Closed" }),
  );
  const severitySelect = el("select", { class: "input" },
    el("option", { value: "", text: "Severity" }),
    el("option", { value: "Critical", text: "Critical" }),
    el("option", { value: "High", text: "High" }),
    el("option", { value: "Medium", text: "Medium" }),
    el("option", { value: "Low", text: "Low" }),
  );

  const list = el("div", { style: "display: flex; flex-direction: column; gap: 12px; margin-top: 8px;" });
  const loading = el("div", { class: "muted", text: "Loading vulnerabilities..." });
  list.appendChild(loading);

  async function load() {
    list.innerHTML = "";
    list.appendChild(el("div", { class: "muted", text: "Loading vulnerabilities..." }));
    try {
      const data = await listVulnerabilities({
        search: searchInput.value.trim() || undefined,
        status: statusSelect.value || undefined,
        severity: severitySelect.value || undefined,
      });

      list.innerHTML = "";
      if (!data?.items?.length) {
        list.appendChild(el("div", { class: "muted", text: "No vulnerabilities found." }));
        return;
      }

      data.items.forEach((v) => list.appendChild(renderRow(v)));
    } catch (e) {
      list.innerHTML = "";
      toast({ title: "Failed to load", message: e?.message || "Unable to fetch vulnerabilities" });
      list.appendChild(el("div", { class: "muted", text: "Unable to load vulnerabilities." }));
    }
  }

  const applyBtn = el("button", { class: "btn" }, "Apply filters");
  applyBtn.addEventListener("click", load);

  const controls = el("div", { class: "row", style: "gap: 8px; align-items: center; margin: 12px 0; flex-wrap: wrap;" },
    searchInput,
    statusSelect,
    severitySelect,
    applyBtn,
    el("div", { class: "spacer" }),
    el("button", { class: "btn primary" }, "Add vulnerability"),
  );

  // initial fetch
  load();

  return el("div", { class: "card" },
    el("h1", { class: "page-title", text: "Vulnerabilities" }),
    el("p", { class: "muted", text: "Review, triage, and track vulnerability records." }),
    controls,
    list,
  );
}
