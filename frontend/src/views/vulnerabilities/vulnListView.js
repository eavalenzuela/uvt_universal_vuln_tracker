import { el } from "../../ui/dom/el.js";

export async function VulnListView() {
  const vulns = [
    {
      id: "UVT-1024",
      title: "SQL injection in search endpoint",
      product: "Customer Portal",
      severity: "High",
      status: "Open",
      updated: "2024-05-12",
    },
    {
      id: "UVT-0999",
      title: "Outdated OpenSSL dependency",
      product: "Payment API",
      severity: "Critical",
      status: "In review",
      updated: "2024-05-08",
    },
    {
      id: "UVT-0875",
      title: "Verbose error messages leak stack traces",
      product: "Admin UI",
      severity: "Medium",
      status: "Triaged",
      updated: "2024-05-02",
    },
  ];

  const controls = el("div", { class: "row", style: "gap: 8px; align-items: center; margin: 12px 0; flex-wrap: wrap;" },
    el("input", { class: "input", type: "search", placeholder: "Search by title or ID" }),
    el("select", { class: "input" },
      el("option", { value: "", text: "Filter by status/severity" }),
      el("option", { value: "open", text: "Open" }),
      el("option", { value: "in-review", text: "In review" }),
      el("option", { value: "triaged", text: "Triaged" }),
      el("option", { value: "critical", text: "Critical" }),
      el("option", { value: "high", text: "High" }),
      el("option", { value: "medium", text: "Medium" }),
      el("option", { value: "low", text: "Low" }),
    ),
    el("button", { class: "btn primary" }, "Add vulnerability"),
  );

  const list = el("div", { style: "display: flex; flex-direction: column; gap: 12px; margin-top: 8px;" },
    vulns.map((vuln) => el("div", { class: "card", style: "padding: 12px;" },
      el("div", { class: "row", style: "align-items: center; gap: 12px;" },
        el("div", { style: "flex: 1;" },
          el("div", { class: "row", style: "justify-content: space-between; align-items: baseline; gap: 8px;" },
            el("div", {},
              el("div", { class: "muted", text: vuln.id }),
              el("div", { style: "font-weight: 600;" , text: vuln.title }),
            ),
            el("div", { class: "row", style: "gap: 6px;" },
              el("button", { class: "btn" }, "View"),
              el("button", { class: "btn" }, "Edit"),
            ),
          ),
          el("div", { class: "row", style: "gap: 12px; flex-wrap: wrap; margin-top: 6px;" },
            el("div", {}, el("div", { class: "muted", text: "Product" }), el("div", { text: vuln.product })),
            el("div", {}, el("div", { class: "muted", text: "Severity" }), el("div", { text: vuln.severity })),
            el("div", {}, el("div", { class: "muted", text: "Status" }), el("div", { text: vuln.status })),
            el("div", {}, el("div", { class: "muted", text: "Last updated" }), el("div", { text: vuln.updated })),
          ),
        ),
      ),
    )),
  );

  return el("div", { class: "card" },
    el("h1", { class: "page-title", text: "Vulnerabilities" }),
    el("p", { class: "muted", text: "Review, triage, and track vulnerability records." }),
    controls,
    list,
  );
}
