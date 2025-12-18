import { el } from "../../ui/dom/el.js";

export async function ProductsView() {
  const products = [
    {
      name: "Customer Portal",
      vendor: "Acme Corp",
      lifecycle: "Active",
      owners: "Customer Experience",
      latestRelease: "2024-05-10",
      versions: ["3.4.1", "3.3.0", "3.2.5"],
      notes: "Primary external-facing application.",
    },
    {
      name: "Payment API",
      vendor: "Acme Corp",
      lifecycle: "Maintenance",
      owners: "Payments Platform",
      latestRelease: "2024-04-22",
      versions: ["2.3.2", "2.2.9", "2.1.7"],
      notes: "Handles checkout flows and billing integrations.",
    },
    {
      name: "Admin UI",
      vendor: "Acme Corp",
      lifecycle: "Active",
      owners: "Internal Tools",
      latestRelease: "2024-04-30",
      versions: ["1.9.0", "1.8.4", "1.7.9"],
      notes: "Internal console used by operations and security teams.",
    },
  ];

  const controls = el(
    "div",
    { class: "row", style: "gap: 8px; align-items: center; margin: 12px 0; flex-wrap: wrap;" },
    el("input", { class: "input", type: "search", placeholder: "Search by name or owner" }),
    el(
      "select",
      { class: "input" },
      el("option", { value: "", text: "Filter by lifecycle" }),
      el("option", { value: "active", text: "Active" }),
      el("option", { value: "maintenance", text: "Maintenance" }),
      el("option", { value: "retired", text: "Retired" }),
    ),
    el("button", { class: "btn primary" }, "Add product"),
  );

  const list = el(
    "div",
    { style: "display: flex; flex-direction: column; gap: 12px; margin-top: 8px;" },
    products.map((product) =>
      el(
        "div",
        { class: "card", style: "padding: 12px;" },
        el(
          "div",
          { class: "row", style: "justify-content: space-between; align-items: baseline; gap: 8px;" },
          el(
            "div",
            {},
            el("div", { class: "muted", text: product.vendor }),
            el("div", { style: "font-weight: 600;", text: product.name }),
          ),
          el(
            "div",
            { class: "row", style: "gap: 6px;" },
            el("button", { class: "btn" }, "View"),
            el("button", { class: "btn" }, "Edit"),
          ),
        ),
        el(
          "div",
          { class: "row", style: "gap: 12px; flex-wrap: wrap; margin-top: 6px; align-items: center;" },
          el("div", {}, el("div", { class: "muted", text: "Lifecycle" }), el("div", { text: product.lifecycle })),
          el("div", {}, el("div", { class: "muted", text: "Owners" }), el("div", { text: product.owners })),
          el("div", {}, el("div", { class: "muted", text: "Latest release" }), el("div", { text: product.latestRelease })),
          el(
            "div",
            {},
            el("div", { class: "muted", text: "Tracked versions" }),
            el(
              "div",
              { class: "row", style: "gap: 6px; flex-wrap: wrap;" },
              product.versions.map((v) => el("span", { class: "tag" }, v)),
            ),
          ),
        ),
        el("p", { class: "muted", style: "margin-top: 8px;", text: product.notes }),
      ),
    ),
  );

  return el(
    "div",
    { class: "card" },
    el("h1", { class: "page-title", text: "Products" }),
    el("p", { class: "muted", text: "Track products, owners, and supported versions." }),
    controls,
    list,
  );
}
