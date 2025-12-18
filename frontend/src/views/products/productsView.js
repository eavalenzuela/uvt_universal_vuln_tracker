import { el } from "../../ui/dom/el.js";
import { listProducts } from "../../api/products.js";
import { toast } from "../../ui/components/toast.js";

function renderProduct(product) {
  return el(
    "div",
    { class: "card", style: "padding: 12px;" },
    el(
      "div",
      { class: "row", style: "justify-content: space-between; align-items: baseline; gap: 8px;" },
      el(
        "div",
        {},
        el("div", { class: "muted", text: product.vendor || "" }),
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
      el("div", {}, el("div", { class: "muted", text: "Created" }), el("div", { text: product.created_at ? product.created_at.slice(0, 10) : "-" })),
      el("div", {}, el("div", { class: "muted", text: "Updated" }), el("div", { text: product.updated_at ? product.updated_at.slice(0, 10) : "-" })),
    ),
    product.description ? el("p", { class: "muted", style: "margin-top: 8px;", text: product.description }) : null,
  );
}

export async function ProductsView() {
  const list = el("div", { style: "display: flex; flex-direction: column; gap: 12px; margin-top: 8px;" },
    el("div", { class: "muted", text: "Loading products..." }),
  );

  async function load() {
    list.innerHTML = "";
    list.appendChild(el("div", { class: "muted", text: "Loading products..." }));
    try {
      const products = await listProducts();
      list.innerHTML = "";
      if (!products?.length) {
        list.appendChild(el("div", { class: "muted", text: "No products found." }));
        return;
      }
      products.forEach((p) => list.appendChild(renderProduct(p)));
    } catch (e) {
      list.innerHTML = "";
      toast({ title: "Failed to load products", message: e?.message || "Unable to fetch products" });
      list.appendChild(el("div", { class: "muted", text: "Unable to load products." }));
    }
  }

  const controls = el(
    "div",
    { class: "row", style: "gap: 8px; align-items: center; margin: 12px 0; flex-wrap: wrap;" },
    el("div", { class: "muted", text: "Product catalog" }),
    el("div", { class: "spacer" }),
    el("button", { class: "btn primary" }, "Add product"),
  );

  load();

  return el(
    "div",
    { class: "card" },
    el("h1", { class: "page-title", text: "Products" }),
    el("p", { class: "muted", text: "Track products, owners, and supported versions." }),
    controls,
    list,
  );
}
