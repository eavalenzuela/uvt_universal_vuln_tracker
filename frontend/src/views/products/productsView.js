import { el } from "../../ui/dom/el.js";
import { createProduct, listProducts } from "../../api/products.js";
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

  const nameInput = el("input", { class: "input", placeholder: "Product name", required: "true" });
  const descInput = el("textarea", { class: "input", placeholder: "Description (optional)" });
  const cancelBtn = el("button", { class: "btn", type: "button" }, "Cancel");
  const submitBtn = el("button", { class: "btn primary", type: "submit" }, "Save product");

  const form = el(
    "form",
    { style: "display: flex; flex-direction: column; gap: 10px;" },
    el("div", {}, el("div", { class: "muted", text: "Name" }), nameInput),
    el("div", {}, el("div", { class: "muted", text: "Description" }), descInput),
    el(
      "div",
      { class: "row", style: "justify-content: flex-end; gap: 8px;" },
      cancelBtn,
      submitBtn,
    ),
  );

  const formCard = el(
    "div",
    { class: "card", style: "margin: 12px 0; display: none;" },
    el("h3", { style: "margin-top: 0;", text: "Add product" }),
    el("p", { class: "muted", text: "Create a catalog entry for a product." }),
    form,
  );

  async function submitProduct(e) {
    e.preventDefault();
    const name = nameInput.value.trim();
    const description = descInput.value.trim();

    if (!name) {
      toast({ title: "Name required", message: "Please enter a product name." });
      nameInput.focus();
      return;
    }

    submitBtn.disabled = true;
    cancelBtn.disabled = true;
    submitBtn.textContent = "Saving...";

    try {
      await createProduct({ name, description: description || undefined });
      toast({ title: "Product added", message: `${name} has been created.` });
      nameInput.value = "";
      descInput.value = "";
      formCard.style.display = "none";
      await load();
    } catch (e) {
      toast({ title: "Failed to add product", message: e?.message || "Unable to save product" });
    } finally {
      submitBtn.disabled = false;
      cancelBtn.disabled = false;
      submitBtn.textContent = "Save product";
    }
  }

  form.addEventListener("submit", submitProduct);
  cancelBtn.addEventListener("click", () => {
    formCard.style.display = "none";
  });

  const controls = el(
    "div",
    { class: "row", style: "gap: 8px; align-items: center; margin: 12px 0; flex-wrap: wrap;" },
    el("div", { class: "muted", text: "Product catalog" }),
    el("div", { class: "spacer" }),
    (() => {
      const btn = el("button", { class: "btn primary", type: "button" }, "Add product");
      btn.addEventListener("click", () => {
        formCard.style.display = "block";
        nameInput.focus();
      });
      return btn;
    })(),
  );

  load();

  return el(
    "div",
    { class: "card" },
    el("h1", { class: "page-title", text: "Products" }),
    el("p", { class: "muted", text: "Track products, owners, and supported versions." }),
    controls,
    formCard,
    list,
  );
}
