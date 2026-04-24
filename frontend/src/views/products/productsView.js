import { el } from "../../ui/dom/el.js";
import { createProduct, listProducts } from "../../api/products.js";
import { toast } from "../../ui/components/toast.js";
import { getState } from "../../state/store.js";
import { canWrite, isAdmin } from "../../state/permissions.js";
import { renderProductCard } from "./productCard.js";

export async function ProductsView() {
  const state = getState();
  const editable = canWrite(state);
  const adminUser = isAdmin(state);
  const list = el("div", { class: "flex-col-12 mt-8" },
    el("div", { class: "muted", text: "Loading products..." }),
  );

  async function load() {
    list.innerHTML = "";
    list.appendChild(el("div", { class: "muted", text: "Loading products..." }));
    try {
      const res = await listProducts();
      const products = Array.isArray(res) ? res : (res?.items || []);
      list.innerHTML = "";
      if (!products.length) {
        list.appendChild(el("div", { class: "muted", text: "No products found." }));
        return;
      }
      products.forEach((p) => list.appendChild(renderProductCard(p, load, { canEdit: editable, isAdminUser: adminUser })));
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

  const teams = state?.session?.teams || [];
  const currentTeamId = state?.session?.currentTeamId;
  const showTeamSelect = teams.length >= 2 || adminUser;
  const teamSelect = showTeamSelect ? el("select", { class: "input", "aria-label": "Team" }) : null;
  if (teamSelect) {
    teams.forEach((t) => {
      const opt = el("option", { value: String(t.id) }, t.name + (t.is_default ? " (default)" : ""));
      if (t.id === currentTeamId) opt.selected = true;
      teamSelect.appendChild(opt);
    });
  }

  const form = el(
    "form",
    { class: "flex-col" },
    el("div", {}, el("div", { class: "muted", text: "Name" }), nameInput),
    el("div", {}, el("div", { class: "muted", text: "Description" }), descInput),
    teamSelect ? el("div", {}, el("div", { class: "muted", text: "Team" }), teamSelect) : null,
    el(
      "div",
      { class: "row flex-end gap-8" },
      cancelBtn,
      submitBtn,
    ),
  );

  const formCard = el(
    "div",
    { class: "card", style: "margin: 12px 0; display: none;" },
    el("h3", { class: "mt-0", text: "Add product" }),
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
      const teamId = teamSelect ? Number(teamSelect.value) : null;
      await createProduct({
        name,
        description: description || undefined,
        team_id: Number.isInteger(teamId) && teamId ? teamId : undefined,
      });
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

  if (editable) {
    form.addEventListener("submit", submitProduct);
    cancelBtn.addEventListener("click", () => {
      formCard.style.display = "none";
    });
  }

  const controls = el(
    "div",
    { class: "row flex-row-8 flex-wrap", style: "margin: 12px 0;" },
    el("div", { class: "muted", text: "Product catalog" }),
    el("div", { class: "spacer" }),
    editable
      ? (() => {
          const btn = el("button", { class: "btn primary", type: "button" }, "Add product");
          btn.addEventListener("click", () => {
            formCard.style.display = "block";
            nameInput.focus();
          });
          return btn;
        })()
      : null,
  );

  load();

  return el(
    "div",
    { class: "card" },
    el("h1", { class: "page-title", text: "Products" }),
    el("p", { class: "muted", text: "Track products, owners, and supported versions." }),
    controls,
    editable ? formCard : null,
    list,
  );
}
