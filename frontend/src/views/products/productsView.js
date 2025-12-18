import { el } from "../../ui/dom/el.js";
import {
  createProduct,
  listProducts,
  getProduct,
  updateProduct,
  deleteProduct,
  createProductVersion,
  updateProductVersion,
  deleteProductVersion,
} from "../../api/products.js";
import { listActiveUsers } from "../../api/users.js";
import { toast } from "../../ui/components/toast.js";

function renderOwnerChip(owner) {
  const label = owner.full_name || owner.username || owner.email || `User ${owner.id}`;
  return el(
    "span",
    {
      class: "badge",
      style: "background: #eef2ff; color: #1e3a8a; border: 1px solid #c7d2fe;", // lightweight styling
    },
    label,
  );
}

function renderProductCard(product, reloadList) {
  const detailContent = el("div", {});
  const detailCard = el("div", { class: "card", style: "padding: 12px; margin-top: 8px; display: none;" }, detailContent);

  let detailData = null;
  let isEditing = false;
  let ownerOptions = null;

  const viewBtn = el("button", { class: "btn" }, "View");
  const editBtn = el("button", { class: "btn" }, "Edit");

  const header = el(
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
        viewBtn,
        editBtn,
      ),
    ),
    el(
      "div",
      { class: "row", style: "gap: 12px; flex-wrap: wrap; margin-top: 6px; align-items: center;" },
      el("div", {}, el("div", { class: "muted", text: "Created" }), el("div", { text: product.created_at ? product.created_at.slice(0, 10) : "-" })),
      el("div", {}, el("div", { class: "muted", text: "Updated" }), el("div", { text: product.updated_at ? product.updated_at.slice(0, 10) : "-" })),
      el("div", {}, el("div", { class: "muted", text: "Versions" }), el("div", { text: product.version_count ?? "-" })),
    ),
    product.description ? el("p", { class: "muted", style: "margin-top: 8px;", text: product.description }) : null,
  );

  async function loadDetails(force = false) {
    if (detailData && !force) return detailData;
    detailContent.innerHTML = "";
    detailContent.appendChild(el("div", { class: "muted", text: "Loading product details..." }));
    try {
      detailData = await getProduct(product.id);
      renderDetails();
      return detailData;
    } catch (e) {
      detailContent.innerHTML = "";
      toast({ title: "Failed to load", message: e?.message || "Unable to fetch product" });
      detailContent.appendChild(el("div", { class: "muted", text: "Unable to load product details." }));
      throw e;
    }
  }

  function renderVersionsSection() {
    const versionList = el("div", { style: "display: flex; flex-direction: column; gap: 8px;" });
    if (!detailData.versions?.length) {
      versionList.appendChild(el("div", { class: "muted", text: "No versions recorded yet." }));
    } else {
      detailData.versions.forEach((v) => {
        const toggleBtn = el("button", { class: "btn" }, v.is_active ? "Mark inactive" : "Mark active");
        toggleBtn.addEventListener("click", async () => {
          try {
            await updateProductVersion(product.id, v.id, { is_active: !v.is_active });
            toast({ title: "Version updated", message: `${v.version} status changed.` });
            detailData = await loadDetails(true);
            await reloadList();
          } catch (err) {
            toast({ title: "Failed", message: err?.message || "Unable to update version" });
          }
        });

        const deleteBtn = el("button", { class: "btn" }, "Delete");
        deleteBtn.addEventListener("click", async () => {
          if (!confirm(`Delete version ${v.version}?`)) return;
          try {
            await deleteProductVersion(product.id, v.id);
            toast({ title: "Version removed", message: `${v.version} deleted.` });
            detailData = await loadDetails(true);
            await reloadList();
          } catch (err) {
            toast({ title: "Failed", message: err?.message || "Unable to delete version" });
          }
        });

        versionList.appendChild(
          el(
            "div",
            { class: "row", style: "justify-content: space-between; align-items: center; gap: 10px;" },
            el(
              "div",
              {},
              el("div", { style: "font-weight: 600;", text: v.version }),
              el(
                "div",
                { class: "muted", style: "display: flex; gap: 12px; flex-wrap: wrap;" },
                el("span", { text: v.is_active ? "Active" : "Inactive" }),
                el("span", { text: v.release_date ? `Released ${v.release_date}` : "Release date not set" }),
              ),
            ),
            el("div", { class: "row", style: "gap: 6px;" }, toggleBtn, deleteBtn),
          ),
        );
      });
    }

    const versionInput = el("input", { class: "input", placeholder: "Version identifier", required: "true" });
    const releaseInput = el("input", { class: "input", type: "date" });
    const activeInput = el("input", { type: "checkbox", checked: true });
    const addBtn = el("button", { class: "btn primary", type: "submit" }, "Add version");

    const addForm = el(
      "form",
      { style: "display: flex; flex-direction: column; gap: 8px;" },
      el("div", {}, el("div", { class: "muted", text: "Version" }), versionInput),
      el("div", {}, el("div", { class: "muted", text: "Release date" }), releaseInput),
      el(
        "label",
        { class: "row", style: "gap: 8px; align-items: center;" },
        activeInput,
        el("span", { text: "Active" }),
      ),
      el("div", { class: "row", style: "justify-content: flex-end;" }, addBtn),
    );

    addForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      const version = versionInput.value.trim();
      if (!version) {
        toast({ title: "Version required", message: "Please enter a version label." });
        return;
      }
      addBtn.disabled = true;
      addBtn.textContent = "Saving...";
      try {
        await createProductVersion(product.id, {
          version,
          release_date: releaseInput.value || undefined,
          is_active: !!activeInput.checked,
        });
        toast({ title: "Version added", message: `${version} created.` });
        versionInput.value = "";
        releaseInput.value = "";
        activeInput.checked = true;
        detailData = await loadDetails(true);
        await reloadList();
      } catch (err) {
        toast({ title: "Failed", message: err?.message || "Unable to add version" });
      } finally {
        addBtn.disabled = false;
        addBtn.textContent = "Add version";
      }
    });

    return el(
      "div",
      {},
      el("h4", { text: "Versions" }),
      versionList,
      el("div", { class: "divider", style: "margin: 8px 0; height: 1px; background: #eee;" }),
      addForm,
    );
  }

  async function renderEditSection() {
    if (!ownerOptions) {
      try {
        ownerOptions = await listActiveUsers();
      } catch (err) {
        toast({ title: "Failed to load owners", message: err?.message || "Unable to list users" });
        ownerOptions = [];
      }
    }

    const nameInput = el("input", { class: "input", value: detailData.name || "", required: "true" });
    const descInput = el("textarea", { class: "input", value: detailData.description || "" });
    const ownerSelect = el("select", { class: "input", multiple: "true", size: "5" });
    (ownerOptions || []).forEach((u) => {
      const label = u.full_name || u.username || u.email;
      const opt = el("option", { value: u.id, text: label });
      if ((detailData.owner_ids || []).includes(u.id)) opt.selected = true;
      ownerSelect.appendChild(opt);
    });

    const cancelBtn = el("button", { class: "btn", type: "button" }, "Cancel");
    const saveBtn = el("button", { class: "btn primary", type: "submit" }, "Save changes");

    const form = el(
      "form",
      { style: "display: flex; flex-direction: column; gap: 10px; margin-top: 8px;" },
      el("div", {}, el("div", { class: "muted", text: "Name" }), nameInput),
      el("div", {}, el("div", { class: "muted", text: "Description" }), descInput),
      el("div", {}, el("div", { class: "muted", text: "Owners" }), ownerSelect, el("div", { class: "muted", text: "Hold Ctrl/Cmd to select multiple" })),
      el(
        "div",
        { class: "row", style: "justify-content: flex-end; gap: 8px;" },
        cancelBtn,
        saveBtn,
      ),
    );

    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      const name = nameInput.value.trim();
      if (!name) {
        toast({ title: "Name required", message: "Please enter a product name." });
        return;
      }
      const ownerIds = Array.from(ownerSelect.selectedOptions || []).map((o) => Number(o.value));

      saveBtn.disabled = true;
      cancelBtn.disabled = true;
      saveBtn.textContent = "Saving...";
      try {
        detailData = await updateProduct(product.id, { name, description: descInput.value, owner_ids: ownerIds });
        toast({ title: "Product updated", message: `${name} saved.` });
        isEditing = false;
        renderDetails();
        await reloadList();
      } catch (err) {
        toast({ title: "Failed", message: err?.message || "Unable to update product" });
      } finally {
        saveBtn.disabled = false;
        cancelBtn.disabled = false;
        saveBtn.textContent = "Save changes";
      }
    });

    cancelBtn.addEventListener("click", () => {
      isEditing = false;
      renderDetails();
    });

    return el("div", { class: "card", style: "background: #fafafa;" }, el("h4", { text: "Edit product" }), form);
  }

  function renderDetails() {
    detailContent.innerHTML = "";
    if (!detailData) return;

    const ownerSection = el(
      "div",
      {},
      el("h4", { text: "Owners" }),
      detailData.owners?.length
        ? el("div", { class: "row", style: "gap: 6px; flex-wrap: wrap;" }, ...(detailData.owners.map(renderOwnerChip)))
        : el("div", { class: "muted", text: "No owners assigned." }),
    );

    const meta = el(
      "div",
      { class: "row", style: "gap: 12px; flex-wrap: wrap; margin-bottom: 8px;" },
      detailData.created_by ? el("div", {}, el("div", { class: "muted", text: "Created by" }), el("div", { text: detailData.created_by.full_name || detailData.created_by.username })) : null,
      el("div", {}, el("div", { class: "muted", text: "Updated" }), el("div", { text: detailData.updated_at ? detailData.updated_at.slice(0, 10) : "-" })),
    );

    const description = detailData.description
      ? el("p", { text: detailData.description })
      : el("p", { class: "muted", text: "No description provided." });

    const deleteBtn = el("button", { class: "btn", style: "color: #b91c1c;" }, "Delete product");
    deleteBtn.addEventListener("click", async () => {
      if (!confirm(`Delete ${detailData.name}? This cannot be undone.`)) return;
      try {
        await deleteProduct(product.id);
        toast({ title: "Product deleted", message: `${detailData.name} removed.` });
        header.remove();
        detailCard.remove();
        await reloadList();
      } catch (err) {
        toast({ title: "Failed", message: err?.message || "Unable to delete product" });
      }
    });

    const actionRow = el(
      "div",
      { class: "row", style: "gap: 8px; justify-content: flex-end; flex-wrap: wrap;" },
      el("button", { class: "btn", type: "button", onclick: async () => { isEditing = !isEditing; await loadDetails(); renderDetails(); } }, isEditing ? "Close editor" : "Edit product"),
      deleteBtn,
    );

    detailContent.append(
      el("h3", { text: detailData.name }),
      description,
      ownerSection,
      meta,
      actionRow,
      renderVersionsSection(),
    );

    if (isEditing) {
      renderEditSection().then((form) => {
        if (!detailContent.contains(form)) detailContent.appendChild(form);
      });
    }
  }

  viewBtn.addEventListener("click", async () => {
    if (detailCard.style.display === "none") {
      await loadDetails();
      detailCard.style.display = "block";
      viewBtn.textContent = "Hide";
    } else {
      detailCard.style.display = "none";
      viewBtn.textContent = "View";
    }
  });

  editBtn.addEventListener("click", async () => {
    isEditing = true;
    await loadDetails();
    detailCard.style.display = "block";
    renderDetails();
    viewBtn.textContent = "Hide";
  });

  return el("div", {}, header, detailCard);
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
      products.forEach((p) => list.appendChild(renderProductCard(p, load)));
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
