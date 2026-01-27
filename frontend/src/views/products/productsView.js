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
import { listControls, createControl } from "../../api/controls.js";
import { listActiveUsers } from "../../api/users.js";
import { toast } from "../../ui/components/toast.js";
import { getState } from "../../state/store.js";
import { canWrite, isAdmin } from "../../state/permissions.js";

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

function renderProductCard(product, reloadList, { canEdit, isAdminUser }) {
  const detailContent = el("div", {});
  const detailCard = el("div", { class: "card", style: "padding: 12px; margin-top: 8px; display: none;" }, detailContent);

  let detailData = null;
  let isEditing = false;
  let ownerOptions = null;
  let controlOptions = null;

  const controlStatusOptions = ["Not Started", "In Progress", "Implemented", "Not Applicable"];

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
        canEdit ? editBtn : null,
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

  async function loadControls(force = false) {
    if (controlOptions && !force) return controlOptions;
    try {
      controlOptions = await listControls();
    } catch (err) {
      toast({ title: "Failed to load controls", message: err?.message || "Unable to list controls" });
      controlOptions = [];
    }
    return controlOptions;
  }

  function buildControlsPayload(controls) {
    return (controls || []).map((control) => ({
      control_id: control.id,
      implementation_status: control.implementation_status,
      notes: control.notes,
    }));
  }

  function renderVersionsSection() {
    const versionList = el("div", { style: "display: flex; flex-direction: column; gap: 8px;" });
    if (!detailData.versions?.length) {
      versionList.appendChild(el("div", { class: "muted", text: "No versions recorded yet." }));
    } else {
      detailData.versions.forEach((v) => {
        const toggleBtn = el("button", { class: "btn" }, v.is_active ? "Mark inactive" : "Mark active");
        const deleteBtn = el("button", { class: "btn" }, "Delete");
        if (canEdit) {
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
        } else {
          toggleBtn.disabled = true;
          deleteBtn.disabled = true;
        }

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
            canEdit ? el("div", { class: "row", style: "gap: 6px;" }, toggleBtn, deleteBtn) : null,
          ),
        );
      });
    }

    let addForm = null;
    if (canEdit) {
      const versionInput = el("input", { class: "input", placeholder: "Version identifier", required: "true" });
      const releaseInput = el("input", { class: "input", type: "date" });
      const activeInput = el("input", { type: "checkbox", checked: true });
      const addBtn = el("button", { class: "btn primary", type: "submit" }, "Add version");

      addForm = el(
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
    }

    return el(
      "div",
      {},
      el("h4", { text: "Versions" }),
      versionList,
      canEdit ? el("div", { class: "divider", style: "margin: 8px 0; height: 1px; background: #eee;" }) : null,
      addForm,
    );
  }

  async function renderControlsSection() {
    await loadControls();

    const container = el("div", { class: "card", style: "background: #fafafa;" });
    const content = el("div", {});
    container.append(el("h4", { text: "Controls" }), content);

    const mappings = Array.isArray(detailData.controls) ? detailData.controls : [];

    const list = el("div", { style: "display: flex; flex-direction: column; gap: 10px;" });
    if (!mappings.length) {
      list.appendChild(el("div", { class: "muted", text: "No controls mapped yet." }));
    } else {
      mappings.forEach((mapping) => {
        const statusSelect = el("select", { class: "input" });
        controlStatusOptions.forEach((status) => {
          const opt = el("option", { value: status, text: status });
          if (mapping.implementation_status === status) opt.selected = true;
          statusSelect.appendChild(opt);
        });

        const notesInput = el("textarea", { class: "input", rows: "2", placeholder: "Notes (optional)" });
        notesInput.value = mapping.notes || "";

        const saveBtn = el("button", { class: "btn" }, "Save");
        if (canEdit) {
          saveBtn.addEventListener("click", async () => {
            const updated = mappings.map((entry) => {
              if (entry.id !== mapping.id) return entry;
              return {
                ...entry,
                implementation_status: statusSelect.value,
                notes: notesInput.value,
              };
            });
            saveBtn.disabled = true;
            try {
              detailData = await updateProduct(product.id, { controls: buildControlsPayload(updated) });
              toast({ title: "Control updated", message: `${mapping.name} saved.` });
              await reloadList();
              renderDetails();
            } catch (err) {
              toast({ title: "Failed", message: err?.message || "Unable to update control mapping" });
            } finally {
              saveBtn.disabled = false;
            }
          });
        } else {
          saveBtn.disabled = true;
          statusSelect.disabled = true;
          notesInput.disabled = true;
        }

        const removeBtn = el("button", { class: "btn", style: "color: #b91c1c;" }, "Remove");
        if (canEdit) {
          removeBtn.addEventListener("click", async () => {
            if (!confirm(`Remove ${mapping.name} from this product?`)) return;
            removeBtn.disabled = true;
            try {
              const updated = mappings.filter((entry) => entry.id !== mapping.id);
              detailData = await updateProduct(product.id, { controls: buildControlsPayload(updated) });
              toast({ title: "Control removed", message: `${mapping.name} unmapped.` });
              await reloadList();
              renderDetails();
            } catch (err) {
              toast({ title: "Failed", message: err?.message || "Unable to remove control mapping" });
              removeBtn.disabled = false;
            }
          });
        } else {
          removeBtn.disabled = true;
        }

        list.appendChild(
          el(
            "div",
            { style: "border: 1px solid #e5e7eb; border-radius: 8px; padding: 10px;" },
            el("div", { style: "font-weight: 600;", text: mapping.name }),
            el("div", { class: "muted", text: mapping.framework ? `${mapping.framework}` : "No framework specified" }),
            mapping.description ? el("div", { class: "muted", text: mapping.description }) : null,
            el("div", { style: "margin-top: 8px;" }, el("div", { class: "muted", text: "Implementation status" }), statusSelect),
            el("div", { style: "margin-top: 8px;" }, el("div", { class: "muted", text: "Notes" }), notesInput),
            canEdit
              ? el("div", { class: "row", style: "gap: 8px; justify-content: flex-end; margin-top: 8px;" }, saveBtn, removeBtn)
              : null,
          ),
        );
      });
    }

    let addForm = null;
    let createForm = null;
    if (canEdit) {
      const addSelect = el("select", { class: "input" });
      const addStatus = el("select", { class: "input" }, ...controlStatusOptions.map((status) => el("option", { value: status, text: status })));
      const addNotes = el("textarea", { class: "input", rows: "2", placeholder: "Notes (optional)" });
      const addBtn = el("button", { class: "btn primary", type: "submit" }, "Add control");

      function refreshAddOptions() {
        const mappedIds = new Set(mappings.map((m) => m.id));
        addSelect.innerHTML = "";
        const available = (controlOptions || []).filter((c) => !mappedIds.has(c.id));
        if (!available.length) {
          addSelect.appendChild(el("option", { value: "", text: "No available controls" }));
          addSelect.disabled = true;
          addBtn.disabled = true;
          return;
        }
        addSelect.disabled = false;
        addBtn.disabled = false;
        available.forEach((control) => {
          const label = control.framework ? `${control.framework} - ${control.name}` : control.name;
          addSelect.appendChild(el("option", { value: control.id, text: label }));
        });
      }

      refreshAddOptions();

      addForm = el(
        "form",
        { style: "display: flex; flex-direction: column; gap: 8px; margin-top: 12px;" },
        el("div", {}, el("div", { class: "muted", text: "Control" }), addSelect),
        el("div", {}, el("div", { class: "muted", text: "Implementation status" }), addStatus),
        el("div", {}, el("div", { class: "muted", text: "Notes" }), addNotes),
        el("div", { class: "row", style: "justify-content: flex-end;" }, addBtn),
      );

      addForm.addEventListener("submit", async (e) => {
        e.preventDefault();
        const controlId = Number(addSelect.value);
        if (!controlId) {
          toast({ title: "Select a control", message: "Choose a control to map." });
          return;
        }
        addBtn.disabled = true;
        try {
          const control = (controlOptions || []).find((c) => c.id === controlId);
          const nextControls = [
            ...mappings,
            {
              id: control.id,
              name: control.name,
              framework: control.framework,
              description: control.description,
              implementation_status: addStatus.value,
              notes: addNotes.value,
            },
          ];
          detailData = await updateProduct(product.id, { controls: buildControlsPayload(nextControls) });
          toast({ title: "Control added", message: `${control.name} mapped.` });
          addNotes.value = "";
          await reloadList();
          renderDetails();
        } catch (err) {
          toast({ title: "Failed", message: err?.message || "Unable to map control" });
        } finally {
          addBtn.disabled = false;
        }
      });

      const createName = el("input", { class: "input", placeholder: "Control name", required: "true" });
      const createFramework = el("input", { class: "input", placeholder: "Framework (optional)" });
      const createDescription = el("textarea", { class: "input", placeholder: "Description (optional)" });
      const createBtn = el("button", { class: "btn", type: "submit" }, "Create control");

      createForm = el(
        "form",
        { style: "display: flex; flex-direction: column; gap: 8px; margin-top: 12px;" },
        el("div", {}, el("div", { class: "muted", text: "New control" }), createName),
        el("div", {}, el("div", { class: "muted", text: "Framework" }), createFramework),
        el("div", {}, el("div", { class: "muted", text: "Description" }), createDescription),
        el("div", { class: "row", style: "justify-content: flex-end;" }, createBtn),
      );

      createForm.addEventListener("submit", async (e) => {
        e.preventDefault();
        const name = createName.value.trim();
        if (!name) {
          toast({ title: "Name required", message: "Please enter a control name." });
          return;
        }
        createBtn.disabled = true;
        try {
          const created = await createControl({
            name,
            framework: createFramework.value.trim() || undefined,
            description: createDescription.value.trim() || undefined,
          });
          toast({ title: "Control created", message: `${created.name} added.` });
          createName.value = "";
          createFramework.value = "";
          createDescription.value = "";
          await loadControls(true);
          refreshAddOptions();
          addSelect.value = String(created.id);
        } catch (err) {
          toast({ title: "Failed", message: err?.message || "Unable to create control" });
        } finally {
          createBtn.disabled = false;
        }
      });
    }

    content.append(
      list,
      canEdit ? el("div", { class: "divider", style: "margin: 8px 0; height: 1px; background: #eee;" }) : null,
      addForm,
      canEdit ? el("div", { class: "divider", style: "margin: 8px 0; height: 1px; background: #eee;" }) : null,
      createForm,
    );

    return container;
  }

  async function renderEditSection() {
    if (isAdminUser && !ownerOptions) {
      try {
        ownerOptions = await listActiveUsers();
      } catch (err) {
        toast({ title: "Failed to load owners", message: err?.message || "Unable to list users" });
        ownerOptions = [];
      }
    }

    const nameInput = el("input", { class: "input", value: detailData.name || "", required: "true" });
    const descInput = el("textarea", { class: "input", value: detailData.description || "" });
    let ownerSelect = null;
    if (isAdminUser) {
      ownerSelect = el("select", { class: "input", multiple: "true", size: "5" });
      (ownerOptions || []).forEach((u) => {
        const label = u.full_name || u.username || u.email;
        const opt = el("option", { value: u.id, text: label });
        if ((detailData.owner_ids || []).includes(u.id)) opt.selected = true;
        ownerSelect.appendChild(opt);
      });
    }

    const cancelBtn = el("button", { class: "btn", type: "button" }, "Cancel");
    const saveBtn = el("button", { class: "btn primary", type: "submit" }, "Save changes");

    const form = el(
      "form",
      { style: "display: flex; flex-direction: column; gap: 10px; margin-top: 8px;" },
      el("div", {}, el("div", { class: "muted", text: "Name" }), nameInput),
      el("div", {}, el("div", { class: "muted", text: "Description" }), descInput),
      isAdminUser
        ? el("div", {}, el("div", { class: "muted", text: "Owners" }), ownerSelect, el("div", { class: "muted", text: "Hold Ctrl/Cmd to select multiple" }))
        : el("div", { class: "muted", text: "Owner assignment is restricted to Admins." }),
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
      const ownerIds = isAdminUser ? Array.from(ownerSelect.selectedOptions || []).map((o) => Number(o.value)) : undefined;

      saveBtn.disabled = true;
      cancelBtn.disabled = true;
      saveBtn.textContent = "Saving...";
      try {
        const payload = { name, description: descInput.value };
        if (isAdminUser && ownerIds) {
          payload.owner_ids = ownerIds;
        }
        detailData = await updateProduct(product.id, payload);
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
    if (isAdminUser) {
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
    }

    const actionRow = canEdit
      ? el(
          "div",
          { class: "row", style: "gap: 8px; justify-content: flex-end; flex-wrap: wrap;" },
          el("button", { class: "btn", type: "button", onclick: async () => { isEditing = !isEditing; await loadDetails(); renderDetails(); } }, isEditing ? "Close editor" : "Edit product"),
          isAdminUser ? deleteBtn : null,
        )
      : null;

    detailContent.append(
      el("h3", { text: detailData.name }),
      description,
      ownerSection,
      meta,
      actionRow,
    );

    renderControlsSection().then((controlsSection) => {
      if (controlsSection && !detailContent.contains(controlsSection)) {
        detailContent.appendChild(controlsSection);
      }
    });

    detailContent.append(renderVersionsSection());

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

  if (canEdit) {
    editBtn.addEventListener("click", async () => {
      isEditing = true;
      await loadDetails();
      detailCard.style.display = "block";
      renderDetails();
      viewBtn.textContent = "Hide";
    });
  }

  return el("div", {}, header, detailCard);
}

export async function ProductsView() {
  const state = getState();
  const editable = canWrite(state);
  const adminUser = isAdmin(state);
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

  if (editable) {
    form.addEventListener("submit", submitProduct);
    cancelBtn.addEventListener("click", () => {
      formCard.style.display = "none";
    });
  }

  const controls = el(
    "div",
    { class: "row", style: "gap: 8px; align-items: center; margin: 12px 0; flex-wrap: wrap;" },
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
