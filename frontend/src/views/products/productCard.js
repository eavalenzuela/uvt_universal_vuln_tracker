import { el } from "../../ui/dom/el.js";
import {
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

function renderOwnerChip(owner) {
  const label = owner.full_name || owner.username || owner.email || `User ${owner.id}`;
  return el(
    "span",
    {
      class: "badge badge-owner",
    },
    label,
  );
}

export function renderProductCard(product, reloadList, { canEdit, isAdminUser }) {
  const detailContent = el("div", {});
  const detailCard = el("div", { class: "card p-12 mt-8", style: "display: none;" }, detailContent);

  let detailData = null;
  let isEditing = false;
  let ownerOptions = null;
  let controlOptions = null;

  const controlStatusOptions = ["Not Started", "In Progress", "Implemented", "Not Applicable"];

  const viewBtn = el("button", { class: "btn" }, "View");
  const editBtn = el("button", { class: "btn" }, "Edit");

  const header = el(
    "div",
    { class: "card p-12" },
    el(
      "div",
      { class: "row flex-between items-baseline gap-8" },
      el(
        "div",
        {},
        el("div", { class: "muted", text: product.vendor || "" }),
        el("div", { class: "font-semibold", text: product.name }),
      ),
      el(
        "div",
        { class: "row gap-6" },
        viewBtn,
        canEdit ? editBtn : null,
      ),
    ),
    el(
      "div",
      { class: "row gap-12 flex-wrap items-center", style: "margin-top: 6px;" },
      el("div", {}, el("div", { class: "muted", text: "Created" }), el("div", { text: product.created_at ? product.created_at.slice(0, 10) : "-" })),
      el("div", {}, el("div", { class: "muted", text: "Updated" }), el("div", { text: product.updated_at ? product.updated_at.slice(0, 10) : "-" })),
      el("div", {}, el("div", { class: "muted", text: "Versions" }), el("div", { text: product.version_count ?? "-" })),
      el("div", {}, el("div", { class: "muted", text: "Components" }), el("div", { text: product.component_count ?? "-" })),
    ),
    product.description ? el("p", { class: "muted mt-8", text: product.description }) : null,
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
    const versionList = el("div", { class: "flex-col-8" });
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
            { class: "row flex-between items-center gap-10" },
            el(
              "div",
              {},
              el("div", { class: "font-semibold", text: v.version }),
              el(
                "div",
                { class: "muted flex-row-12 flex-wrap" },
                el("span", { text: v.is_active ? "Active" : "Inactive" }),
                el("span", { text: v.release_date ? `Released ${v.release_date}` : "Release date not set" }),
              ),
            ),
            canEdit ? el("div", { class: "row gap-6" }, toggleBtn, deleteBtn) : null,
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
        { class: "flex-col-8" },
        el("div", {}, el("div", { class: "muted", text: "Version" }), versionInput),
        el("div", {}, el("div", { class: "muted", text: "Release date" }), releaseInput),
        el(
          "label",
          { class: "row gap-8 items-center" },
          activeInput,
          el("span", { text: "Active" }),
        ),
        el("div", { class: "row flex-end" }, addBtn),
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
      canEdit ? el("div", { class: "divider" }) : null,
      addForm,
    );
  }

  async function renderControlsSection() {
    await loadControls();

    const container = el("div", { class: "card", style: "background: #fafafa;" });
    const content = el("div", {});
    container.append(el("h4", { text: "Controls" }), content);

    const mappings = Array.isArray(detailData.controls) ? detailData.controls : [];

    const list = el("div", { class: "flex-col-10" });
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

        const removeBtn = el("button", { class: "btn text-danger" }, "Remove");
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
            { class: "detail-border p-10" },
            el("div", { class: "font-semibold", text: mapping.name }),
            el("div", { class: "muted", text: mapping.framework ? `${mapping.framework}` : "No framework specified" }),
            mapping.description ? el("div", { class: "muted", text: mapping.description }) : null,
            el("div", { class: "mt-8" }, el("div", { class: "muted", text: "Implementation status" }), statusSelect),
            el("div", { class: "mt-8" }, el("div", { class: "muted", text: "Notes" }), notesInput),
            canEdit
              ? el("div", { class: "row gap-8 flex-end mt-8" }, saveBtn, removeBtn)
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
        { class: "flex-col-8 mt-12" },
        el("div", {}, el("div", { class: "muted", text: "Control" }), addSelect),
        el("div", {}, el("div", { class: "muted", text: "Implementation status" }), addStatus),
        el("div", {}, el("div", { class: "muted", text: "Notes" }), addNotes),
        el("div", { class: "row flex-end" }, addBtn),
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
        { class: "flex-col-8 mt-12" },
        el("div", {}, el("div", { class: "muted", text: "New control" }), createName),
        el("div", {}, el("div", { class: "muted", text: "Framework" }), createFramework),
        el("div", {}, el("div", { class: "muted", text: "Description" }), createDescription),
        el("div", { class: "row flex-end" }, createBtn),
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
      canEdit ? el("div", { class: "divider" }) : null,
      addForm,
      canEdit ? el("div", { class: "divider" }) : null,
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
      { class: "flex-col-10 mt-8" },
      el("div", {}, el("div", { class: "muted", text: "Name" }), nameInput),
      el("div", {}, el("div", { class: "muted", text: "Description" }), descInput),
      isAdminUser
        ? el("div", {}, el("div", { class: "muted", text: "Owners" }), ownerSelect, el("div", { class: "muted", text: "Hold Ctrl/Cmd to select multiple" }))
        : el("div", { class: "muted", text: "Owner assignment is restricted to Admins." }),
      el(
        "div",
        { class: "row flex-end gap-8" },
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
        ? el("div", { class: "row gap-6 flex-wrap" }, ...(detailData.owners.map(renderOwnerChip)))
        : el("div", { class: "muted", text: "No owners assigned." }),
    );

    const meta = el(
      "div",
      { class: "row gap-12 flex-wrap mb-8" },
      detailData.created_by ? el("div", {}, el("div", { class: "muted", text: "Created by" }), el("div", { text: detailData.created_by.full_name || detailData.created_by.username })) : null,
      el("div", {}, el("div", { class: "muted", text: "Updated" }), el("div", { text: detailData.updated_at ? detailData.updated_at.slice(0, 10) : "-" })),
    );

    const description = detailData.description
      ? el("p", { text: detailData.description })
      : el("p", { class: "muted", text: "No description provided." });

    const deleteBtn = el("button", { class: "btn text-danger" }, "Delete product");
    const componentSection = el(
      "div",
      {},
      el("h4", { text: "Software components" }),
      detailData.components?.length
        ? el("div", { class: "flex-col-8" },
            ...detailData.components.map((c) =>
              el("div", { class: "card p-8" },
                el("div", { class: "font-semibold", text: `${c.ecosystem || "pkg"} • ${c.name} ${c.version || ""}` }),
                el("div", { class: "muted", text: `Product version: ${c.version_label || "-"}` }),
                c.dependency_path ? el("div", { class: "muted", text: c.dependency_path }) : null,
              )
            )
          )
        : el("div", { class: "muted", text: "No software components imported yet." }),
    );
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
          { class: "row gap-8 flex-end flex-wrap" },
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
    detailContent.append(componentSection);

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
