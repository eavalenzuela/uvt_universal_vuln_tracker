import { el } from "../../ui/dom/el.js";
import { navigate } from "../../router/router.js";
import { getState } from "../../state/store.js";
import { canWrite, isAdmin } from "../../state/permissions.js";
import { toast } from "../../ui/components/toast.js";
import { getProduct, updateProduct, createProductVersion, deleteProduct } from "../../api/products.js";
import { listComponents } from "../../api/components.js";
import { listVulnerabilities } from "../../api/vulnerabilities.js";

function fmtDate(value) {
  return value ? value.slice(0, 10) : "-";
}

function ownerLabel(owner) {
  return owner?.full_name || owner?.username || owner?.email || `User ${owner?.id || "-"}`;
}

export async function ProductDetailView(params = {}) {
  const productId = Number(params?.id);
  if (!Number.isFinite(productId) || productId <= 0) {
    return el("div", { class: "card" }, el("h1", { class: "page-title", text: "Product detail" }), el("p", { text: "Invalid product id." }));
  }

  const state = getState();
  const editable = canWrite(state);
  const adminUser = isAdmin(state);

  const root = el("div", { class: "stack" });
  const header = el(
    "div",
    { class: "card" },
    el("div", { class: "row", style: "justify-content: space-between; gap: 8px; align-items: center; flex-wrap: wrap;" },
      el("h1", { class: "page-title", text: "Product detail" }),
      el("button", { class: "btn", type: "button", onClick: () => navigate("/products") }, "Back to products"),
    ),
  );
  const content = el("div", { class: "card" }, el("p", { class: "muted", text: "Loading product..." }));

  async function render() {
    content.innerHTML = "";
    content.appendChild(el("p", { class: "muted", text: "Loading product..." }));

    try {
      const product = await getProduct(productId);

      const versions = product.versions || [];
      const sortedVersions = [...versions].sort((a, b) => (a.version || "").localeCompare(b.version || "", undefined, { numeric: true }));

      const componentsByVersion = await Promise.all(
        sortedVersions.map(async (version) => {
          try {
            const rows = await listComponents(version.id);
            return [version.id, rows || []];
          } catch {
            return [version.id, []];
          }
        }),
      );
      const componentMap = new Map(componentsByVersion);

      const componentKeys = new Map();
      for (const [, rows] of componentMap.entries()) {
        rows.forEach((component) => {
          const key = `${component.ecosystem || ""}::${component.name || ""}`;
          if (component.name && !componentKeys.has(key)) {
            componentKeys.set(key, { ecosystem: component.ecosystem, name: component.name });
          }
        });
      }

      const vulnerabilityPairs = await Promise.all(
        [...componentKeys.values()].map(async (componentRef) => {
          try {
            const response = await listVulnerabilities({
              component_ecosystem: componentRef.ecosystem,
              component_name: componentRef.name,
              page_size: 10,
            });
            return [componentRef, response?.items || []];
          } catch {
            return [componentRef, []];
          }
        }),
      );

      const vulnIndex = new Map();
      vulnerabilityPairs.forEach(([componentRef, items]) => {
        items.forEach((item) => {
          if (!item?.id) return;
          const existing = vulnIndex.get(item.id) || { vuln: item, components: [] };
          existing.components.push(`${componentRef.ecosystem || "-"}/${componentRef.name}`);
          vulnIndex.set(item.id, existing);
        });
      });

      const editBtn = el("button", { class: "btn", type: "button" }, "Edit product");
      const addVersionBtn = el("button", { class: "btn", type: "button" }, "Add version");

      const editSection = el("div", { class: "card", style: "display:none; margin-top:8px;" });
      const addVersionSection = el("div", { class: "card", style: "display:none; margin-top:8px;" });

      if (editable) {
        const nameInput = el("input", { class: "input", value: product.name || "", required: "true" });
        const descInput = el("textarea", { class: "input", rows: "3" });
        descInput.value = product.description || "";
        const saveBtn = el("button", { class: "btn primary", type: "submit" }, "Save changes");
        const cancelBtn = el("button", { class: "btn", type: "button" }, "Cancel");

        const editForm = el(
          "form",
          { style: "display:flex; flex-direction:column; gap:8px;" },
          el("h3", { text: "Edit product" }),
          el("div", {}, el("div", { class: "muted", text: "Name" }), nameInput),
          el("div", {}, el("div", { class: "muted", text: "Description" }), descInput),
          el("div", { class: "row", style: "justify-content:flex-end; gap:8px;" }, cancelBtn, saveBtn),
        );

        editForm.addEventListener("submit", async (event) => {
          event.preventDefault();
          const nextName = nameInput.value.trim();
          if (!nextName) {
            toast({ title: "Name required", message: "Enter a product name." });
            return;
          }
          saveBtn.disabled = true;
          try {
            await updateProduct(productId, { name: nextName, description: descInput.value.trim() || undefined });
            toast({ title: "Product updated", message: `${nextName} saved.` });
            await render();
          } catch (err) {
            toast({ title: "Update failed", message: err?.message || "Unable to save product" });
          } finally {
            saveBtn.disabled = false;
          }
        });

        cancelBtn.addEventListener("click", () => {
          editSection.style.display = "none";
        });

        editSection.appendChild(editForm);

        const versionInput = el("input", { class: "input", placeholder: "Version label", required: "true" });
        const releaseInput = el("input", { class: "input", type: "date" });
        const activeInput = el("input", { type: "checkbox", checked: true });
        const addBtn = el("button", { class: "btn primary", type: "submit" }, "Create version");

        const versionForm = el(
          "form",
          { style: "display:flex; flex-direction:column; gap:8px;" },
          el("h3", { text: "Add version" }),
          el("div", {}, el("div", { class: "muted", text: "Version" }), versionInput),
          el("div", {}, el("div", { class: "muted", text: "Release date" }), releaseInput),
          el("label", { class: "row", style: "gap:8px; align-items:center;" }, activeInput, el("span", { text: "Active" })),
          el("div", { class: "row", style: "justify-content:flex-end;" }, addBtn),
        );

        versionForm.addEventListener("submit", async (event) => {
          event.preventDefault();
          const version = versionInput.value.trim();
          if (!version) {
            toast({ title: "Version required", message: "Enter a version label." });
            return;
          }
          addBtn.disabled = true;
          try {
            await createProductVersion(productId, {
              version,
              release_date: releaseInput.value || undefined,
              is_active: !!activeInput.checked,
            });
            toast({ title: "Version added", message: `${version} created.` });
            await render();
          } catch (err) {
            toast({ title: "Failed", message: err?.message || "Unable to create version" });
          } finally {
            addBtn.disabled = false;
          }
        });

        addVersionSection.appendChild(versionForm);

        editBtn.addEventListener("click", () => {
          editSection.style.display = editSection.style.display === "none" ? "block" : "none";
        });
        addVersionBtn.addEventListener("click", () => {
          addVersionSection.style.display = addVersionSection.style.display === "none" ? "block" : "none";
        });
      } else {
        editBtn.disabled = true;
        addVersionBtn.disabled = true;
      }

      const deleteBtn = el("button", { class: "btn", style: "color:#b91c1c;", type: "button" }, "Delete product");
      if (adminUser) {
        deleteBtn.addEventListener("click", async () => {
          if (!window.confirm(`Delete ${product.name}? This cannot be undone.`)) return;
          try {
            await deleteProduct(productId);
            toast({ title: "Product deleted", message: `${product.name} removed.` });
            navigate("/products");
          } catch (err) {
            toast({ title: "Delete failed", message: err?.message || "Unable to delete product" });
          }
        });
      } else {
        deleteBtn.disabled = true;
      }

      const versionTableBody = el("tbody", {});
      if (!sortedVersions.length) {
        versionTableBody.appendChild(el("tr", {}, el("td", { colspan: "5", class: "muted", text: "No versions yet." })));
      } else {
        sortedVersions.forEach((version, index) => {
          const prev = sortedVersions[index - 1];
          const diffLink = prev
            ? el("button", {
                class: "btn",
                type: "button",
                onClick: () => navigate(`/products/component-diff?from=${prev.id}&to=${version.id}`),
              }, "Inspect component diff")
            : el("span", { class: "muted", text: "N/A" });

          versionTableBody.appendChild(
            el("tr", {},
              el("td", { text: version.version || "-" }),
              el("td", { text: fmtDate(version.release_date) }),
              el("td", { text: version.is_active ? "Active" : "Inactive" }),
              el("td", { text: String((componentMap.get(version.id) || []).length) }),
              el("td", {}, diffLink),
            ),
          );
        });
      }

      const linkedVulns = [...vulnIndex.values()].sort((a, b) => (b.vuln.updated_at || "").localeCompare(a.vuln.updated_at || ""));

      content.innerHTML = "";
      content.append(
        el("div", { class: "row", style: "justify-content:space-between; align-items:center; flex-wrap:wrap; gap:8px;" },
          el("div", {},
            el("h2", { text: product.name }),
            product.description ? el("p", { class: "muted", text: product.description }) : el("p", { class: "muted", text: "No description provided." }),
          ),
          el("div", { class: "row", style: "gap:8px; flex-wrap:wrap;" }, editBtn, addVersionBtn, adminUser ? deleteBtn : null),
        ),
        editable || adminUser ? el("div", { class: "muted", text: editable ? "Write access granted" : "Read-only access" }) : null,
        editSection,
        addVersionSection,
        el("div", { class: "card", style: "margin-top:12px;" },
          el("h3", { text: "Metadata" }),
          el("div", { class: "row", style: "gap:12px; flex-wrap:wrap;" },
            el("div", {}, el("div", { class: "muted", text: "Created" }), el("div", { text: fmtDate(product.created_at) })),
            el("div", {}, el("div", { class: "muted", text: "Updated" }), el("div", { text: fmtDate(product.updated_at) })),
            el("div", {}, el("div", { class: "muted", text: "Owners" }), el("div", { text: (product.owners || []).map(ownerLabel).join(", ") || "None" })),
          ),
        ),
        el("div", { class: "card", style: "margin-top:12px;" },
          el("h3", { text: "Versions" }),
          el("table", { class: "table", style: "width:100%;" },
            el("thead", {}, el("tr", {},
              el("th", { text: "Version" }),
              el("th", { text: "Release" }),
              el("th", { text: "Status" }),
              el("th", { text: "Components" }),
              el("th", { text: "Actions" }),
            )),
            versionTableBody,
          ),
        ),
        el("div", { class: "card", style: "margin-top:12px;" },
          el("h3", { text: "Components by version" }),
          ...sortedVersions.map((version) => {
            const rows = componentMap.get(version.id) || [];
            return el("div", { style: "margin-bottom:12px;" },
              el("div", { style: "font-weight:600;" }, `Version ${version.version}`),
              !rows.length
                ? el("div", { class: "muted", text: "No components loaded." })
                : el("div", { style: "display:flex; flex-direction:column; gap:6px;" },
                    ...rows.slice(0, 30).map((component) =>
                      el("div", { style: "border:1px solid #e5e7eb; border-radius:8px; padding:8px;" },
                        el("div", { text: `${component.ecosystem || "pkg"} • ${component.name} ${component.version || ""}` }),
                        component.dependencies?.length
                          ? el("div", { class: "muted", text: `${component.dependencies.length} dependency links` })
                          : el("div", { class: "muted", text: "No dependency links" }),
                      ),
                    ),
                  ),
            );
          }),
        ),
        el("div", { class: "card", style: "margin-top:12px;" },
          el("h3", { text: "Linked vulnerabilities" }),
          !linkedVulns.length
            ? el("div", { class: "muted", text: "No linked vulnerabilities found through component matching." })
            : el("div", { style: "display:flex; flex-direction:column; gap:8px;" },
                ...linkedVulns.map((entry) =>
                  el("div", { style: "border:1px solid #e5e7eb; border-radius:8px; padding:8px;" },
                    el("div", { style: "font-weight:600;", text: entry.vuln.title || `Vulnerability ${entry.vuln.id}` }),
                    el("div", { class: "muted", text: `${entry.vuln.severity || "-"} • ${entry.vuln.status || "-"}` }),
                    el("div", { class: "muted", text: `Matched components: ${[...new Set(entry.components)].slice(0, 4).join(", ")}` }),
                    el("button", { class: "btn", type: "button", onClick: () => navigate(`/vulnerabilities/${entry.vuln.id}`) }, "Open vulnerability"),
                  ),
                ),
              ),
        ),
      );
    } catch (err) {
      content.innerHTML = "";
      content.append(
        el("h2", { text: "Unable to load product" }),
        el("p", { class: "muted", text: err?.message || "Product details are unavailable." }),
      );
    }
  }

  root.append(header, content);
  await render();
  return root;
}
