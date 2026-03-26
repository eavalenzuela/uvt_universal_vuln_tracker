import { el } from "../../../ui/dom/el.js";
import { toast } from "../../../ui/components/toast.js";
import {
  updateVulnerabilityVersion,
  deleteVulnerabilityVersion,
  attachVulnerabilityVersions,
} from "../../../api/vulnerabilities.js";
import { formatDate } from "../selectors/formatters.js";
import { MITIGATION_OPTIONS, ensureProductVersions } from "./vulnShared.js";

function renderVersionRow(mapping, vulnId, reloadDetails, canEdit) {
  const affectedToggle = el("input", { type: "checkbox", checked: mapping.affected });
  const fixedInput = el("input", { class: "input", value: mapping.fixed_in_version || "", placeholder: "Fixed in version" });
  const mitigationSelect = el(
    "select",
    { class: "input" },
    ...MITIGATION_OPTIONS.map((m) => el("option", { value: m, text: m, selected: m === mapping.mitigation_status })),
  );
  const notesInput = el("textarea", { class: "input", value: mapping.notes || "", placeholder: "Notes" });

  const saveBtn = el("button", { class: "btn primary", type: "button" }, "Save");
  const deleteBtn = el("button", { class: "btn", type: "button", style: "color: #b91c1c;" }, "Remove");

  if (canEdit) {
    saveBtn.addEventListener("click", async () => {
      saveBtn.disabled = true;
      deleteBtn.disabled = true;
      saveBtn.textContent = "Saving...";
      try {
        await updateVulnerabilityVersion(vulnId, mapping.id, {
          affected: affectedToggle.checked,
          fixed_in_version: fixedInput.value || undefined,
          mitigation_status: mitigationSelect.value || undefined,
          notes: notesInput.value || undefined,
        });
        toast({ title: "Mapping updated", message: `${mapping.version} updated.` });
        await reloadDetails();
      } catch (err) {
        toast({ title: "Failed", message: err?.message || "Unable to update mapping" });
      } finally {
        saveBtn.disabled = false;
        deleteBtn.disabled = false;
        saveBtn.textContent = "Save";
      }
    });

    deleteBtn.addEventListener("click", async () => {
      if (!confirm("Remove this product version from the vulnerability?")) return;
      saveBtn.disabled = true;
      deleteBtn.disabled = true;
      try {
        await deleteVulnerabilityVersion(vulnId, mapping.id);
        toast({ title: "Version detached", message: `${mapping.version || "Version"} removed.` });
        await reloadDetails();
      } catch (err) {
        toast({ title: "Failed", message: err?.message || "Unable to remove mapping" });
      } finally {
        saveBtn.disabled = false;
        deleteBtn.disabled = false;
      }
    });
  } else {
    affectedToggle.disabled = true;
    fixedInput.disabled = true;
    mitigationSelect.disabled = true;
    notesInput.disabled = true;
  }

  return el(
    "div",
    { class: "card", style: "padding: 10px; display: flex; flex-direction: column; gap: 8px;" },
    el(
      "div",
      { class: "row", style: "justify-content: space-between; gap: 8px;" },
      el(
        "div",
        {},
        el("div", { class: "muted", text: mapping.product_name || "Product" }),
        el("div", { style: "font-weight: 600;", text: mapping.version || "Version" }),
        mapping.release_date ? el("div", { class: "muted", text: `Released ${formatDate(mapping.release_date)}` }) : null,
      ),
      canEdit
        ? el("div", { class: "row", style: "gap: 6px; align-items: center;" }, deleteBtn, saveBtn)
        : null,
    ),
    el(
      "div",
      { class: "row", style: "gap: 8px; flex-wrap: wrap; align-items: center;" },
      el(
        "label",
        { class: "row", style: "gap: 6px; align-items: center;" },
        affectedToggle,
        el("span", { text: "Affected" }),
      ),
      el("div", { style: "flex: 1; min-width: 180px;" }, el("div", { class: "muted", text: "Fixed in" }), fixedInput),
      el("div", { style: "flex: 1; min-width: 180px;" }, el("div", { class: "muted", text: "Mitigation" }), mitigationSelect),
    ),
    el("div", {}, el("div", { class: "muted", text: "Notes" }), notesInput),
  );
}

export function renderVersionsSection(detailData, vulnId, reloadDetails, canEdit) {
  const container = el("div", {});
  const list = el("div", { style: "display: flex; flex-direction: column; gap: 8px;" });

  if (!detailData.affected_versions?.length) {
    list.appendChild(el("div", { class: "muted", text: "No affected product versions linked." }));
  } else {
    detailData.affected_versions.forEach((m) => list.appendChild(renderVersionRow(m, vulnId, reloadDetails, canEdit)));
  }

  container.appendChild(el("h4", { text: "Affected product versions" }));
  container.appendChild(list);

  if (canEdit) {
    const select = el("select", { class: "input", multiple: "true", size: "6" });
    const addBtn = el("button", { class: "btn primary", type: "button" }, "Attach versions");
    const refreshOptions = async () => {
      const options = await ensureProductVersions();
      const existingIds = new Set((detailData.affected_versions || []).map((m) => m.product_version_id));
      select.innerHTML = "";
      if (!options.length) {
        select.appendChild(el("option", { text: "No product versions available", disabled: "true" }));
        return;
      }
      options
        .filter((pv) => !existingIds.has(pv.id))
        .forEach((pv) => {
          select.appendChild(
            el("option", { value: pv.id, text: `${pv.product_name || "Product"} ${pv.version}` })
          );
        });
    };

    addBtn.addEventListener("click", async () => {
      const ids = Array.from(select.selectedOptions || []).map((o) => Number(o.value));
      if (!ids.length) {
        toast({ title: "Select versions", message: "Choose at least one product version to attach." });
        return;
      }
      addBtn.disabled = true;
      addBtn.textContent = "Attaching...";
      try {
        await attachVulnerabilityVersions(vulnId, ids);
        toast({ title: "Attached", message: `${ids.length} version(s) linked.` });
        await reloadDetails();
        await refreshOptions();
      } catch (err) {
        toast({ title: "Failed", message: err?.message || "Unable to attach versions" });
      } finally {
        addBtn.disabled = false;
        addBtn.textContent = "Attach versions";
      }
    });

    refreshOptions();

    container.appendChild(el("div", { class: "divider", style: "margin: 10px 0; height: 1px; background: #e5e7eb;" }));
    container.appendChild(
      el(
        "div",
        { style: "display: flex; flex-direction: column; gap: 8px;" },
        el("div", { class: "muted", text: "Link additional product versions" }),
        select,
        el("div", { class: "row", style: "justify-content: flex-end;" }, addBtn),
      )
    );
  }

  return container;
}
