import { el } from "../../../ui/dom/el.js";
import { toast } from "../../../ui/components/toast.js";
import {
  updateVulnerabilityAttackVector,
  deleteVulnerabilityAttackVector,
  attachVulnerabilityAttackVectors,
} from "../../../api/vulnerabilities.js";
import { ensureAttackVectors, ensureProductVersions } from "./vulnShared.js";

function renderAttackVectorRow(mapping, vulnId, reloadDetails, canEdit) {
  const productSelect = el("select", { class: "input" },
    el("option", { value: "", text: "No specific version" }),
  );
  const saveBtn = el("button", { class: "btn primary", type: "button" }, "Save");
  const deleteBtn = el("button", { class: "btn", type: "button", style: "color: #b91c1c;" }, "Remove");

  const fillProductOptions = async () => {
    const options = await ensureProductVersions();
    productSelect.querySelectorAll("option[value]").forEach((opt) => opt.remove());
    options.forEach((pv) => {
      productSelect.appendChild(
        el("option", { value: pv.id, text: `${pv.product_name || "Product"} ${pv.version}` })
      );
    });
    productSelect.value = mapping.product_version_id ? String(mapping.product_version_id) : "";
  };

  fillProductOptions();

  if (canEdit) {
    saveBtn.addEventListener("click", async () => {
      saveBtn.disabled = true;
      deleteBtn.disabled = true;
      saveBtn.textContent = "Saving...";
      try {
        await updateVulnerabilityAttackVector(vulnId, mapping.id, {
          product_version_id: productSelect.value ? Number(productSelect.value) : null,
        });
        toast({ title: "Mapping updated", message: `${mapping.attack_vector_name || "Attack vector"} updated.` });
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
      if (!confirm("Remove this attack vector mapping?")) return;
      saveBtn.disabled = true;
      deleteBtn.disabled = true;
      try {
        await deleteVulnerabilityAttackVector(vulnId, mapping.id);
        toast({ title: "Mapping removed", message: `${mapping.attack_vector_name || "Attack vector"} removed.` });
        await reloadDetails();
      } catch (err) {
        toast({ title: "Failed", message: err?.message || "Unable to remove mapping" });
      } finally {
        saveBtn.disabled = false;
        deleteBtn.disabled = false;
      }
    });
  } else {
    productSelect.disabled = true;
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
        el("div", { style: "font-weight: 600;", text: mapping.attack_vector_name || "Attack vector" }),
        mapping.attack_vector_description ? el("div", { class: "muted", text: mapping.attack_vector_description }) : null,
      ),
      canEdit ? el("div", { class: "row", style: "gap: 6px; align-items: center;" }, deleteBtn, saveBtn) : null,
    ),
    el(
      "div",
      { style: "flex: 1; min-width: 200px;" },
      el("div", { class: "muted", text: "Product version" }),
      productSelect,
    ),
  );
}

export function renderAttackVectorsSection(detailData, vulnId, reloadDetails, canEdit) {
  const container = el("div", {});
  const list = el("div", { style: "display: flex; flex-direction: column; gap: 8px;" });

  if (!detailData.attack_vectors?.length) {
    list.appendChild(el("div", { class: "muted", text: "No attack vectors linked." }));
  } else {
    detailData.attack_vectors.forEach((m) => list.appendChild(renderAttackVectorRow(m, vulnId, reloadDetails, canEdit)));
  }

  container.appendChild(el("h4", { text: "Attack vectors" }));
  container.appendChild(list);

  if (canEdit) {
    const vectorSelect = el("select", { class: "input" });
    const versionSelect = el("select", { class: "input" },
      el("option", { value: "", text: "No specific version" }),
    );
    const addBtn = el("button", { class: "btn primary", type: "button" }, "Attach attack vector");

    const refreshOptions = async () => {
      const vectors = await ensureAttackVectors();
      const versions = await ensureProductVersions();
      const existingIds = new Set((detailData.attack_vectors || []).map((m) => m.attack_vector_id));

      vectorSelect.innerHTML = "";
      if (!vectors.length) {
        vectorSelect.appendChild(el("option", { text: "No attack vectors available", disabled: "true" }));
      } else {
        vectors
          .filter((v) => !existingIds.has(v.id))
          .forEach((v) => vectorSelect.appendChild(el("option", { value: v.id, text: v.name })));
      }

      versionSelect.querySelectorAll("option[value]").forEach((opt) => opt.remove());
      versions.forEach((pv) => {
        versionSelect.appendChild(
          el("option", { value: pv.id, text: `${pv.product_name || "Product"} ${pv.version}` })
        );
      });
    };

    addBtn.addEventListener("click", async () => {
      const attackVectorId = vectorSelect.value ? Number(vectorSelect.value) : null;
      if (!attackVectorId) {
        toast({ title: "Select attack vector", message: "Choose an attack vector to attach." });
        return;
      }
      addBtn.disabled = true;
      addBtn.textContent = "Attaching...";
      try {
        await attachVulnerabilityAttackVectors(vulnId, [{
          attack_vector_id: attackVectorId,
          product_version_id: versionSelect.value ? Number(versionSelect.value) : null,
        }]);
        toast({ title: "Attached", message: "Attack vector linked." });
        await reloadDetails();
        await refreshOptions();
      } catch (err) {
        toast({ title: "Failed", message: err?.message || "Unable to attach attack vector" });
      } finally {
        addBtn.disabled = false;
        addBtn.textContent = "Attach attack vector";
      }
    });

    refreshOptions();

    container.appendChild(el("div", { class: "divider", style: "margin: 10px 0; height: 1px; background: #e5e7eb;" }));
    container.appendChild(
      el(
        "div",
        { style: "display: flex; flex-direction: column; gap: 8px;" },
        el("div", { class: "muted", text: "Link an attack vector" }),
        vectorSelect,
        el("div", { class: "muted", text: "Map to a product version (optional)" }),
        versionSelect,
        el("div", { class: "row", style: "justify-content: flex-end;" }, addBtn),
      )
    );
  }

  return container;
}
