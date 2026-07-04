import { el } from "../../../ui/dom/el.js";
import { toast } from "../../../ui/components/toast.js";
import { confirmModal } from "../../../ui/components/modal.js";
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
  const deleteBtn = el("button", { class: "btn text-danger", type: "button" }, "Remove");

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
      if (!(await confirmModal({ title: "Remove mapping", message: "Remove this attack vector mapping?", confirmText: "Remove", danger: true }))) return;
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
    { class: "card p-10 flex-col-8" },
    el(
      "div",
      { class: "row flex-between gap-8" },
      el(
        "div",
        {},
        el("div", { class: "font-semibold", text: mapping.attack_vector_name || "Attack vector" }),
        mapping.attack_vector_description ? el("div", { class: "muted", text: mapping.attack_vector_description }) : null,
      ),
      canEdit ? el("div", { class: "row flex-row-6" }, deleteBtn, saveBtn) : null,
    ),
    el(
      "div",
      { class: "flex-1", style: "min-width: 200px;" },
      el("div", { class: "muted", text: "Product version" }),
      productSelect,
    ),
  );
}

export function renderAttackVectorsSection(detailData, vulnId, reloadDetails, canEdit) {
  const container = el("div", {});
  const list = el("div", { class: "flex-col-8" });

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

    container.appendChild(el("div", { class: "divider", style: "margin: 10px 0;" }));
    container.appendChild(
      el(
        "div",
        { class: "flex-col-8" },
        el("div", { class: "muted", text: "Link an attack vector" }),
        vectorSelect,
        el("div", { class: "muted", text: "Map to a product version (optional)" }),
        versionSelect,
        el("div", { class: "row flex-end" }, addBtn),
      )
    );
  }

  return container;
}
