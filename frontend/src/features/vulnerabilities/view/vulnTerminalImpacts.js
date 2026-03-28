import { el } from "../../../ui/dom/el.js";
import { toast } from "../../../ui/components/toast.js";
import {
  updateVulnerabilityTerminalImpact,
  deleteVulnerabilityTerminalImpact,
  attachVulnerabilityTerminalImpacts,
} from "../../../api/vulnerabilities.js";
import { ensureTerminalImpacts } from "./vulnShared.js";

function renderTerminalImpactRow(mapping, vulnId, reloadDetails, canEdit) {
  const impactSelect = el("select", { class: "input" });
  const saveBtn = el("button", { class: "btn primary", type: "button" }, "Save");
  const deleteBtn = el("button", { class: "btn text-danger", type: "button" }, "Remove");

  const fillImpactOptions = async () => {
    const impacts = await ensureTerminalImpacts();
    impactSelect.innerHTML = "";
    impacts.forEach((impact) => {
      impactSelect.appendChild(
        el("option", { value: impact.id, text: impact.name, selected: impact.id === mapping.terminal_impact_id })
      );
    });
  };

  fillImpactOptions();

  if (canEdit) {
    saveBtn.addEventListener("click", async () => {
      const terminalImpactId = impactSelect.value ? Number(impactSelect.value) : null;
      if (!terminalImpactId) {
        toast({ title: "Select impact", message: "Choose a terminal impact to save." });
        return;
      }
      saveBtn.disabled = true;
      deleteBtn.disabled = true;
      saveBtn.textContent = "Saving...";
      try {
        await updateVulnerabilityTerminalImpact(vulnId, mapping.id, { terminal_impact_id: terminalImpactId });
        toast({ title: "Mapping updated", message: `${mapping.terminal_impact_name || "Terminal impact"} updated.` });
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
      if (!confirm("Remove this terminal impact mapping?")) return;
      saveBtn.disabled = true;
      deleteBtn.disabled = true;
      try {
        await deleteVulnerabilityTerminalImpact(vulnId, mapping.id);
        toast({ title: "Mapping removed", message: `${mapping.terminal_impact_name || "Terminal impact"} removed.` });
        await reloadDetails();
      } catch (err) {
        toast({ title: "Failed", message: err?.message || "Unable to remove mapping" });
      } finally {
        saveBtn.disabled = false;
        deleteBtn.disabled = false;
      }
    });
  } else {
    impactSelect.disabled = true;
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
        el("div", { class: "font-semibold", text: mapping.terminal_impact_name || "Terminal impact" }),
        mapping.terminal_impact_description ? el("div", { class: "muted", text: mapping.terminal_impact_description }) : null,
      ),
      canEdit ? el("div", { class: "row flex-row-6" }, deleteBtn, saveBtn) : null,
    ),
    el("div", { class: "flex-1", style: "min-width: 200px;" }, el("div", { class: "muted", text: "Terminal impact" }), impactSelect),
  );
}

export function renderTerminalImpactsSection(detailData, vulnId, reloadDetails, canEdit) {
  const container = el("div", {});
  const list = el("div", { class: "flex-col-8" });

  if (!detailData.terminal_impacts?.length) {
    list.appendChild(el("div", { class: "muted", text: "No terminal impacts linked." }));
  } else {
    detailData.terminal_impacts.forEach((m) => list.appendChild(renderTerminalImpactRow(m, vulnId, reloadDetails, canEdit)));
  }

  container.appendChild(el("h4", { text: "Terminal impacts" }));
  container.appendChild(list);

  if (canEdit) {
    const impactSelect = el("select", { class: "input", multiple: "true", size: "6" });
    const addBtn = el("button", { class: "btn primary", type: "button" }, "Attach terminal impacts");

    const refreshOptions = async () => {
      const impacts = await ensureTerminalImpacts();
      const existingIds = new Set((detailData.terminal_impacts || []).map((m) => m.terminal_impact_id));
      impactSelect.innerHTML = "";
      if (!impacts.length) {
        impactSelect.appendChild(el("option", { text: "No terminal impacts available", disabled: "true" }));
      } else {
        impacts
          .filter((impact) => !existingIds.has(impact.id))
          .forEach((impact) => impactSelect.appendChild(el("option", { value: impact.id, text: impact.name })));
      }
    };

    addBtn.addEventListener("click", async () => {
      const ids = Array.from(impactSelect.selectedOptions || []).map((o) => Number(o.value));
      if (!ids.length) {
        toast({ title: "Select terminal impacts", message: "Choose at least one terminal impact to attach." });
        return;
      }
      addBtn.disabled = true;
      addBtn.textContent = "Attaching...";
      try {
        await attachVulnerabilityTerminalImpacts(vulnId, ids);
        toast({ title: "Attached", message: `${ids.length} terminal impact(s) linked.` });
        await reloadDetails();
        await refreshOptions();
      } catch (err) {
        toast({ title: "Failed", message: err?.message || "Unable to attach terminal impacts" });
      } finally {
        addBtn.disabled = false;
        addBtn.textContent = "Attach terminal impacts";
      }
    });

    refreshOptions();

    container.appendChild(el("div", { class: "divider", style: "margin: 10px 0;" }));
    container.appendChild(
      el(
        "div",
        { class: "flex-col-8" },
        el("div", { class: "muted", text: "Link terminal impacts" }),
        impactSelect,
        el("div", { class: "row flex-end" }, addBtn),
      )
    );
  }

  return container;
}
