import { el } from "../../../ui/dom/el.js";
import { toast } from "../../../ui/components/toast.js";
import {
  getVulnerability,
  updateVulnerability,
  deleteVulnerability,
} from "../../../api/vulnerabilities.js";
import { getState } from "../../../state/store.js";
import { canWrite, isAdmin } from "../../../state/permissions.js";
import { navigate } from "../../../router/router.js";
import { formatDate, formatDateTime } from "../selectors/formatters.js";
import {
  STATUS_OPTIONS,
  SEVERITY_OPTIONS,
  ATTACK_COMPLEXITY_OPTIONS,
  IMPACT_OPTIONS,
  severityBadge,
  slaBadge,
  statusPill,
} from "./vulnShared.js";
import { renderVersionsSection } from "./vulnVersions.js";
import { renderAttackVectorsSection } from "./vulnAttackVectors.js";
import { renderTerminalImpactsSection } from "./vulnTerminalImpacts.js";

export function renderVulnerabilityCard(vuln, reloadList, options = {}) {
  const { autoOpen = false, writable = false, selectedIds = null, onToggleSelect = null } = options;
  const detailContent = el("div", {});
  const detailCard = el("div", { class: "card", style: "padding: 12px; margin-top: 8px; display: none;" }, detailContent);
  let detailData = null;
  let isEditing = false;
  const canEdit = canWrite(getState());

  const viewBtn = el("button", { class: "btn" }, "View");
  const editBtn = el("button", { class: "btn" }, "Edit");

  async function loadDetails(force = false) {
    if (detailData && !force) return detailData;
    detailContent.innerHTML = "";
    detailContent.appendChild(el("div", { class: "muted", text: "Loading vulnerability details..." }));
    try {
      detailData = await getVulnerability(vuln.id);
      renderDetails();
      return detailData;
    } catch (e) {
      detailContent.innerHTML = "";
      toast({ title: "Failed to load", message: e?.message || "Unable to fetch vulnerability" });
      detailContent.appendChild(el("div", { class: "muted", text: "Unable to load vulnerability details." }));
      throw e;
    }
  }

  async function renderEditSection() {
    const titleInput = el("input", { class: "input", value: detailData.title || "", required: "true" });
    const cveInput = el("input", { class: "input", value: detailData.cve_id || "", placeholder: "CVE-2024-0001" });
    const severitySelect = el(
      "select",
      { class: "input" },
      ...SEVERITY_OPTIONS.map((s) => el("option", { value: s, text: s, selected: s === detailData.severity }))
    );
    const attackComplexitySelect = el(
      "select",
      { class: "input" },
      ...ATTACK_COMPLEXITY_OPTIONS.map((c) => el("option", { value: c, text: c, selected: c === detailData.attack_complexity }))
    );
    const confidentialitySelect = el(
      "select",
      { class: "input" },
      ...IMPACT_OPTIONS.map((i) => el("option", { value: i, text: i, selected: i === detailData.confidentiality_impact }))
    );
    const integritySelect = el(
      "select",
      { class: "input" },
      ...IMPACT_OPTIONS.map((i) => el("option", { value: i, text: i, selected: i === detailData.integrity_impact }))
    );
    const availabilitySelect = el(
      "select",
      { class: "input" },
      ...IMPACT_OPTIONS.map((i) => el("option", { value: i, text: i, selected: i === detailData.availability_impact }))
    );
    const statusSelect = el(
      "select",
      { class: "input" },
      ...STATUS_OPTIONS.map((s) => el("option", { value: s, text: s, selected: s === detailData.status }))
    );
    const cvssInput = el("input", { class: "input", type: "number", step: "0.1", min: "0", max: "10", value: detailData.cvss_score ?? "" });
    const publishedInput = el("input", { class: "input", type: "date", value: detailData.published_date ? detailData.published_date.slice(0, 10) : "" });
    const modifiedInput = el("input", { class: "input", type: "date", value: detailData.last_modified_date ? detailData.last_modified_date.slice(0, 10) : "" });
    const descInput = el("textarea", { class: "input", value: detailData.description || "" });

    const cancelBtn = el("button", { class: "btn", type: "button" }, "Cancel");
    const saveBtn = el("button", { class: "btn primary", type: "submit" }, "Save changes");

    const form = el(
      "form",
      { style: "display: flex; flex-direction: column; gap: 10px; margin-top: 8px;" },
      el("div", {}, el("div", { class: "muted", text: "Title" }), titleInput),
      el("div", {}, el("div", { class: "muted", text: "CVE" }), cveInput),
      el("div", { class: "row", style: "gap: 10px; flex-wrap: wrap;" },
        el("div", { style: "flex: 1; min-width: 180px;" }, el("div", { class: "muted", text: "Severity" }), severitySelect),
        el("div", { style: "flex: 1; min-width: 180px;" }, el("div", { class: "muted", text: "Attack complexity" }), attackComplexitySelect),
        el("div", { style: "flex: 1; min-width: 180px;" }, el("div", { class: "muted", text: "Confidentiality impact" }), confidentialitySelect),
        el("div", { style: "flex: 1; min-width: 180px;" }, el("div", { class: "muted", text: "Integrity impact" }), integritySelect),
        el("div", { style: "flex: 1; min-width: 180px;" }, el("div", { class: "muted", text: "Availability impact" }), availabilitySelect),
        el("div", { style: "flex: 1; min-width: 180px;" }, el("div", { class: "muted", text: "Status" }), statusSelect),
        el("div", { style: "flex: 1; min-width: 120px;" }, el("div", { class: "muted", text: "CVSS" }), cvssInput),
      ),
      el("div", { class: "row", style: "gap: 10px; flex-wrap: wrap;" },
        el("div", { style: "flex: 1; min-width: 180px;" }, el("div", { class: "muted", text: "Published" }), publishedInput),
        el("div", { style: "flex: 1; min-width: 180px;" }, el("div", { class: "muted", text: "Last modified" }), modifiedInput),
      ),
      el("div", {}, el("div", { class: "muted", text: "Description" }), descInput),
      el("div", { class: "row", style: "justify-content: flex-end; gap: 8px;" }, cancelBtn, saveBtn),
    );

    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      const title = titleInput.value.trim();
      if (!title) {
        toast({ title: "Title required", message: "Please provide a vulnerability title." });
        return;
      }
      saveBtn.disabled = true;
      cancelBtn.disabled = true;
      saveBtn.textContent = "Saving...";
      try {
        await updateVulnerability(vuln.id, {
          title,
          cve_id: cveInput.value.trim() || undefined,
          severity: severitySelect.value,
          attack_complexity: attackComplexitySelect.value,
          confidentiality_impact: confidentialitySelect.value,
          integrity_impact: integritySelect.value,
          availability_impact: availabilitySelect.value,
          status: statusSelect.value,
          cvss_score: cvssInput.value || undefined,
          published_date: publishedInput.value || undefined,
          last_modified_date: modifiedInput.value || undefined,
          description: descInput.value,
        });
        toast({ title: "Updated", message: `${title} saved.` });
        isEditing = false;
        await loadDetails(true);
        await reloadList();
      } catch (err) {
        toast({ title: "Failed", message: err?.message || "Unable to update vulnerability" });
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

    return el("div", { class: "card" }, el("h4", { text: "Edit vulnerability" }), form);
  }

  function renderDetails() {
    detailContent.innerHTML = "";
    if (!detailData) return;

    const meta = el(
      "div",
      { class: "row", style: "gap: 12px; flex-wrap: wrap; margin-bottom: 8px; align-items: center;" },
      severityBadge(detailData.severity || "Unknown"),
      statusPill(detailData.status || "Open"),
      slaBadge(detailData.sla_state),
      detailData.cvss_score !== null && detailData.cvss_score !== undefined
        ? el("div", {}, el("div", { class: "muted", text: "CVSS" }), el("div", { text: detailData.cvss_score }))
        : null,
      el("div", {}, el("div", { class: "muted", text: "Attack complexity" }), el("div", { text: detailData.attack_complexity || "Not Defined" })),
      el("div", {}, el("div", { class: "muted", text: "Confidentiality impact" }), el("div", { text: detailData.confidentiality_impact || "Not Defined" })),
      el("div", {}, el("div", { class: "muted", text: "Integrity impact" }), el("div", { text: detailData.integrity_impact || "Not Defined" })),
      el("div", {}, el("div", { class: "muted", text: "Availability impact" }), el("div", { text: detailData.availability_impact || "Not Defined" })),
      el("div", {}, el("div", { class: "muted", text: "Published" }), el("div", { text: formatDate(detailData.published_date) })),
      el("div", {}, el("div", { class: "muted", text: "Last modified" }), el("div", { text: formatDate(detailData.last_modified_date) })),
      el("div", {}, el("div", { class: "muted", text: "Updated" }), el("div", { text: formatDate(detailData.updated_at) })),
      el("div", {}, el("div", { class: "muted", text: "SLA due" }), el("div", { text: formatDateTime(detailData.sla_due_at) })),
    );

    const description = detailData.description
      ? el("p", { text: detailData.description })
      : el("p", { class: "muted", text: "No description provided." });

    const actionRow = canEdit
      ? el(
          "div",
          { class: "row", style: "gap: 8px; justify-content: flex-end; flex-wrap: wrap;" },
          el("button", { class: "btn", type: "button", onclick: async () => { isEditing = !isEditing; await loadDetails(); renderDetails(); } }, isEditing ? "Close editor" : "Edit details"),
          isAdmin(getState())
            ? (() => {
                const delBtn = el("button", { class: "btn", style: "color: #b91c1c;" }, "Delete");
                delBtn.addEventListener("click", async () => {
                  if (!confirm(`Delete ${detailData.title}? This cannot be undone.`)) return;
                  try {
                    await deleteVulnerability(vuln.id);
                    toast({ title: "Deleted", message: `${detailData.title} removed.` });
                    await reloadList();
                    detailCard.remove();
                  } catch (err) {
                    toast({ title: "Failed", message: err?.message || "Unable to delete vulnerability" });
                  }
                });
                return delBtn;
              })()
            : null,
        )
      : null;

    detailContent.append(
      el("h3", { text: detailData.title }),
      detailData.cve_id ? el("div", { class: "muted", text: detailData.cve_id }) : null,
      meta,
      description,
      renderVersionsSection(detailData, vuln.id, () => loadDetails(true), canEdit),
      renderAttackVectorsSection(detailData, vuln.id, () => loadDetails(true), canEdit),
      renderTerminalImpactsSection(detailData, vuln.id, () => loadDetails(true), canEdit),
      actionRow,
    );

    if (canEdit && isEditing) {
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
    if (!canEdit) return;
    isEditing = true;
    await loadDetails();
    detailCard.style.display = "block";
    renderDetails();
    viewBtn.textContent = "Hide";
  });

  if (!canEdit) editBtn.style.display = "none";

  const selectionCheckbox = writable
    ? el("input", {
      type: "checkbox",
      checked: selectedIds?.has(vuln.id) || false,
      onChange: (event) => onToggleSelect?.(vuln.id, event.target.checked),
      title: "Select vulnerability",
    })
    : null;

  const header = el(
    "div",
    { class: "card", style: "padding: 12px;" },
    el(
      "div",
      { class: "row", style: "justify-content: space-between; align-items: baseline; gap: 8px;" },
      el(
        "div",
        { class: "row", style: "gap: 8px; align-items: flex-start;" },
        selectionCheckbox,
        el(
          "div",
          {},
          el("div", { class: "muted", text: vuln.cve_id || `VULN-${vuln.id}` }),
          el("div", { style: "font-weight: 600;", text: vuln.title }),
        ),
      ),
      el("div", { class: "row", style: "gap: 6px;" },
        el("button", { class: "btn", type: "button", onClick: () => navigate(`/vulnerabilities/${vuln.id}`) }, "Open page"),
        viewBtn,
        editBtn
      ),
    ),
    el(
      "div",
      { class: "row", style: "gap: 12px; flex-wrap: wrap; margin-top: 6px; align-items: center;" },
      severityBadge(vuln.severity || "Medium"),
      statusPill(vuln.status || "Open"),
      slaBadge(vuln.sla_state),
      el("div", {}, el("div", { class: "muted", text: "CVSS" }), el("div", { text: vuln.cvss_score ?? "-" })),
      el("div", {}, el("div", { class: "muted", text: "Attack complexity" }), el("div", { text: vuln.attack_complexity || "Not Defined" })),
      el("div", {}, el("div", { class: "muted", text: "Confidentiality impact" }), el("div", { text: vuln.confidentiality_impact || "Not Defined" })),
      el("div", {}, el("div", { class: "muted", text: "Integrity impact" }), el("div", { text: vuln.integrity_impact || "Not Defined" })),
      el("div", {}, el("div", { class: "muted", text: "Availability impact" }), el("div", { text: vuln.availability_impact || "Not Defined" })),
      el("div", {}, el("div", { class: "muted", text: "Updated" }), el("div", { text: formatDate(vuln.updated_at) })),
    ),
  );

  const card = el("div", {}, header, detailCard);

  if (autoOpen) {
    loadDetails().then(() => {
      detailCard.style.display = "block";
      viewBtn.textContent = "Hide";
      card.scrollIntoView({ behavior: "smooth", block: "start" });
    }).catch(() => {});
  }

  return card;
}
