import { el } from "../../../ui/dom/el.js";
import { toast } from "../../../ui/components/toast.js";
import { confirmModal, promptModal } from "../../../ui/components/modal.js";
import {
  listVulnerabilities,
  createVulnerability,
  batchUpdateVulnerabilities,
  listSavedVulnerabilityFilters,
  getDefaultVulnerabilityFilter,
  createSavedVulnerabilityFilter,
  updateSavedVulnerabilityFilter,
  deleteSavedVulnerabilityFilter,
} from "../../../api/vulnerabilities.js";
import { getState } from "../../../state/store.js";
import { canWrite, isAdmin } from "../../../state/permissions.js";
import { downloadReportArtifact, exportVulnerabilities, waitForReportArtifact } from "../../../api/reports.js";
import { navigate } from "../../../router/router.js";
import { collectFilterValues, applyFilterValues } from "../selectors/filterNormalization.js";
import { createFilterRow } from "../../../ui/primitives/filters.js";
import {
  STATUS_OPTIONS,
  SEVERITY_OPTIONS,
  ATTACK_COMPLEXITY_OPTIONS,
  IMPACT_OPTIONS,
  ensureProductVersions,
} from "./vulnShared.js";
import { renderVulnerabilityCard } from "./vulnCard.js";

export async function VulnListView(params = {}) {
  const state = getState();
  const writable = canWrite(state);
  const targetId = params?.id ? Number(params.id) : null;

  const searchInput = el("input", { class: "input", type: "search", placeholder: "Search by title or CVE" });
  const statusSelect = el(
    "select",
    { class: "input" },
    el("option", { value: "", text: "Status" }),
    ...STATUS_OPTIONS.map((s) => el("option", { value: s, text: s }))
  );
  const severitySelect = el(
    "select",
    { class: "input" },
    el("option", { value: "", text: "Severity" }),
    ...SEVERITY_OPTIONS.map((s) => el("option", { value: s, text: s }))
  );
  const attackComplexitySelect = el(
    "select",
    { class: "input" },
    el("option", { value: "", text: "Attack complexity" }),
    ...ATTACK_COMPLEXITY_OPTIONS.map((c) => el("option", { value: c, text: c }))
  );
  const confidentialitySelect = el(
    "select",
    { class: "input" },
    el("option", { value: "", text: "Confidentiality impact" }),
    ...IMPACT_OPTIONS.map((c) => el("option", { value: c, text: c }))
  );
  const integritySelect = el(
    "select",
    { class: "input" },
    el("option", { value: "", text: "Integrity impact" }),
    ...IMPACT_OPTIONS.map((c) => el("option", { value: c, text: c }))
  );
  const availabilitySelect = el(
    "select",
    { class: "input" },
    el("option", { value: "", text: "Availability impact" }),
    ...IMPACT_OPTIONS.map((c) => el("option", { value: c, text: c }))
  );
  const componentEcosystemInput = el("input", { class: "input", placeholder: "Component ecosystem (e.g. npm)" });
  const componentNameInput = el("input", { class: "input", placeholder: "Component package name" });
  const componentDepthInput = el("input", { class: "input", type: "number", min: "0", placeholder: "Max transitive depth" });

  const list = el("div", { class: "flex-col-12 mt-8" },
    el("div", { class: "muted", text: "Loading vulnerabilities..." }),
  );
  const selectedIds = new Set();
  let currentItems = [];

  const selectAllCheckbox = el("input", { type: "checkbox" });
  const selectedCountLabel = el("span", { class: "muted", text: "0 selected" });
  const bulkSeveritySelect = el(
    "select",
    { class: "input max-w-170" },
    el("option", { value: "", text: "Severity (no change)" }),
    ...SEVERITY_OPTIONS.map((value) => el("option", { value, text: value })),
  );
  const bulkStatusSelect = el(
    "select",
    { class: "input max-w-170" },
    el("option", { value: "", text: "Status (no change)" }),
    ...STATUS_OPTIONS.map((value) => el("option", { value, text: value })),
  );
  const bulkAssigneeInput = el("input", { class: "input max-w-170", type: "number", min: "1", placeholder: "Assignee user ID" });
  const bulkSlaInput = el("input", { class: "input max-w-220", type: "datetime-local" });
  const applyBulkBtn = el("button", { class: "btn", type: "button" }, "Apply to selected");

  const bulkToolbar = el(
    "div",
    { class: "card mt-8 p-10 flex-row-8 flex-wrap items-center" },
    el("label", { class: "row gap-6 items-center" }, selectAllCheckbox, el("span", { text: "Select all on page" })),
    selectedCountLabel,
    bulkSeveritySelect,
    bulkStatusSelect,
    bulkAssigneeInput,
    bulkSlaInput,
    applyBulkBtn,
  );

  const refreshSelectionUi = () => {
    selectedCountLabel.textContent = `${selectedIds.size} selected`;
    if (!currentItems.length) {
      selectAllCheckbox.checked = false;
      selectAllCheckbox.indeterminate = false;
      return;
    }
    const selectedOnPage = currentItems.filter((item) => selectedIds.has(item.id)).length;
    selectAllCheckbox.checked = selectedOnPage > 0 && selectedOnPage === currentItems.length;
    selectAllCheckbox.indeterminate = selectedOnPage > 0 && selectedOnPage < currentItems.length;
  };

  const toggleSelection = (id, checked) => {
    if (checked) selectedIds.add(id);
    else selectedIds.delete(id);
    refreshSelectionUi();
  };

  selectAllCheckbox.addEventListener("change", () => {
    if (selectAllCheckbox.checked) {
      currentItems.forEach((item) => selectedIds.add(item.id));
    } else {
      currentItems.forEach((item) => selectedIds.delete(item.id));
    }
    load();
  });

  applyBulkBtn.addEventListener("click", async () => {
    if (!selectedIds.size) {
      toast({ title: "Nothing selected", message: "Select at least one vulnerability." });
      return;
    }

    const updates = {};
    if (bulkSeveritySelect.value) updates.severity = bulkSeveritySelect.value;
    if (bulkStatusSelect.value) updates.status = bulkStatusSelect.value;
    if (bulkAssigneeInput.value !== "") updates.assigned_to = Number(bulkAssigneeInput.value);
    if (bulkSlaInput.value) updates.sla_due_at = new Date(bulkSlaInput.value).toISOString();

    if (!Object.keys(updates).length) {
      toast({ title: "No changes selected", message: "Choose one or more fields to update." });
      return;
    }

    applyBulkBtn.disabled = true;
    try {
      const result = await batchUpdateVulnerabilities({
        vulnerability_ids: Array.from(selectedIds),
        ...updates,
      });
      const updatedCount = Number(result?.updated_count || 0);
      const missingCount = Number(result?.missing_count || 0);
      const skippedCount = Number(result?.skipped_count || 0);
      const failedCount = Number(result?.failed_count || 0);

      if (updatedCount > 0 && missingCount === 0 && skippedCount === 0 && failedCount === 0) {
        toast({ title: "Bulk update completed", message: `Updated ${updatedCount} vulnerabilities.` });
      }
      if (missingCount > 0 || skippedCount > 0 || failedCount > 0) {
        toast({
          title: "Bulk update partial",
          message: `Updated ${updatedCount}. Missing ${missingCount}. Unchanged ${skippedCount}. Failed ${failedCount}.`,
        });
      }
      if (updatedCount === 0 && missingCount === 0 && skippedCount === 0 && failedCount === 0) {
        toast({ title: "Bulk update", message: "No vulnerabilities were changed." });
      }

      selectedIds.clear();
      refreshSelectionUi();
      await load();
    } catch (e) {
      toast({ title: "Bulk update failed", message: e?.message || "Unable to apply bulk mutation" });
    } finally {
      applyBulkBtn.disabled = false;
    }
  });

  async function load() {
    list.innerHTML = "";
    list.appendChild(el("div", { class: "muted", text: "Loading vulnerabilities..." }));
    try {
      const data = await listVulnerabilities(collectFilterValues({
        searchInput,
        statusSelect,
        severitySelect,
        attackComplexitySelect,
        confidentialitySelect,
        integritySelect,
        availabilitySelect,
        componentEcosystemInput,
        componentNameInput,
        componentDepthInput,
      }));

      list.innerHTML = "";
      if (!data?.items?.length) {
        currentItems = [];
        refreshSelectionUi();
        list.appendChild(el("div", { class: "muted", text: "No vulnerabilities found." }));
        return;
      }

      currentItems = data.items || [];
      refreshSelectionUi();
      data.items.forEach((v) => list.appendChild(renderVulnerabilityCard(v, load, {
        autoOpen: targetId === v.id,
        writable,
        selectedIds,
        onToggleSelect: toggleSelection,
      })));
    } catch (e) {
      list.innerHTML = "";
      currentItems = [];
      refreshSelectionUi();
      toast({ title: "Failed to load", message: e?.message || "Unable to fetch vulnerabilities" });
      list.appendChild(el("div", { class: "muted", text: "Unable to load vulnerabilities." }));
    }
  }

  const applyBtn = el("button", { class: "btn" }, "Apply filters");
  applyBtn.addEventListener("click", load);

  const exportFormatSelect = el("select", { class: "input max-w-120" },
    el("option", { value: "csv", text: "CSV" }),
    el("option", { value: "json", text: "JSON" }),
    el("option", { value: "pdf", text: "PDF" }),
  );
  const pdfLayoutSelect = el("select", { class: "input max-w-180", style: "display: none;" },
    el("option", { value: "default", text: "Default layout" }),
    el("option", { value: "executive_summary", text: "Executive summary" }),
  );
  exportFormatSelect.addEventListener("change", () => {
    pdfLayoutSelect.style.display = exportFormatSelect.value === "pdf" ? "" : "none";
  });
  const exportBtn = el("button", { class: "btn", type: "button" }, "Export current view");
  exportBtn.addEventListener("click", async () => {
    exportBtn.disabled = true;
    const filters = collectFilterValues({
      searchInput,
      statusSelect,
      severitySelect,
      attackComplexitySelect,
      confidentialitySelect,
      integritySelect,
      availabilitySelect,
      componentEcosystemInput,
      componentNameInput,
      componentDepthInput,
    });
    try {
      const fmt = exportFormatSelect.value;
      const opts = fmt === "pdf" && pdfLayoutSelect ? { pdfLayout: pdfLayoutSelect.value } : {};
      const response = await exportVulnerabilities(filters, fmt, opts);
      let artifact = response?.artifact;
      if (!artifact) throw new Error("Export artifact missing");
      if (artifact.status && artifact.status !== "ready") {
        toast({ title: "Generating report", message: "Rendering PDF — this can take a few seconds…" });
        artifact = await waitForReportArtifact(artifact.id);
      }
      if (!artifact?.download_url) throw new Error("Export artifact missing download URL");
      const blob = await downloadReportArtifact(artifact.download_url);
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `vulnerabilities_export.${artifact.format || fmt}`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
      toast({ title: "Export ready", message: `Downloaded vulnerabilities ${String((artifact.format || fmt)).toUpperCase()}.` });
    } catch (e) {
      toast({ title: "Export failed", message: e?.message || "Unable to export vulnerabilities" });
    } finally {
      exportBtn.disabled = false;
    }
  });

  const savedFiltersSelect = el("select", { class: "input" },
    el("option", { value: "", text: "Saved filters" }),
  );
  const saveCurrentBtn = el("button", { class: "btn", type: "button" }, "Save current filter");
  const setDefaultBtn = el("button", { class: "btn", type: "button" }, "Set default");
  const deleteSavedBtn = el("button", { class: "btn", type: "button" }, "Delete saved");

  let savedFilters = [];
  const refreshSavedFilters = async () => {
    const result = await listSavedVulnerabilityFilters();
    savedFilters = Array.isArray(result) ? result : result?.items || [];
    const selected = savedFiltersSelect.value;
    savedFiltersSelect.innerHTML = "";
    savedFiltersSelect.appendChild(el("option", { value: "", text: "Saved filters" }));
    savedFilters.forEach((item) => {
      const owner = item?.owner?.username ? ` (${item.owner.username})` : "";
      const sharedFlag = item.visibility === "shared" ? " [shared]" : "";
      savedFiltersSelect.appendChild(el("option", { value: String(item.id), text: `${item.name}${sharedFlag}${owner}` }));
    });
    if (savedFilters.some((item) => String(item.id) === selected)) {
      savedFiltersSelect.value = selected;
    }
  };

  saveCurrentBtn.addEventListener("click", async () => {
    const name = await promptModal({ title: "Save filter", inputLabel: "Filter name", placeholder: "Name for this saved filter", required: true });
    if (name === null) return;
    const visibility = (await promptModal({ title: "Filter visibility", inputLabel: "Visibility", defaultValue: "private", message: "Enter 'private' or 'shared'." }) || "private").toLowerCase();
    try {
      await createSavedVulnerabilityFilter({
        name: name.trim(),
        filter_json: collectFilterValues({
          searchInput,
          statusSelect,
          severitySelect,
          attackComplexitySelect,
          confidentialitySelect,
          integritySelect,
          availabilitySelect,
          componentEcosystemInput,
          componentNameInput,
          componentDepthInput,
        }),
        visibility,
      });
      await refreshSavedFilters();
      toast({ title: "Saved", message: "Filter preset saved." });
    } catch (e) {
      toast({ title: "Save failed", message: e?.message || "Unable to save filter preset" });
    }
  });

  savedFiltersSelect.addEventListener("change", async () => {
    const id = Number(savedFiltersSelect.value);
    if (!id) return;
    const selected = savedFilters.find((f) => f.id === id);
    if (!selected) return;
    applyFilterValues(selected.filter_json || {}, {
      searchInput,
      statusSelect,
      severitySelect,
      attackComplexitySelect,
      confidentialitySelect,
      integritySelect,
      availabilitySelect,
      componentEcosystemInput,
      componentNameInput,
      componentDepthInput,
    });
    await load();
  });

  setDefaultBtn.addEventListener("click", async () => {
    const id = Number(savedFiltersSelect.value);
    if (!id) {
      toast({ title: "Select filter", message: "Choose a saved filter first." });
      return;
    }
    try {
      await updateSavedVulnerabilityFilter(id, { is_default: true });
      await refreshSavedFilters();
      toast({ title: "Default updated", message: "This filter is now your default." });
    } catch (e) {
      toast({ title: "Update failed", message: e?.message || "Unable to set default filter" });
    }
  });

  deleteSavedBtn.addEventListener("click", async () => {
    const id = Number(savedFiltersSelect.value);
    if (!id) {
      toast({ title: "Select filter", message: "Choose a saved filter first." });
      return;
    }
    if (!(await confirmModal({ title: "Delete saved filter", message: "Delete selected saved filter?", confirmText: "Delete", danger: true }))) return;
    try {
      await deleteSavedVulnerabilityFilter(id);
      savedFiltersSelect.value = "";
      await refreshSavedFilters();
      toast({ title: "Deleted", message: "Saved filter deleted." });
    } catch (e) {
      toast({ title: "Delete failed", message: e?.message || "Unable to delete saved filter" });
    }
  });

  const controls = createFilterRow({
    controls: [searchInput, statusSelect, severitySelect, attackComplexitySelect, confidentialitySelect, integritySelect, availabilitySelect, componentEcosystemInput, componentNameInput, componentDepthInput],
    actions: [applyBtn, exportFormatSelect, pdfLayoutSelect, exportBtn, savedFiltersSelect, saveCurrentBtn, setDefaultBtn, deleteSavedBtn],
  });
  controls.classList.add("my-12");

  let creationCard = null;
  if (writable) {
    const titleInput = el("input", { class: "input", placeholder: "Title", required: "true" });
    const cveInput = el("input", { class: "input", placeholder: "CVE-2024-0001" });
    const severityInput = el(
      "select",
      { class: "input" },
      ...SEVERITY_OPTIONS.map((s) => el("option", { value: s, text: s, selected: s === "Medium" }))
    );
    const attackComplexityInput = el(
      "select",
      { class: "input" },
      ...ATTACK_COMPLEXITY_OPTIONS.map((c) => el("option", { value: c, text: c, selected: c === "Not Defined" }))
    );
    const confidentialityInput = el(
      "select",
      { class: "input" },
      ...IMPACT_OPTIONS.map((c) => el("option", { value: c, text: c, selected: c === "Not Defined" }))
    );
    const integrityInput = el(
      "select",
      { class: "input" },
      ...IMPACT_OPTIONS.map((c) => el("option", { value: c, text: c, selected: c === "Not Defined" }))
    );
    const availabilityInput = el(
      "select",
      { class: "input" },
      ...IMPACT_OPTIONS.map((c) => el("option", { value: c, text: c, selected: c === "Not Defined" }))
    );
    const statusInput = el(
      "select",
      { class: "input" },
      ...STATUS_OPTIONS.map((s) => el("option", { value: s, text: s, selected: s === "Open" }))
    );
    const cvssInput = el("input", { class: "input", type: "number", step: "0.1", min: "0", max: "10", placeholder: "CVSS (optional)" });
    const publishedInput = el("input", { class: "input", type: "date" });
    const modifiedInput = el("input", { class: "input", type: "date" });
    const descInput = el("textarea", { class: "input", placeholder: "Description" });
    const versionSelect = el("select", { class: "input", multiple: "true", size: "6" });

    const fillVersions = async () => {
      const options = await ensureProductVersions();
      versionSelect.innerHTML = "";
      if (!options.length) {
        versionSelect.appendChild(el("option", { text: "No product versions available", disabled: "true" }));
        return;
      }
      options.forEach((pv) => versionSelect.appendChild(el("option", { value: pv.id, text: `${pv.product_name || "Product"} ${pv.version}` })));
    };

    const cancelBtn = el("button", { class: "btn", type: "button" }, "Cancel");
    const submitBtn = el("button", { class: "btn primary", type: "submit" }, "Save vulnerability");

    const form = el(
      "form",
      { class: "flex-col-10" },
      el("div", {}, el("div", { class: "muted", text: "Title" }), titleInput),
      el("div", {}, el("div", { class: "muted", text: "CVE" }), cveInput),
      el("div", { class: "row gap-10 flex-wrap" },
        el("div", { class: "form-field" }, el("div", { class: "muted", text: "Severity" }), severityInput),
        el("div", { class: "form-field" }, el("div", { class: "muted", text: "Attack complexity" }), attackComplexityInput),
        el("div", { class: "form-field" }, el("div", { class: "muted", text: "Confidentiality impact" }), confidentialityInput),
        el("div", { class: "form-field" }, el("div", { class: "muted", text: "Integrity impact" }), integrityInput),
        el("div", { class: "form-field" }, el("div", { class: "muted", text: "Availability impact" }), availabilityInput),
        el("div", { class: "form-field" }, el("div", { class: "muted", text: "Status" }), statusInput),
        el("div", { class: "form-field-sm" }, el("div", { class: "muted", text: "CVSS" }), cvssInput),
      ),
      el("div", { class: "row gap-10 flex-wrap" },
        el("div", { class: "form-field" }, el("div", { class: "muted", text: "Published" }), publishedInput),
        el("div", { class: "form-field" }, el("div", { class: "muted", text: "Last modified" }), modifiedInput),
      ),
      el("div", {}, el("div", { class: "muted", text: "Description" }), descInput),
      el("div", {}, el("div", { class: "muted", text: "Link product versions (optional)" }), versionSelect, el("div", { class: "muted", text: "Hold Ctrl/Cmd to select multiple" })),
      el("div", { class: "row flex-end gap-8" }, cancelBtn, submitBtn),
    );

    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      const title = titleInput.value.trim();
      if (!title) {
        toast({ title: "Title required", message: "Please enter a title." });
        titleInput.focus();
        return;
      }

      const versionIds = Array.from(versionSelect.selectedOptions || []).map((o) => Number(o.value));

      submitBtn.disabled = true;
      cancelBtn.disabled = true;
      submitBtn.textContent = "Saving...";

      try {
        await createVulnerability({
          title,
          cve_id: cveInput.value.trim() || undefined,
          severity: severityInput.value,
          attack_complexity: attackComplexityInput.value,
          confidentiality_impact: confidentialityInput.value,
          integrity_impact: integrityInput.value,
          availability_impact: availabilityInput.value,
          status: statusInput.value,
          cvss_score: cvssInput.value || undefined,
          published_date: publishedInput.value || undefined,
          last_modified_date: modifiedInput.value || undefined,
          description: descInput.value,
          affected_versions: versionIds,
        });
        toast({ title: "Vulnerability added", message: `${title} created.` });
        titleInput.value = "";
        cveInput.value = "";
        cvssInput.value = "";
        descInput.value = "";
        publishedInput.value = "";
        modifiedInput.value = "";
        attackComplexityInput.value = "Not Defined";
        confidentialityInput.value = "Not Defined";
        integrityInput.value = "Not Defined";
        availabilityInput.value = "Not Defined";
        versionSelect.selectedIndex = -1;
        creationCard.style.display = "none";
        await load();
      } catch (err) {
        toast({ title: "Failed", message: err?.message || "Unable to create vulnerability" });
      } finally {
        submitBtn.disabled = false;
        cancelBtn.disabled = false;
        submitBtn.textContent = "Save vulnerability";
      }
    });

    cancelBtn.addEventListener("click", () => {
      creationCard.style.display = "none";
    });

    creationCard = el(
      "div",
      { class: "card mt-12 mb-12", style: "display: none;" },
      el("h3", { class: "mt-0", text: "Add vulnerability" }),
      el("p", { class: "muted", text: "Create and optionally link affected product versions." }),
      form,
    );

    const addBtn = el("button", { class: "btn primary", type: "button" }, "Add vulnerability");
    addBtn.addEventListener("click", () => {
      creationCard.style.display = "block";
      fillVersions();
      titleInput.focus();
    });

    controls.appendChild(el("div", { class: "spacer" }));
    controls.appendChild(addBtn);
  }

  await refreshSavedFilters();
  try {
    const defaultPayload = await getDefaultVulnerabilityFilter();
    const defaultFilter = defaultPayload?.default;
    if (defaultFilter?.id) {
      savedFiltersSelect.value = String(defaultFilter.id);
      applyFilterValues(defaultFilter.filter_json || {}, {
        searchInput,
        statusSelect,
        severitySelect,
        attackComplexitySelect,
        confidentialitySelect,
        integritySelect,
        availabilitySelect,
        componentEcosystemInput,
        componentNameInput,
        componentDepthInput,
      });
    }
  } catch (_e) {
    // Non-fatal
  }
  await load();

  return el(
    "div",
    { class: "card" },
    el("h1", { class: "page-title", text: "Vulnerabilities" }),
    el("p", { class: "muted", text: "Review, triage, and track vulnerability records." }),
    controls,
    writable ? bulkToolbar : null,
    creationCard,
    list,
  );
}
