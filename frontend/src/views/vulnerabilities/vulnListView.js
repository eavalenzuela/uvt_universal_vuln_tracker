import { el } from "../../ui/dom/el.js";
import { toast } from "../../ui/components/toast.js";
import {
  listVulnerabilities,
  createVulnerability,
  getVulnerability,
  updateVulnerability,
  deleteVulnerability,
  listProductVersions,
  listAttackVectors,
  listTerminalImpacts,
  attachVulnerabilityVersions,
  updateVulnerabilityVersion,
  deleteVulnerabilityVersion,
  attachVulnerabilityAttackVectors,
  updateVulnerabilityAttackVector,
  deleteVulnerabilityAttackVector,
  attachVulnerabilityTerminalImpacts,
  updateVulnerabilityTerminalImpact,
  deleteVulnerabilityTerminalImpact,
  listSavedVulnerabilityFilters,
  getDefaultVulnerabilityFilter,
  createSavedVulnerabilityFilter,
  updateSavedVulnerabilityFilter,
  deleteSavedVulnerabilityFilter,
} from "../../api/vulnerabilities.js";
import { getState } from "../../state/store.js";
import { canWrite, isAdmin } from "../../state/permissions.js";
import { downloadReportArtifact, exportVulnerabilities } from "../../api/reports.js";
import { navigate } from "../../router/router.js";

const STATUS_OPTIONS = ["Open", "In Progress", "Resolved", "Closed"];
const SEVERITY_OPTIONS = ["Critical", "High", "Medium", "Low", "None"];
const ATTACK_COMPLEXITY_OPTIONS = ["Not Defined", "Low", "High"];
const IMPACT_OPTIONS = ["Not Defined", "None", "Low", "Medium", "High"];
const MITIGATION_OPTIONS = ["Not Started", "Investigating", "In Progress", "Mitigated", "Not Applicable"];


function collectFilterValues({
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
}) {
  return {
    search: searchInput.value.trim() || undefined,
    status: statusSelect.value || undefined,
    severity: severitySelect.value || undefined,
    attack_complexity: attackComplexitySelect.value || undefined,
    confidentiality_impact: confidentialitySelect.value || undefined,
    integrity_impact: integritySelect.value || undefined,
    availability_impact: availabilitySelect.value || undefined,
    component_ecosystem: componentEcosystemInput.value.trim() || undefined,
    component_name: componentNameInput.value.trim() || undefined,
    component_depth_max: componentDepthInput.value || undefined,
  };
}

function applyFilterValues(values, {
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
}) {
  searchInput.value = values?.search || "";
  statusSelect.value = values?.status || "";
  severitySelect.value = values?.severity || "";
  attackComplexitySelect.value = values?.attack_complexity || "";
  confidentialitySelect.value = values?.confidentiality_impact || "";
  integritySelect.value = values?.integrity_impact || "";
  availabilitySelect.value = values?.availability_impact || "";
  componentEcosystemInput.value = values?.component_ecosystem || "";
  componentNameInput.value = values?.component_name || "";
  componentDepthInput.value = values?.component_depth_max || "";
}
let cachedProductVersions = null;
let cachedAttackVectors = null;
let cachedTerminalImpacts = null;

function formatDate(value) {
  return value ? value.slice(0, 10) : "-";
}

function severityBadge(severity) {
  const colors = {
    Critical: "#7f1d1d",
    High: "#b45309",
    Medium: "#92400e",
    Low: "#365314",
    None: "#334155",
  };
  const bg = {
    Critical: "#fef2f2",
    High: "#fffbeb",
    Medium: "#fffbeb",
    Low: "#f0fdf4",
    None: "#f8fafc",
  };
  const color = colors[severity] || "#0f172a";
  return el(
    "span",
    {
      class: "badge",
      style: `background: ${bg[severity] || "#f8fafc"}; color: ${color}; border: 1px solid #e2e8f0;`,
    },
    severity || "Unknown",
  );
}


function formatDateTime(value) {
  if (!value) return "-";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "-";
  return date.toLocaleString();
}

function slaBadge(state) {
  const palette = {
    breached: { bg: "#fef2f2", color: "#991b1b", border: "#fecaca", label: "SLA breached" },
    due_soon: { bg: "#fffbeb", color: "#92400e", border: "#fde68a", label: "Due soon" },
    on_track: { bg: "#ecfeff", color: "#155e75", border: "#a5f3fc", label: "On track" },
  };
  const cfg = palette[state] || palette.on_track;
  return el("span", { class: "badge", style: `background:${cfg.bg}; color:${cfg.color}; border:1px solid ${cfg.border};` }, cfg.label);
}

function statusPill(status) {
  return el(
    "span",
    {
      class: "badge",
      style: "background: #eef2ff; color: #312e81; border: 1px solid #c7d2fe;",
    },
    status || "-",
  );
}

async function ensureProductVersions() {
  if (cachedProductVersions) return cachedProductVersions;
  try {
    cachedProductVersions = await listProductVersions();
    return cachedProductVersions;
  } catch (err) {
    toast({ title: "Failed to load versions", message: err?.message || "Unable to list product versions" });
    cachedProductVersions = [];
    return cachedProductVersions;
  }
}

async function ensureAttackVectors() {
  if (cachedAttackVectors) return cachedAttackVectors;
  try {
    cachedAttackVectors = await listAttackVectors();
    return cachedAttackVectors;
  } catch (err) {
    toast({ title: "Failed to load attack vectors", message: err?.message || "Unable to list attack vectors" });
    cachedAttackVectors = [];
    return cachedAttackVectors;
  }
}

async function ensureTerminalImpacts() {
  if (cachedTerminalImpacts) return cachedTerminalImpacts;
  try {
    cachedTerminalImpacts = await listTerminalImpacts();
    return cachedTerminalImpacts;
  } catch (err) {
    toast({ title: "Failed to load terminal impacts", message: err?.message || "Unable to list terminal impacts" });
    cachedTerminalImpacts = [];
    return cachedTerminalImpacts;
  }
}

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

function renderVersionsSection(detailData, vulnId, reloadDetails, canEdit) {
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

function renderAttackVectorsSection(detailData, vulnId, reloadDetails, canEdit) {
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

function renderTerminalImpactRow(mapping, vulnId, reloadDetails, canEdit) {
  const impactSelect = el("select", { class: "input" });
  const saveBtn = el("button", { class: "btn primary", type: "button" }, "Save");
  const deleteBtn = el("button", { class: "btn", type: "button", style: "color: #b91c1c;" }, "Remove");

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
    { class: "card", style: "padding: 10px; display: flex; flex-direction: column; gap: 8px;" },
    el(
      "div",
      { class: "row", style: "justify-content: space-between; gap: 8px;" },
      el(
        "div",
        {},
        el("div", { style: "font-weight: 600;", text: mapping.terminal_impact_name || "Terminal impact" }),
        mapping.terminal_impact_description ? el("div", { class: "muted", text: mapping.terminal_impact_description }) : null,
      ),
      canEdit ? el("div", { class: "row", style: "gap: 6px; align-items: center;" }, deleteBtn, saveBtn) : null,
    ),
    el("div", { style: "flex: 1; min-width: 200px;" }, el("div", { class: "muted", text: "Terminal impact" }), impactSelect),
  );
}

function renderTerminalImpactsSection(detailData, vulnId, reloadDetails, canEdit) {
  const container = el("div", {});
  const list = el("div", { style: "display: flex; flex-direction: column; gap: 8px;" });

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

    container.appendChild(el("div", { class: "divider", style: "margin: 10px 0; height: 1px; background: #e5e7eb;" }));
    container.appendChild(
      el(
        "div",
        { style: "display: flex; flex-direction: column; gap: 8px;" },
        el("div", { class: "muted", text: "Link terminal impacts" }),
        impactSelect,
        el("div", { class: "row", style: "justify-content: flex-end;" }, addBtn),
      )
    );
  }

  return container;
}

function renderVulnerabilityCard(vuln, reloadList, { autoOpen = false } = {}) {
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

  const header = el(
    "div",
    { class: "card", style: "padding: 12px;" },
    el(
      "div",
      { class: "row", style: "justify-content: space-between; align-items: baseline; gap: 8px;" },
      el(
        "div",
        {},
        el("div", { class: "muted", text: vuln.cve_id || `VULN-${vuln.id}` }),
        el("div", { style: "font-weight: 600;", text: vuln.title }),
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

  const list = el("div", { style: "display: flex; flex-direction: column; gap: 12px; margin-top: 8px;" },
    el("div", { class: "muted", text: "Loading vulnerabilities..." }),
  );

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
        list.appendChild(el("div", { class: "muted", text: "No vulnerabilities found." }));
        return;
      }

      data.items.forEach((v) => list.appendChild(renderVulnerabilityCard(v, load, { autoOpen: targetId === v.id })));
    } catch (e) {
      list.innerHTML = "";
      toast({ title: "Failed to load", message: e?.message || "Unable to fetch vulnerabilities" });
      list.appendChild(el("div", { class: "muted", text: "Unable to load vulnerabilities." }));
    }
  }

  const applyBtn = el("button", { class: "btn" }, "Apply filters");
  applyBtn.addEventListener("click", load);

  const exportFormatSelect = el("select", { class: "input", style: "max-width: 120px;" },
    el("option", { value: "csv", text: "CSV" }),
    el("option", { value: "json", text: "JSON" }),
    el("option", { value: "pdf", text: "PDF" }),
  );
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
      const response = await exportVulnerabilities(filters, exportFormatSelect.value);
      const artifact = response?.artifact;
      if (!artifact?.download_url) throw new Error("Export artifact missing download URL");
      const blob = await downloadReportArtifact(artifact.download_url);
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `vulnerabilities_export.${artifact.format || exportFormatSelect.value}`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
      toast({ title: "Export ready", message: `Downloaded vulnerabilities ${String((artifact.format || exportFormatSelect.value)).toUpperCase()}.` });
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
    savedFilters = await listSavedVulnerabilityFilters();
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
    const name = window.prompt("Name for this saved filter:");
    if (!name || !name.trim()) return;
    const visibility = (window.prompt("Visibility: private or shared", "private") || "private").toLowerCase();
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
    if (!window.confirm("Delete selected saved filter?")) return;
    try {
      await deleteSavedVulnerabilityFilter(id);
      savedFiltersSelect.value = "";
      await refreshSavedFilters();
      toast({ title: "Deleted", message: "Saved filter deleted." });
    } catch (e) {
      toast({ title: "Delete failed", message: e?.message || "Unable to delete saved filter" });
    }
  });

  const controls = el("div", { class: "row", style: "gap: 8px; align-items: center; margin: 12px 0; flex-wrap: wrap;" },
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
    applyBtn,
    exportBtn,
    savedFiltersSelect,
    saveCurrentBtn,
    setDefaultBtn,
    deleteSavedBtn,
  );

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
      { style: "display: flex; flex-direction: column; gap: 10px;" },
      el("div", {}, el("div", { class: "muted", text: "Title" }), titleInput),
      el("div", {}, el("div", { class: "muted", text: "CVE" }), cveInput),
      el("div", { class: "row", style: "gap: 10px; flex-wrap: wrap;" },
        el("div", { style: "flex: 1; min-width: 180px;" }, el("div", { class: "muted", text: "Severity" }), severityInput),
        el("div", { style: "flex: 1; min-width: 180px;" }, el("div", { class: "muted", text: "Attack complexity" }), attackComplexityInput),
        el("div", { style: "flex: 1; min-width: 180px;" }, el("div", { class: "muted", text: "Confidentiality impact" }), confidentialityInput),
        el("div", { style: "flex: 1; min-width: 180px;" }, el("div", { class: "muted", text: "Integrity impact" }), integrityInput),
        el("div", { style: "flex: 1; min-width: 180px;" }, el("div", { class: "muted", text: "Availability impact" }), availabilityInput),
        el("div", { style: "flex: 1; min-width: 180px;" }, el("div", { class: "muted", text: "Status" }), statusInput),
        el("div", { style: "flex: 1; min-width: 120px;" }, el("div", { class: "muted", text: "CVSS" }), cvssInput),
      ),
      el("div", { class: "row", style: "gap: 10px; flex-wrap: wrap;" },
        el("div", { style: "flex: 1; min-width: 180px;" }, el("div", { class: "muted", text: "Published" }), publishedInput),
        el("div", { style: "flex: 1; min-width: 180px;" }, el("div", { class: "muted", text: "Last modified" }), modifiedInput),
      ),
      el("div", {}, el("div", { class: "muted", text: "Description" }), descInput),
      el("div", {}, el("div", { class: "muted", text: "Link product versions (optional)" }), versionSelect, el("div", { class: "muted", text: "Hold Ctrl/Cmd to select multiple" })),
      el("div", { class: "row", style: "justify-content: flex-end; gap: 8px;" }, cancelBtn, submitBtn),
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
      { class: "card", style: "margin: 12px 0; display: none;" },
      el("h3", { style: "margin-top: 0;", text: "Add vulnerability" }),
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
    creationCard,
    list,
  );
}
