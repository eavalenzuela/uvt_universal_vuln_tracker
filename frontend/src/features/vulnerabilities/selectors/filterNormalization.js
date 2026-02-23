export function collectFilterValues({
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

export function applyFilterValues(values, controls) {
  controls.searchInput.value = values?.search || "";
  controls.statusSelect.value = values?.status || "";
  controls.severitySelect.value = values?.severity || "";
  controls.attackComplexitySelect.value = values?.attack_complexity || "";
  controls.confidentialitySelect.value = values?.confidentiality_impact || "";
  controls.integritySelect.value = values?.integrity_impact || "";
  controls.availabilitySelect.value = values?.availability_impact || "";
  controls.componentEcosystemInput.value = values?.component_ecosystem || "";
  controls.componentNameInput.value = values?.component_name || "";
  controls.componentDepthInput.value = values?.component_depth_max || "";
}
