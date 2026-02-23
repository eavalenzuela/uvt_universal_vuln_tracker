import test from "node:test";
import assert from "node:assert/strict";
import { collectFilterValues, applyFilterValues } from "../../../src/features/vulnerabilities/selectors/filterNormalization.js";

function control(value = "") { return { value }; }

test("collectFilterValues trims and omits empties", () => {
  const values = collectFilterValues({
    searchInput: control("  abc  "),
    statusSelect: control("Open"),
    severitySelect: control(""),
    attackComplexitySelect: control("Low"),
    confidentialitySelect: control(""),
    integritySelect: control(""),
    availabilitySelect: control(""),
    componentEcosystemInput: control(" npm "),
    componentNameInput: control("lodash"),
    componentDepthInput: control("2"),
  });
  assert.equal(values.search, "abc");
  assert.equal(values.severity, undefined);
  assert.equal(values.component_ecosystem, "npm");
});

test("applyFilterValues restores values to controls", () => {
  const controls = {
    searchInput: control(), statusSelect: control(), severitySelect: control(), attackComplexitySelect: control(),
    confidentialitySelect: control(), integritySelect: control(), availabilitySelect: control(),
    componentEcosystemInput: control(), componentNameInput: control(), componentDepthInput: control(),
  };
  applyFilterValues({ search: "x", status: "Open", component_depth_max: "4" }, controls);
  assert.equal(controls.searchInput.value, "x");
  assert.equal(controls.componentDepthInput.value, "4");
});
