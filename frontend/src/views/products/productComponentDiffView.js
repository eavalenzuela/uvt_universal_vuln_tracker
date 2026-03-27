import { el } from "../../ui/dom/el.js";
import { listProductVersions } from "../../api/vulnerabilities.js";
import { compareProductVersionComponents } from "../../api/components.js";
import { toast } from "../../ui/components/toast.js";


function parseSelectionFromHash() {
  const hash = window.location.hash || "";
  const query = hash.includes("?") ? hash.slice(hash.indexOf("?") + 1) : "";
  const params = new URLSearchParams(query);
  return {
    from: Number(params.get("from") || 0) || null,
    to: Number(params.get("to") || 0) || null,
  };
}

function versionLabel(v) {
  const product = v.product_name || `Product ${v.product_id}`;
  return `${product} / ${v.version}${v.is_active ? "" : " (inactive)"}`;
}

function renderSimpleTable(title, rows, columns) {
  const table = el("table", { class: "table w-full" });
  const thead = el("thead", {});
  const trh = el("tr", {});
  columns.forEach((col) => trh.appendChild(el("th", { text: col.label })));
  thead.appendChild(trh);
  const tbody = el("tbody", {});

  if (!rows.length) {
    tbody.appendChild(el("tr", {}, el("td", { colspan: String(columns.length), class: "muted", text: "No records." })));
  } else {
    rows.forEach((row) => {
      const tr = el("tr", {});
      columns.forEach((col) => tr.appendChild(el("td", { text: col.value(row) })));
      tbody.appendChild(tr);
    });
  }

  table.append(thead, tbody);
  return el("div", { class: "card p-12" }, el("h4", { text: title }), table);
}

export function ProductComponentDiffView() {
  const root = el("div", { class: "stack" });
  const header = el(
    "div",
    { class: "card" },
    el("h2", { text: "Product Version Component Diff" }),
    el("p", { class: "muted", text: "Compare two product versions to identify component and dependency graph deltas." }),
  );

  const fromSelect = el("select", { class: "input" });
  const toSelect = el("select", { class: "input" });
  const compareBtn = el("button", { class: "btn" }, "Compare");
  const summary = el("div", { class: "muted" }, "Select versions and run comparison.");
  const results = el("div", { class: "stack" });

  function populateSelect(select, versions, selectedId = null) {
    select.innerHTML = "";
    select.appendChild(el("option", { value: "", text: "Select version" }));
    versions.forEach((v) => {
      const opt = el("option", { value: String(v.id), text: versionLabel(v) });
      if (selectedId && Number(selectedId) === v.id) opt.selected = true;
      select.appendChild(opt);
    });
  }

  async function loadVersionOptions() {
    try {
      const versions = await listProductVersions({ includeInactive: true });
      const selected = parseSelectionFromHash();
      populateSelect(fromSelect, versions, selected.from);
      populateSelect(toSelect, versions, selected.to);
      if ((!selected.from || !selected.to) && versions.length >= 2) {
        fromSelect.value = String(versions[0].id);
        toSelect.value = String(versions[1].id);
      }
    } catch (err) {
      toast({ title: "Failed to load versions", message: err?.message || "Unable to load version list" });
    }
  }

  compareBtn.addEventListener("click", async () => {
    const fromId = Number(fromSelect.value || 0);
    const toId = Number(toSelect.value || 0);

    if (!fromId || !toId) {
      toast({ title: "Versions required", message: "Select both source and target versions." });
      return;
    }
    if (fromId === toId) {
      toast({ title: "Invalid selection", message: "Choose two different product versions." });
      return;
    }

    compareBtn.disabled = true;
    compareBtn.textContent = "Comparing...";
    results.innerHTML = "";

    try {
      const diff = await compareProductVersionComponents({
        fromProductVersionId: fromId,
        toProductVersionId: toId,
      });

      const s = diff.summary || {};
      summary.textContent = `Added: ${s.added_components || 0}, Removed: ${s.removed_components || 0}, Changed: ${s.changed_components || 0}, Upgrades: ${s.version_upgrades || 0}, Downgrades: ${s.version_downgrades || 0}`;

      const componentColumns = [
        { label: "Ecosystem", value: (r) => r.ecosystem || "-" },
        { label: "Name", value: (r) => r.name || "-" },
        { label: "Version", value: (r) => r.version || "-" },
        { label: "Type", value: (r) => r.component_type || "-" },
      ];

      results.appendChild(renderSimpleTable("Added Components", diff.components?.added || [], componentColumns));
      results.appendChild(renderSimpleTable("Removed Components", diff.components?.removed || [], componentColumns));

      results.appendChild(renderSimpleTable("Changed Components", diff.components?.changed || [], [
        { label: "Ecosystem", value: (r) => r.component_key?.ecosystem || "-" },
        { label: "Name", value: (r) => r.component_key?.name || "-" },
        { label: "From Version", value: (r) => r.from?.version || "-" },
        { label: "To Version", value: (r) => r.to?.version || "-" },
        { label: "Changed Fields", value: (r) => Object.keys(r.changes || {}).join(", ") || "-" },
      ]));

      results.appendChild(renderSimpleTable("Version Upgrades", diff.version_deltas?.upgrades || [], [
        { label: "Ecosystem", value: (r) => r.ecosystem || "-" },
        { label: "Name", value: (r) => r.name || "-" },
        { label: "From", value: (r) => r.from_version || "-" },
        { label: "To", value: (r) => r.to_version || "-" },
      ]));

      results.appendChild(renderSimpleTable("Version Downgrades", diff.version_deltas?.downgrades || [], [
        { label: "Ecosystem", value: (r) => r.ecosystem || "-" },
        { label: "Name", value: (r) => r.name || "-" },
        { label: "From", value: (r) => r.from_version || "-" },
        { label: "To", value: (r) => r.to_version || "-" },
      ]));

      const dependencyColumns = [
        { label: "Parent", value: (r) => `${r.parent?.name || "?"}@${r.parent?.version || "-"}` },
        { label: "Child", value: (r) => `${r.child?.name || "?"}@${r.child?.version || "-"}` },
        { label: "Depth", value: (r) => String(r.depth ?? "-") },
        { label: "Direct", value: (r) => (r.is_direct ? "Yes" : "No") },
      ];

      results.appendChild(renderSimpleTable("Dependency Edges Added", diff.dependency_graph?.added || [], dependencyColumns));
      results.appendChild(renderSimpleTable("Dependency Edges Removed", diff.dependency_graph?.removed || [], dependencyColumns));
      results.appendChild(renderSimpleTable("Dependency Edges Changed", diff.dependency_graph?.changed || [], [
        { label: "Parent", value: (r) => `${r.to?.parent?.name || r.from?.parent?.name || "?"}` },
        { label: "Child", value: (r) => `${r.to?.child?.name || r.from?.child?.name || "?"}` },
        { label: "From", value: (r) => `depth=${r.from?.depth ?? "-"}, direct=${r.from?.is_direct ? "yes" : "no"}` },
        { label: "To", value: (r) => `depth=${r.to?.depth ?? "-"}, direct=${r.to?.is_direct ? "yes" : "no"}` },
      ]));
    } catch (err) {
      toast({ title: "Comparison failed", message: err?.message || "Unable to compare versions" });
      summary.textContent = "Unable to compare selected versions.";
    } finally {
      compareBtn.disabled = false;
      compareBtn.textContent = "Compare";
    }
  });

  const controls = el(
    "div",
    { class: "card p-12" },
    el("h3", { text: "Select Versions" }),
    el("div", { class: "row gap-8 items-end flex-wrap" },
      el("div", {}, el("div", { class: "muted", text: "From version" }), fromSelect),
      el("div", {}, el("div", { class: "muted", text: "To version" }), toSelect),
      compareBtn,
    ),
    el("div", { class: "muted mt-8" }, summary),
  );

  root.append(header, controls, results);
  loadVersionOptions();
  return root;
}
