import { el } from "../../ui/dom/el.js";
import { navigate } from "../../router/router.js";
import { getProduct } from "../../api/products.js";
import { getDependencyGraph } from "../../api/components.js";

function severityColor(severity) {
  return {
    Critical: "#b91c1c",
    High: "#d97706",
    Medium: "#ca8a04",
    Low: "#15803d",
    None: "#334155",
  }[severity] || "#2563eb";
}

function computeDepths(nodes, edges, rootNodeIds) {
  const depthMap = new Map(nodes.map((n) => [n.id, Number.POSITIVE_INFINITY]));
  const queue = [...rootNodeIds];
  rootNodeIds.forEach((id) => depthMap.set(id, 0));

  while (queue.length) {
    const currentId = queue.shift();
    const currentDepth = depthMap.get(currentId) || 0;
    edges.filter((edge) => edge.parent_component_id === currentId).forEach((edge) => {
      const nextDepth = currentDepth + 1;
      if (nextDepth < (depthMap.get(edge.child_component_id) || Number.POSITIVE_INFINITY)) {
        depthMap.set(edge.child_component_id, nextDepth);
        queue.push(edge.child_component_id);
      }
    });
  }

  nodes.forEach((node) => {
    if (!Number.isFinite(depthMap.get(node.id))) depthMap.set(node.id, 0);
  });
  return depthMap;
}

export async function ProductDependencyGraphView(params = {}) {
  const productId = Number(params?.id);
  const productVersionId = Number(params?.productVersionId);
  const root = el("div", { class: "stack" });
  const card = el("div", { class: "card" }, el("p", { class: "muted", text: "Loading dependency graph..." }));

  root.append(
    el("div", { class: "card" },
      el("div", { class: "row flex-between" },
        el("h1", { class: "page-title", text: "Dependency graph" }),
        el("button", { class: "btn", type: "button", onClick: () => navigate(`/products/${productId}`) }, "Back to product"),
      ),
    ),
    card,
  );

  try {
    const [product, graph] = await Promise.all([getProduct(productId), getDependencyGraph(productVersionId)]);
    const depthMap = computeDepths(graph.nodes || [], graph.edges || [], graph.root_node_ids || []);
    const maxDepth = Math.max(0, ...[...depthMap.values()].filter(Number.isFinite));

    const controls = el("div", { class: "row gap-8 flex-wrap items-end" });
    const depthInput = el("input", { class: "input", type: "number", min: "1", value: String(Math.max(1, maxDepth)), style: "width:100px;" });
    const showTransitiveToggle = el("input", { type: "checkbox", checked: true });
    const vulnOnlyToggle = el("input", { type: "checkbox" });

    controls.append(
      el("label", { class: "flex-col-4" },
        el("span", { class: "muted", text: "Max depth" }),
        depthInput,
      ),
      el("label", { class: "row gap-6" }, showTransitiveToggle, el("span", { text: "Show transitive edges" })),
      el("label", { class: "row gap-6" }, vulnOnlyToggle, el("span", { text: "Highlight vulnerable only" })),
    );

    const graphWrap = el("div", { class: "detail-border", style: "overflow:auto; background:var(--color-surface);" });
    const detailPane = el("div", { class: "card mt-12" }, el("div", { class: "muted", text: "Select a node to inspect details." }));

    const renderGraph = () => {
      const maxSelectedDepth = Number(depthInput.value || maxDepth) || maxDepth;
      const visibleNodes = (graph.nodes || []).filter((node) => (depthMap.get(node.id) || 0) <= maxSelectedDepth);
      const visibleNodeIds = new Set(visibleNodes.map((node) => node.id));
      const visibleEdges = (graph.edges || []).filter((edge) => {
        if (!showTransitiveToggle.checked && !edge.is_direct) return false;
        if ((edge.depth || 0) > maxSelectedDepth) return false;
        return visibleNodeIds.has(edge.parent_component_id) && visibleNodeIds.has(edge.child_component_id);
      });

      const layers = new Map();
      visibleNodes.forEach((node) => {
        const depth = depthMap.get(node.id) || 0;
        if (!layers.has(depth)) layers.set(depth, []);
        layers.get(depth).push(node);
      });
      [...layers.values()].forEach((layerNodes) => layerNodes.sort((a, b) => (a.name || "").localeCompare(b.name || "")));

      const width = Math.max(1000, (layers.size + 1) * 260);
      const height = Math.max(600, Math.max(...[...layers.values()].map((v) => v.length), 1) * 110 + 120);
      const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
      svg.setAttribute("width", String(width));
      svg.setAttribute("height", String(height));
      svg.setAttribute("viewBox", `0 0 ${width} ${height}`);

      const pos = new Map();
      [...layers.entries()].forEach(([depth, layerNodes]) => {
        const x = 120 + depth * 230;
        const total = layerNodes.length;
        layerNodes.forEach((node, i) => {
          const y = 80 + ((i + 1) * (height - 160)) / (total + 1);
          pos.set(node.id, { x, y });
        });
      });

      visibleEdges.forEach((edge) => {
        const parentPos = pos.get(edge.parent_component_id);
        const childPos = pos.get(edge.child_component_id);
        if (!parentPos || !childPos) return;
        const line = document.createElementNS("http://www.w3.org/2000/svg", "line");
        line.setAttribute("x1", String(parentPos.x + 50));
        line.setAttribute("y1", String(parentPos.y));
        line.setAttribute("x2", String(childPos.x - 50));
        line.setAttribute("y2", String(childPos.y));
        line.setAttribute("stroke", edge.is_direct ? "#94a3b8" : "#cbd5e1");
        line.setAttribute("stroke-width", edge.is_direct ? "2" : "1");
        svg.appendChild(line);
      });

      visibleNodes.forEach((node) => {
        const nodePos = pos.get(node.id);
        if (!nodePos) return;
        const hasVulns = (node.vulnerability_count || 0) > 0;
        const hiddenByVulnFilter = vulnOnlyToggle.checked && !hasVulns;
        const group = document.createElementNS("http://www.w3.org/2000/svg", "g");

        const rect = document.createElementNS("http://www.w3.org/2000/svg", "rect");
        rect.setAttribute("x", String(nodePos.x - 55));
        rect.setAttribute("y", String(nodePos.y - 22));
        rect.setAttribute("rx", "10");
        rect.setAttribute("ry", "10");
        rect.setAttribute("width", "110");
        rect.setAttribute("height", "44");
        rect.setAttribute("fill", hiddenByVulnFilter ? "#f8fafc" : hasVulns ? "#fef2f2" : "#eff6ff");
        rect.setAttribute("stroke", hiddenByVulnFilter ? "#cbd5e1" : hasVulns ? severityColor(node.max_severity) : "#60a5fa");
        rect.setAttribute("stroke-width", hiddenByVulnFilter ? "1" : "2");
        rect.style.cursor = "pointer";

        const label = document.createElementNS("http://www.w3.org/2000/svg", "text");
        label.setAttribute("x", String(nodePos.x));
        label.setAttribute("y", String(nodePos.y - 2));
        label.setAttribute("text-anchor", "middle");
        label.setAttribute("font-size", "11");
        label.textContent = node.name?.slice(0, 18) || `Component ${node.id}`;

        const sub = document.createElementNS("http://www.w3.org/2000/svg", "text");
        sub.setAttribute("x", String(nodePos.x));
        sub.setAttribute("y", String(nodePos.y + 12));
        sub.setAttribute("text-anchor", "middle");
        sub.setAttribute("font-size", "10");
        sub.setAttribute("fill", "#475569");
        sub.textContent = node.version || "-";

        const openNodeDetail = () => {
          detailPane.innerHTML = "";
          detailPane.append(
            el("h3", { text: `${node.name} ${node.version || ""}` }),
            el("div", { class: "muted", text: `${node.ecosystem || "-"} • ${node.component_type || "component"}` }),
            el("div", { class: "muted", text: `Depth: ${depthMap.get(node.id) || 0} • Vulnerabilities: ${node.vulnerability_count || 0}` }),
            el("div", { class: "row gap-8 flex-wrap mt-8" },
              el("button", {
                class: "btn",
                type: "button",
                onClick: () => navigate(`/vulnerabilities?component_name=${encodeURIComponent(node.name || "")}&component_ecosystem=${encodeURIComponent(node.ecosystem || "")}`),
              }, "Open vulnerability list"),
            ),
            (node.vulnerabilities || []).length
              ? el("div", { class: "flex-col-6 mt-8" },
                  ...(node.vulnerabilities || []).map((vuln) =>
                    el("div", { class: "detail-border" },
                      el("div", { class: "font-semibold", style: `color:${severityColor(vuln.severity)};`, text: vuln.title || `Vulnerability ${vuln.id}` }),
                      el("div", { class: "muted", text: `${vuln.severity || "-"} • ${vuln.status || "-"}` }),
                      el("button", { class: "btn", type: "button", onClick: () => navigate(`/vulnerabilities/${vuln.id}`) }, "Open vulnerability detail"),
                    ),
                  ),
                )
              : el("div", { class: "muted", text: "No linked vulnerabilities." }),
          );
        };

        rect.addEventListener("click", openNodeDetail);
        label.addEventListener("click", openNodeDetail);
        sub.addEventListener("click", openNodeDetail);

        group.append(rect, label, sub);
        svg.appendChild(group);
      });

      graphWrap.innerHTML = "";
      graphWrap.appendChild(svg);
    };

    depthInput.addEventListener("change", renderGraph);
    showTransitiveToggle.addEventListener("change", renderGraph);
    vulnOnlyToggle.addEventListener("change", renderGraph);

    card.innerHTML = "";
    card.append(
      el("h2", { text: `${product.name} - ${graph.product_version_id}` }),
      controls,
      el("p", { class: "muted", text: `Nodes: ${(graph.nodes || []).length} • Edges: ${(graph.edges || []).length} • Roots: ${(graph.root_node_ids || []).length}` }),
      graphWrap,
      detailPane,
    );

    renderGraph();
  } catch (err) {
    card.innerHTML = "";
    card.append(el("h2", { text: "Unable to load dependency graph" }), el("p", { class: "muted", text: err?.message || "Unknown error" }));
  }

  return root;
}
