import { el } from "../../../ui/dom/el.js";
import {
  updateVulnerability,
  getVulnerability,
} from "../../../api/vulnerabilities.js";
import { navigate } from "../../../router/router.js";
import { subscribe } from "../../../state/store.js";
import { getDashboardSummary } from "../../../api/reports.js";
import { applyDashboardMetricDelta, filterByRange, formatAge, formatDate, parseDueHorizon, parseFilterList } from "../selectors/dashboardLogic.js";
import { listVulnerabilitiesWithFilters, loadHighRiskVulnerabilityDetails, loadRiskTrendData } from "../effects/dashboardEffects.js";
import {
  STATUS_OPTIONS,
  SEVERITY_OPTIONS,
  WIDGET_BORDER,
  WIDGET_SURFACE,
  WIDGET_SUBTLE,
  DASHBOARD_SUMMARY_POLL_MS,
  renderSparkline,
  severityBadge,
  ensureActiveUsers,
} from "./dashboardConstants.js";

export function renderHighRiskWidget(ctx) {
  const { writable } = ctx;
  const container = el("div", { style: "display:flex; flex-direction:column; gap:8px;" });
  const list = el("div", { class: "muted", text: "Loading high-risk vulnerabilities..." });
  container.append(list);

  const load = async () => {
    list.innerHTML = "";
    list.appendChild(el("div", { class: "muted", text: "Loading high-risk vulnerabilities..." }));
    try {
      const details = await loadHighRiskVulnerabilityDetails({ page_size: 6, sort: "updated_at", order: "desc" });
      const users = await ensureActiveUsers();
      const userMap = new Map((users || []).map((u) => [u.id, u]));

      list.innerHTML = "";
      if (!details.length) {
        list.appendChild(el("div", { class: "muted", text: "No open High/Critical vulnerabilities." }));
        return;
      }

      const headerRow = el(
        "div",
        {
          style:
            "display:grid; grid-template-columns: 72px 1.6fr 1.1fr 70px 110px 70px 140px auto; gap:8px; font-size:12px; text-transform:uppercase; letter-spacing:0.04em; color:#64748b;",
        },
        el("div", { text: "ID" }),
        el("div", { text: "Title" }),
        el("div", { text: "Asset/App" }),
        el("div", { text: "CVSS" }),
        el("div", { text: "Severity" }),
        el("div", { text: "Age" }),
        el("div", { text: "Owner" }),
        el("div", { text: "Actions" }),
      );

      const rows = details.map((item) => {
        const detail = item.detail;
        const vulnId = item.cve_id || `VULN-${item.id}`;
        const productNames = Array.from(
          new Set((detail?.affected_versions || []).map((version) => version.product_name).filter(Boolean)),
        );
        const assetLabel = productNames.length
          ? productNames.length > 1
            ? `${productNames[0]} +${productNames.length - 1}`
            : productNames[0]
          : "-";
        const owner = detail?.assigned_to ? userMap.get(detail.assigned_to) : null;
        const ownerLabel = owner ? (owner.full_name || owner.username || owner.email || `User ${owner.id}`) : "Unassigned";

        const actionRow = el(
          "div",
          { style: "display:flex; gap:6px; flex-wrap:wrap; align-items:center;" },
          el("button", {
            class: "btn",
            text: "Open",
            onClick: () => navigate(`/vulnerabilities/${item.id}`),
          }),
        );

        if (writable) {
          const statusSelect = el(
            "select",
            { class: "input", style: "padding:4px 6px; font-size:12px;" },
            ...STATUS_OPTIONS.map((status) =>
              el("option", { value: status, text: status, selected: status === item.status }),
            ),
          );
          const assigneeSelect = el("select", { class: "input", style: "padding:4px 6px; font-size:12px; min-width:120px;" },
            el("option", { value: "", text: "Unassigned" }),
            ...(users || []).map((u) => {
              const label = u.full_name || u.username || u.email || `User ${u.id}`;
              return el("option", { value: u.id, text: label, selected: u.id === detail?.assigned_to });
            }),
          );
          const saveBtn = el("button", { class: "btn", text: "Update" });
          saveBtn.addEventListener("click", async () => {
            saveBtn.disabled = true;
            statusSelect.disabled = true;
            assigneeSelect.disabled = true;
            saveBtn.textContent = "Saving...";
            try {
              await updateVulnerability(item.id, {
                status: statusSelect.value,
                assigned_to: assigneeSelect.value ? Number(assigneeSelect.value) : null,
              });
              await load();
            } catch (error) {
              console.warn("Unable to update vulnerability.", error);
            } finally {
              saveBtn.disabled = false;
              statusSelect.disabled = false;
              assigneeSelect.disabled = false;
              saveBtn.textContent = "Update";
            }
          });
          actionRow.append(statusSelect, assigneeSelect, saveBtn);
        }

        return el(
          "div",
          {
            style:
              `display:grid; grid-template-columns: 72px 1.6fr 1.1fr 70px 110px 70px 140px auto; gap:8px; align-items:center; padding:6px 0; border-top:1px solid ${WIDGET_BORDER};`,
          },
          el("div", { style: "font-weight:600; color:#e2e8f0;", text: vulnId }),
          el("div", { style: "font-weight:600;", text: item.title }),
          el("div", { class: "muted", text: assetLabel }),
          el("div", { text: item.cvss_score ?? "-" }),
          severityBadge(item.severity || "Unknown"),
          el("div", { text: formatAge(item.created_at) }),
          el("div", { class: "muted", text: ownerLabel }),
          actionRow,
        );
      });

      list.append(headerRow, ...rows);
    } catch (error) {
      list.innerHTML = "";
      console.warn("Unable to load high risk vulnerabilities.", error);
      list.appendChild(el("div", { class: "muted", text: "Unable to load high risk vulnerabilities." }));
    }
  };

  load();

  return container;
}

export function renderRiskOverviewWidget(widgetSettings) {
  const container = el("div", { style: "display:flex; flex-direction:column; gap:10px;" });
  const content = el("div", { class: "muted", text: "Loading risk overview..." });
  container.append(content);

  let summaryState = null;
  let syncing = false;
  let seenEvents = new Set();

  const renderSummary = () => {
    if (!summaryState) return;
    const counts = (summaryState?.trend?.buckets || []).map((bucket) => bucket.count || 0);
    const totalUpdates = counts.reduce((sum, value) => sum + value, 0);

    content.innerHTML = "";
    const kpiRow = el(
      "div",
      { style: "display:grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); gap:8px;" },
      el("div", { style: `padding:8px; border-radius:8px; background:${WIDGET_SURFACE}; border:1px solid ${WIDGET_BORDER};` },
        el("div", { class: "muted", text: "Total" }),
        el("div", { style: "font-size:20px; font-weight:600;", text: summaryState.total ?? 0 }),
      ),
      el("div", { style: `padding:8px; border-radius:8px; background:${WIDGET_SURFACE}; border:1px solid ${WIDGET_BORDER};` },
        el("div", { class: "muted", text: "Critical" }),
        el("div", { style: "font-size:20px; font-weight:600; color:#b91c1c;", text: summaryState.by_severity?.Critical ?? 0 }),
      ),
      el("div", { style: `padding:8px; border-radius:8px; background:${WIDGET_SURFACE}; border:1px solid ${WIDGET_BORDER};` },
        el("div", { class: "muted", text: "High" }),
        el("div", { style: "font-size:20px; font-weight:600; color:#b45309;", text: summaryState.by_severity?.High ?? 0 }),
      ),
    );

    const trendBlock = el(
      "div",
      { style: `display:flex; align-items:center; gap:12px; padding:8px; border-radius:8px; background:${WIDGET_SURFACE}; border:1px solid ${WIDGET_BORDER};` },
      el("div", { style: "display:flex; flex-direction:column; gap:4px;" },
        el("div", { class: "muted", text: `Updates (${widgetSettings.range})` }),
        el("div", { style: "font-size:16px; font-weight:600;", text: `${totalUpdates} updates` }),
      ),
      renderSparkline(counts),
    );

    content.append(kpiRow, trendBlock);
  };

  const load = async () => {
    if (syncing) return;
    syncing = true;
    content.innerHTML = "";
    content.appendChild(el("div", { class: "muted", text: "Loading risk overview..." }));
    try {
      const statusFilters = parseFilterList(widgetSettings.filter, STATUS_OPTIONS);
      summaryState = await getDashboardSummary({
        status: statusFilters?.length ? statusFilters.join(",") : undefined,
        group_by: widgetSettings.grouping || "Severity",
        range: widgetSettings.range,
      });
      renderSummary();
    } catch (error) {
      content.innerHTML = "";
      console.warn("Unable to load risk overview.", error);
      content.appendChild(el("div", { class: "muted", text: "Unable to load risk overview." }));
    } finally {
      syncing = false;
    }
  };

  subscribe((state) => {
    const events = state?.liveNotifications || [];
    for (const event of events) {
      const key = `${event.sent_at || ""}-${event.type || ""}-${event.payload?.vulnerability_id || ""}`;
      if (seenEvents.has(key)) continue;
      seenEvents.add(key);
      if (event?.type !== "dashboard_metric_change") continue;
      summaryState = applyDashboardMetricDelta(summaryState, event, widgetSettings);
      renderSummary();
    }
    if (seenEvents.size > 120) {
      seenEvents = new Set([...seenEvents].slice(-60));
    }
  });

  load();
  setInterval(load, DASHBOARD_SUMMARY_POLL_MS);
  return container;
}

export function renderRecentlyUpdatedWidget(widgetSettings) {
  const container = el("div", { style: "display:flex; flex-direction:column; gap:8px;" });
  const list = el("div", { class: "muted", text: "Loading updates..." });
  container.append(list);

  const load = async () => {
    list.innerHTML = "";
    list.appendChild(el("div", { class: "muted", text: "Loading updates..." }));
    try {
      const statusFilters = parseFilterList(widgetSettings.filter, STATUS_OPTIONS);
      const severityFilters = parseFilterList(widgetSettings.filter, SEVERITY_OPTIONS);
      const data = await listVulnerabilitiesWithFilters({
        statusFilters,
        severityFilters,
        sort: "updated_at",
        order: "desc",
        page_size: 8,
      });
      const filtered = filterByRange(data.items || [], widgetSettings.range, "updated_at");
      list.innerHTML = "";
      if (!filtered.length) {
        list.appendChild(el("div", { class: "muted", text: "No updates in this range." }));
        return;
      }

      filtered.forEach((item) => {
        list.append(
          el(
            "div",
            {
              style:
                `display:flex; justify-content:space-between; align-items:center; gap:8px; padding:6px 0; border-top:1px solid ${WIDGET_BORDER};`,
            },
            el("div", { style: "display:flex; flex-direction:column; gap:2px;" },
              el("span", { style: "font-weight:600;", text: item.title }),
              el("span", { class: "muted", text: `Updated ${formatAge(item.updated_at)} ago` }),
            ),
            el("div", { style: "display:flex; align-items:center; gap:6px;" },
              severityBadge(item.severity),
              el("button", { class: "btn", text: "Open", onClick: () => navigate(`/vulnerabilities/${item.id}`) }),
            ),
          ),
        );
      });
    } catch (error) {
      list.innerHTML = "";
      console.warn("Unable to load updates.", error);
      list.appendChild(el("div", { class: "muted", text: "Unable to load recent updates." }));
    }
  };

  load();
  return container;
}

export function renderSlaWidget(widgetSettings) {
  const container = el("div", { style: "display:flex; flex-direction:column; gap:8px;" });
  const list = el("div", { class: "muted", text: "Loading SLA items..." });
  container.append(list);

  const load = async () => {
    list.innerHTML = "";
    list.appendChild(el("div", { class: "muted", text: "Loading SLA items..." }));
    try {
      const statusFilters = parseFilterList(widgetSettings.filter, STATUS_OPTIONS);
      const data = await listVulnerabilitiesWithFilters({
        statusFilters,
        sort: "created_at",
        order: "asc",
        page_size: 80,
      });
      const horizon = parseDueHorizon(widgetSettings.range);
      const now = new Date();
      const withDueDates = (data.items || [])
        .map((item) => {
          const dueDate = item?.sla_due_at ? new Date(item.sla_due_at) : null;
          if (!dueDate || Number.isNaN(dueDate.getTime())) return null;
          return { ...item, dueDate };
        })
        .filter(Boolean);
      const dueSoon = withDueDates
        .filter((item) => (horizon ? item.dueDate <= horizon : true))
        .sort((a, b) => a.dueDate - b.dueDate)
        .slice(0, 8);

      const breached = withDueDates.filter((item) => item.sla_state === "breached");
      const bySeverity = breached.reduce((acc, item) => {
        const key = item.severity || "Unknown";
        acc[key] = (acc[key] || 0) + 1;
        return acc;
      }, {});
      const users = await ensureActiveUsers();
      const userMap = new Map(users.map((u) => [u.id, u]));
      const byOwner = breached.reduce((acc, item) => {
        const user = item.assigned_to ? userMap.get(item.assigned_to) : null;
        const label = user ? (user.full_name || user.username || user.email || `User ${user.id}`) : "Unassigned";
        acc[label] = (acc[label] || 0) + 1;
        return acc;
      }, {});

      list.innerHTML = "";
      const rollup = el("div", { style: `display:grid; grid-template-columns: 1fr 1fr; gap:10px; padding:8px; border:1px solid ${WIDGET_BORDER}; border-radius:8px; background:${WIDGET_SURFACE};` });
      rollup.append(
        el("div", {},
          el("div", { style: "font-weight:600;", text: "Breaches by severity" }),
          ...(Object.entries(bySeverity).length
            ? Object.entries(bySeverity).sort((a, b) => b[1] - a[1]).map(([severity, count]) => el("div", { class: "muted", text: `${severity}: ${count}` }))
            : [el("div", { class: "muted", text: "No breaches." })]),
        ),
        el("div", {},
          el("div", { style: "font-weight:600;", text: "Breaches by owner" }),
          ...(Object.entries(byOwner).length
            ? Object.entries(byOwner).sort((a, b) => b[1] - a[1]).slice(0, 5).map(([owner, count]) => el("div", { class: "muted", text: `${owner}: ${count}` }))
            : [el("div", { class: "muted", text: "No breaches." })]),
        ),
      );
      list.appendChild(rollup);
      if (!dueSoon.length) {
        list.appendChild(el("div", { class: "muted", text: "No upcoming SLA deadlines." }));
        return;
      }

      dueSoon.forEach((item) => {
        const remainingDays = Math.ceil((item.dueDate - now) / (1000 * 60 * 60 * 24));
        const statusLabel = remainingDays < 0 ? `Overdue by ${Math.abs(remainingDays)}d` : `${remainingDays}d left`;
        list.append(
          el(
            "div",
            {
              style:
                `display:grid; grid-template-columns: 1.6fr 0.8fr 0.8fr auto; gap:8px; align-items:center; padding:6px 0; border-top:1px solid ${WIDGET_BORDER};`,
            },
            el("div", { style: "display:flex; flex-direction:column; gap:2px;" },
              el("span", { style: "font-weight:600;", text: item.title }),
              el("span", { class: "muted", text: `Due ${formatDate(item.dueDate)}` }),
            ),
            severityBadge(item.severity),
            el("div", { class: "muted", text: statusLabel }),
            el("button", { class: "btn", text: "Open", onClick: () => navigate(`/vulnerabilities/${item.id}`) }),
          ),
        );
      });
    } catch (error) {
      list.innerHTML = "";
      console.warn("Unable to load SLA widget.", error);
      list.appendChild(el("div", { class: "muted", text: "Unable to load SLA items." }));
    }
  };

  load();
  return container;
}

export function renderTopAssetsWidget(widgetSettings) {
  const container = el("div", { style: "display:flex; flex-direction:column; gap:8px;" });
  const list = el("div", { class: "muted", text: "Loading affected assets..." });
  container.append(list);

  const load = async () => {
    list.innerHTML = "";
    list.appendChild(el("div", { class: "muted", text: "Loading affected assets..." }));
    try {
      const statusFilters = parseFilterList(widgetSettings.filter, STATUS_OPTIONS);
      const severityFilters = parseFilterList(widgetSettings.filter, SEVERITY_OPTIONS);
      const data = await listVulnerabilitiesWithFilters({
        statusFilters,
        severityFilters,
        sort: "updated_at",
        order: "desc",
        page_size: 30,
      });
      const scoped = filterByRange(data.items || [], widgetSettings.range, "updated_at");
      const details = await Promise.all(
        scoped.map(async (item) => {
          try {
            const detail = await getVulnerability(item.id);
            return { ...item, detail };
          } catch (error) {
            console.warn("Unable to load vulnerability detail.", error);
            return { ...item, detail: null };
          }
        }),
      );

      const grouping = widgetSettings.grouping || "Product";
      const counts = new Map();
      details.forEach((item) => {
        const versions = item.detail?.affected_versions || [];
        versions.forEach((version) => {
          const label =
            grouping === "Product Version"
              ? `${version.product_name || "Unknown"} ${version.version || ""}`.trim()
              : version.product_name || "Unknown";
          if (!label) return;
          counts.set(label, (counts.get(label) || 0) + 1);
        });
      });

      const sorted = [...counts.entries()]
        .map(([label, count]) => ({ label, count }))
        .sort((a, b) => b.count - a.count)
        .slice(0, 6);

      list.innerHTML = "";
      if (!sorted.length) {
        list.appendChild(el("div", { class: "muted", text: "No affected assets in this range." }));
        return;
      }

      const max = Math.max(...sorted.map((entry) => entry.count), 1);
      sorted.forEach((entry) => {
        list.append(
          el(
            "div",
            { style: `display:flex; flex-direction:column; gap:4px; padding:6px 0; border-top:1px solid ${WIDGET_BORDER};` },
            el("div", { style: "display:flex; justify-content:space-between; align-items:center; gap:8px;" },
              el("span", { style: "font-weight:600;", text: entry.label }),
              el("span", { class: "muted", text: `${entry.count} vulns` }),
            ),
            el("div", { style: `height:6px; border-radius:999px; background:${WIDGET_SUBTLE}; overflow:hidden;` },
              el("div", {
                style: `height:100%; width:${(entry.count / max) * 100}%; background:#2563eb;`,
              }),
            ),
          ),
        );
      });
    } catch (error) {
      list.innerHTML = "";
      console.warn("Unable to load top affected assets.", error);
      list.appendChild(el("div", { class: "muted", text: "Unable to load top affected assets." }));
    }
  };

  load();
  return container;
}

export function renderRiskTrendsWidget(widgetSettings) {
  const container = el("div", { style: "display:flex; flex-direction:column; gap:8px;" });
  const body = el("div", { class: "muted", text: "Loading risk trend data..." });
  container.append(body);

  const load = async () => {
    try {
      const data = await loadRiskTrendData(widgetSettings);
      body.innerHTML = "";
      const grouped = (data.items || []).reduce((acc, item) => {
        const key = `${item.product_name || "Unknown"} ${item.product_version || ""}`.trim();
        if (!acc[key]) acc[key] = [];
        acc[key].push(item);
        return acc;
      }, {});
      const topSeries = Object.entries(grouped)
        .map(([name, items]) => ({
          name,
          items: items.sort((a, b) => a.bucket.localeCompare(b.bucket)),
          score: items.reduce((sum, item) => sum + (item.weighted_risk_score || 0), 0),
        }))
        .sort((a, b) => b.score - a.score)
        .slice(0, 3);
      if (!topSeries.length) {
        body.appendChild(el("div", { class: "muted", text: "No risk trend data for selected filters." }));
        return;
      }
      topSeries.forEach((series) => {
        const spark = renderSparkline(series.items.map((row) => row.weighted_risk_score || 0));
        body.append(
          el("div", { style: `padding:8px; border:1px solid ${WIDGET_BORDER}; border-radius:8px; background:${WIDGET_SURFACE};` },
            el("div", { style: "font-weight:600;", text: series.name }),
            el("div", { class: "muted", text: `Buckets: ${series.items.length} • Total score: ${series.score}` }),
            spark,
          ),
        );
      });
    } catch (error) {
      body.innerHTML = "";
      body.appendChild(el("div", { class: "muted", text: "Unable to load risk trends." }));
    }
  };
  load();
  return container;
}

export function renderTopRiskProductsWidget(widgetSettings) {
  const container = el("div", { style: "display:flex; flex-direction:column; gap:8px;" });
  const body = el("div", { class: "muted", text: "Loading top-risk products..." });
  container.append(body);

  const load = async () => {
    try {
      const data = await loadRiskTrendData(widgetSettings);
      const rows = data.top_risk_products || [];
      body.innerHTML = "";
      if (!rows.length) {
        body.appendChild(el("div", { class: "muted", text: "No top-risk products for selected filters." }));
        return;
      }
      rows.forEach((item, idx) => {
        const label = `${item.product_name || "Unknown"} ${item.product_version || ""}`.trim();
        body.append(
          el("div", { style: `display:grid; grid-template-columns:32px 1.4fr 0.8fr 0.8fr 1fr; gap:8px; padding:6px 0; border-top:1px solid ${WIDGET_BORDER}; align-items:center;` },
            el("div", { text: `${idx + 1}.` }),
            el("div", { text: label }),
            el("div", { class: "muted", text: `Critical: ${item.open_critical_count}` }),
            el("div", { class: "muted", text: `Overdue: ${item.overdue_sla_count}` }),
            el("div", { style: "font-weight:600;", text: `Score: ${item.weighted_risk_score}` }),
          ),
        );
      });
    } catch (error) {
      body.innerHTML = "";
      body.appendChild(el("div", { class: "muted", text: "Unable to load top-risk products." }));
    }
  };
  load();
  return container;
}

export function renderMyWorkWidget(widgetSettings, ctx) {
  const { user } = ctx;
  const container = el("div", { style: "display:flex; flex-direction:column; gap:8px;" });
  const list = el("div", { class: "muted", text: "Loading assigned work..." });
  container.append(list);

  const load = async () => {
    list.innerHTML = "";
    list.appendChild(el("div", { class: "muted", text: "Loading assigned work..." }));
    try {
      if (!user?.id) {
        list.innerHTML = "";
        list.appendChild(el("div", { class: "muted", text: "Sign in to view assigned work." }));
        return;
      }
      const statusFilters = parseFilterList(widgetSettings.filter, STATUS_OPTIONS);
      const data = await listVulnerabilitiesWithFilters({
        statusFilters,
        assigned_to: user?.id,
        sort: "updated_at",
        order: "desc",
        page_size: 12,
      });
      const filtered = filterByRange(data.items || [], widgetSettings.range, "updated_at");
      list.innerHTML = "";
      if (!filtered.length) {
        list.appendChild(el("div", { class: "muted", text: "No assigned work in this range." }));
        return;
      }

      filtered.slice(0, 8).forEach((item) => {
        list.append(
          el(
            "div",
            {
              style:
                `display:grid; grid-template-columns: 1.6fr 0.8fr 0.8fr auto; gap:8px; align-items:center; padding:6px 0; border-top:1px solid ${WIDGET_BORDER};`,
            },
            el("div", { style: "display:flex; flex-direction:column; gap:2px;" },
              el("span", { style: "font-weight:600;", text: item.title }),
              el("span", { class: "muted", text: `Updated ${formatAge(item.updated_at)} ago` }),
            ),
            severityBadge(item.severity),
            el("div", { class: "muted", text: item.status || "-" }),
            el("button", { class: "btn", text: "Open", onClick: () => navigate(`/vulnerabilities/${item.id}`) }),
          ),
        );
      });
    } catch (error) {
      list.innerHTML = "";
      console.warn("Unable to load assigned work.", error);
      list.appendChild(el("div", { class: "muted", text: "Unable to load assigned work." }));
    }
  };

  load();
  return container;
}
