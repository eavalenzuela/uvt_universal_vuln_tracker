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
  DASHBOARD_SUMMARY_POLL_MS,
  renderSparkline,
  severityBadge,
  ensureActiveUsers,
} from "./dashboardConstants.js";

export function renderHighRiskWidget(ctx) {
  const { writable } = ctx;
  const container = el("div", { class: "flex-col-8" });
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
          class: "widget-grid-high-risk text-label",
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
          { class: "flex-row-6 flex-wrap" },
          el("button", {
            class: "btn",
            text: "Open",
            onClick: () => navigate(`/vulnerabilities/${item.id}`),
          }),
        );

        if (writable) {
          const statusSelect = el(
            "select",
            { class: "input input-sm" },
            ...STATUS_OPTIONS.map((status) =>
              el("option", { value: status, text: status, selected: status === item.status }),
            ),
          );
          const assigneeSelect = el("select", { class: "input input-sm", style: "min-width:120px;" },
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
            class: "widget-grid-high-risk widget-row",
          },
          el("div", { class: "font-semibold text-subtle", text: vulnId }),
          el("div", { class: "font-semibold", text: item.title }),
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
  const container = el("div", { class: "flex-col-10" });
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
      { class: "widget-kpi-grid" },
      // The tile said "Total" while counting only the widget's status filter,
      // so the dashboard reported 12 where the list reported 38. Name what is
      // actually being counted; the server returns the applied scope.
      el("div", { class: "widget-surface" },
        el("div", {
          class: "muted",
          text: summaryState.scope?.status ? `${summaryState.scope.status} total` : "Total",
          title: summaryState.scope?.status
            ? `Vulnerabilities with status ${summaryState.scope.status} (all time)`
            : "All vulnerabilities",
        }),
        el("div", { class: "kpi-value", text: summaryState.total ?? 0 }),
      ),
      el("div", { class: "widget-surface" },
        el("div", { class: "muted", text: "Critical" }),
        el("div", { class: "kpi-value-critical", text: summaryState.by_severity?.Critical ?? 0 }),
      ),
      el("div", { class: "widget-surface" },
        el("div", { class: "muted", text: "High" }),
        el("div", { class: "kpi-value-high", text: summaryState.by_severity?.High ?? 0 }),
      ),
    );

    const trendBlock = el(
      "div",
      { class: "widget-surface flex-row-12" },
      el("div", { class: "flex-col-4" },
        el("div", { class: "muted", text: `Updates (${widgetSettings.range})` }),
        el("div", { class: "font-semibold", style: "font-size:16px;", text: `${totalUpdates} updates` }),
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

  const unsubscribe = subscribe((state) => {
    // Skip work once this widget instance has been detached; the poll timer
    // below performs the actual unsubscribe/clearInterval cleanup.
    if (!container.isConnected) return;
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
  // The dashboard re-creates widgets on every layout change. Self-clean the poll
  // loop and the store subscription once this instance leaves the DOM, otherwise
  // each render leaks a 30s interval and a live-notification listener forever.
  const pollTimer = setInterval(() => {
    if (!container.isConnected) {
      clearInterval(pollTimer);
      unsubscribe();
      return;
    }
    load();
  }, DASHBOARD_SUMMARY_POLL_MS);
  return container;
}

export function renderRecentlyUpdatedWidget(widgetSettings) {
  const container = el("div", { class: "flex-col-8" });
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
              class: "flex-between gap-8 widget-row",
            },
            el("div", { class: "flex-col-2" },
              el("span", { class: "font-semibold", text: item.title }),
              el("span", { class: "muted", text: `Updated ${formatAge(item.updated_at)} ago` }),
            ),
            el("div", { class: "flex-row-6" },
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
  const container = el("div", { class: "flex-col-8" });
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
      const rollup = el("div", { class: "widget-surface widget-rollup" });
      rollup.append(
        el("div", {},
          el("div", { class: "font-semibold", text: "Breaches by severity" }),
          ...(Object.entries(bySeverity).length
            ? Object.entries(bySeverity).sort((a, b) => b[1] - a[1]).map(([severity, count]) => el("div", { class: "muted", text: `${severity}: ${count}` }))
            : [el("div", { class: "muted", text: "No breaches." })]),
        ),
        el("div", {},
          el("div", { class: "font-semibold", text: "Breaches by owner" }),
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
              class: "widget-grid-sla widget-row",
            },
            el("div", { class: "flex-col-2" },
              el("span", { class: "font-semibold", text: item.title }),
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
  const container = el("div", { class: "flex-col-8" });
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
            { class: "flex-col-4 widget-row" },
            el("div", { class: "flex-between gap-8" },
              el("span", { class: "font-semibold", text: entry.label }),
              el("span", { class: "muted", text: `${entry.count} vulns` }),
            ),
            el("div", { class: "progress-track" },
              el("div", {
                class: "progress-fill",
                style: `width:${(entry.count / max) * 100}%;`,
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
  const container = el("div", { class: "flex-col-8" });
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
          el("div", { class: "widget-surface" },
            el("div", { class: "font-semibold", text: series.name }),
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
  const container = el("div", { class: "flex-col-8" });
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
          el("div", { class: "widget-grid-top-risk widget-row" },
            el("div", { text: `${idx + 1}.` }),
            el("div", { text: label }),
            el("div", { class: "muted", text: `Critical: ${item.open_critical_count}` }),
            el("div", { class: "muted", text: `Overdue: ${item.overdue_sla_count}` }),
            el("div", { class: "font-semibold", text: `Score: ${item.weighted_risk_score}` }),
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
  const container = el("div", { class: "flex-col-8" });
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
              class: "widget-grid-sla widget-row",
            },
            el("div", { class: "flex-col-2" },
              el("span", { class: "font-semibold", text: item.title }),
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
