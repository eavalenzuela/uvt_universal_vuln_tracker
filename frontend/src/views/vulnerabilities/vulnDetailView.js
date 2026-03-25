import { el } from "../../ui/dom/el.js";
import { toast } from "../../ui/components/toast.js";
import { promptModal } from "../../ui/components/modal.js";
import { withLoading } from "../../ui/components/loading.js";
import { navigate } from "../../router/router.js";
import { getState } from "../../state/store.js";
import {
  getVulnerability,
  listVulnerabilityActivity,
  listVulnerabilityHistory,
  listVulnerabilityComments,
  createVulnerabilityComment,
  updateVulnerabilityComment,
  deleteVulnerabilityComment,
  listVulnerabilityWatchers,
  watchVulnerability,
  unwatchVulnerability,
  listMergeCandidates,
  mergeVulnerability,
} from "../../api/vulnerabilities.js";

function formatDate(value) {
  return value ? value.slice(0, 10) : "-";
}

function formatDateTime(value) {
  if (!value) return "-";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "-" : date.toLocaleString();
}

function field(label, value) {
  return el("div", {}, el("div", { class: "muted", text: label }), el("div", { text: value ?? "-" }));
}

function renderList(title, items, renderItem) {
  return el(
    "div",
    { class: "card", style: "margin-top: 12px;" },
    el("h3", { style: "margin-top: 0;", text: title }),
    !items?.length
      ? el("div", { class: "muted", text: "None" })
      : el("div", { style: "display:flex; flex-direction:column; gap:8px;" }, ...items.map(renderItem)),
  );
}

function renderActivityItem(item) {
  const actor = item?.user?.username || "system";
  const summary = `${item.action} • ${item.table_name}`;
  const delta = item.new_values || item.old_values
    ? JSON.stringify({ old: item.old_values || null, new: item.new_values || null })
    : "No field data";

  return el(
    "div",
    { style: "padding:10px; border:1px solid #e2e8f0; border-radius:10px;" },
    el("div", { style: "font-weight:600;", text: summary }),
    el("div", { class: "muted", text: `${formatDateTime(item.created_at)} by ${actor}` }),
    el("pre", { style: "white-space:pre-wrap; margin:8px 0 0; background:#f8fafc; padding:8px; border-radius:8px;" }, delta),
  );
}


function renderHistoryItem(item) {
  const actor = item?.actor?.username || "system";
  const delta = item?.field_diff ? JSON.stringify(item.field_diff, null, 2) : "No field diff";

  return el(
    "div",
    { style: "padding:10px; border:1px solid #e2e8f0; border-radius:10px;" },
    el("div", { style: "font-weight:600;", text: item.action || "-" }),
    el("div", { class: "muted", text: `${formatDateTime(item.timestamp)} by ${actor}` }),
    el("pre", { style: "white-space:pre-wrap; margin:8px 0 0; background:#f8fafc; padding:8px; border-radius:8px;" }, delta),
  );
}


function renderMergeCandidateRow(item, onMerge) {
  const candidate = item?.candidate || {};
  return el(
    "div",
    { style: "padding:10px; border:1px solid #e2e8f0; border-radius:10px;" },
    el("div", { style: "font-weight:600;", text: `${candidate.title || `Vulnerability ${candidate.id}`} (${candidate.severity || "-"})` }),
    el("div", { class: "muted", text: `ID ${candidate.id}${candidate.cve_id ? ` • ${candidate.cve_id}` : ""}` }),
    el("div", { class: "muted", text: `Score: ${item.score} • Reasons: ${(item.reasons || []).join(", ") || "-"}` }),
    el("button", {
      class: "btn danger",
      text: "Merge into this vulnerability",
      onClick: () => onMerge(candidate),
    }),
  );
}

function canModerateComment(currentUser, comment) {
  if (!currentUser) return false;
  return currentUser.role === "Admin" || currentUser.id === comment.author_id;
}

function renderCommentItem(item, currentUser, onRefresh) {
  const actions = [];
  if (canModerateComment(currentUser, item)) {
    actions.push(
      el("button", {
        class: "btn",
        text: "Edit",
        onClick: withLoading(async () => {
          const nextBody = await promptModal({ title: "Update comment", defaultValue: item.body || "", inputLabel: "Comment body" });
          if (nextBody === null) return;
          await updateVulnerabilityComment(item.vulnerability_id, item.id, nextBody);
          await onRefresh();
        }, { loadingText: "Saving\u2026" }),
      }),
      el("button", {
        class: "btn danger",
        text: "Delete",
        onClick: withLoading(async () => {
          await deleteVulnerabilityComment(item.vulnerability_id, item.id);
          await onRefresh();
        }, { loadingText: "Deleting\u2026" }),
      }),
    );
  }

  return el(
    "div",
    { style: "padding:10px; border:1px solid #e2e8f0; border-radius:10px;" },
    el("div", { style: "font-weight:600;", text: item.author?.username || `User ${item.author_id}` }),
    el("div", { class: "muted", text: `${formatDateTime(item.created_at)}${item.updated_at !== item.created_at ? " (edited)" : ""}` }),
    el("div", { style: "white-space:pre-wrap; margin-top:8px;", text: item.body || "" }),
    actions.length ? el("div", { class: "row", style: "gap:8px; margin-top:8px;" }, ...actions) : null,
  );
}

export async function VulnDetailView(params = {}) {
  const vulnId = Number(params?.id);
  if (!Number.isFinite(vulnId) || vulnId <= 0) {
    return el("div", { class: "card" }, el("h1", { class: "page-title", text: "Vulnerability detail" }), el("p", { text: "Invalid vulnerability id." }));
  }

  const currentUser = getState()?.session?.user;
  const canComment = ["Admin", "Analyst"].includes(currentUser?.role);
  const container = el("div", { class: "card" }, el("h1", { class: "page-title", text: "Vulnerability detail" }), el("p", { class: "muted", text: "Loading vulnerability..." }));

  async function render() {
    try {
      const [vuln, activity, history, comments, watchers, mergeCandidatesPayload] = await Promise.all([
        getVulnerability(vulnId),
        listVulnerabilityActivity(vulnId).catch(() => []),
        listVulnerabilityHistory(vulnId).catch(() => []),
        listVulnerabilityComments(vulnId).catch(() => []),
        listVulnerabilityWatchers(vulnId).catch(() => []),
        listMergeCandidates(vulnId).catch(() => ({ items: [] })),
      ]);
      const mergeCandidates = mergeCandidatesPayload?.items || [];

      const isWatching = watchers.some((watcher) => watcher.user_id === currentUser?.id);

      const commentInput = el("textarea", { class: "input", rows: 4, placeholder: "Add a comment. Mention users with @username" });
      const commentSubmit = el("button", {
        class: "btn",
        text: "Add comment",
        onClick: withLoading(async () => {
          const value = (commentInput.value || "").trim();
          if (!value) return;
          await createVulnerabilityComment(vulnId, value);
          commentInput.value = "";
          await render();
        }, { loadingText: "Posting\u2026" }),
      });

      container.innerHTML = "";
      container.append(
        el(
          "div",
          { class: "row", style: "justify-content:space-between; align-items:center; margin-bottom:8px;" },
          el("h1", { class: "page-title", text: vuln.title || `Vulnerability ${vuln.id}` }),
          el("button", { class: "btn", onClick: () => navigate("/vulnerabilities") }, "Back to list"),
        ),
        vuln.cve_id ? el("p", { class: "muted", text: vuln.cve_id }) : null,
        vuln.is_merged ? el("p", { class: "muted", text: `Merged into vulnerability #${vuln.merged_into_id || "-"}` }) : null,
        el("p", { text: vuln.description || "No description provided." }),
        el(
          "div",
          { class: "card", style: "padding:10px;" },
          el("h3", { style: "margin-top:0;", text: "Core fields" }),
          el(
            "div",
            { class: "row", style: "gap:12px; flex-wrap:wrap;" },
            field("Severity", vuln.severity),
            field("Status", vuln.status),
            field("SLA state", vuln.sla_state),
            field("SLA due", formatDateTime(vuln.sla_due_at)),
            field("CVSS", vuln.cvss_score ?? "-"),
            field("Attack complexity", vuln.attack_complexity),
            field("Confidentiality impact", vuln.confidentiality_impact),
            field("Integrity impact", vuln.integrity_impact),
            field("Availability impact", vuln.availability_impact),
            field("Published", formatDate(vuln.published_date)),
            field("Last modified", formatDate(vuln.last_modified_date)),
            field("Assigned to", vuln.assigned_to ?? "Unassigned"),
            field("Created by", vuln.created_by ?? "-"),
          ),
        ),
        el(
          "div",
          { class: "card", style: "margin-top:12px;" },
          el("h3", { style: "margin-top:0;", text: "Watchers" }),
          el("div", { class: "muted", text: watchers.length ? watchers.map((w) => w.username || `User ${w.user_id}`).join(", ") : "No watchers" }),
          canComment
            ? el("button", {
                class: "btn",
                text: isWatching ? "Unwatch" : "Watch",
                onClick: withLoading(async () => {
                  if (isWatching) await unwatchVulnerability(vulnId, currentUser.id);
                  else await watchVulnerability(vulnId);
                  await render();
                }),
              })
            : null,
        ),
        ["Admin", "Analyst"].includes(currentUser?.role) && !vuln.is_merged
          ? el(
              "div",
              { class: "card", style: "margin-top:12px;" },
              el("h3", { style: "margin-top:0;", text: "Merge candidates" }),
              !mergeCandidates.length
                ? el("div", { class: "muted", text: "No high-confidence merge candidates found." })
                : el(
                    "div",
                    { style: "display:flex; flex-direction:column; gap:8px;" },
                    ...mergeCandidates.map((candidate) =>
                      renderMergeCandidateRow(candidate, async (choice) => {
                        const confirm = window.confirm(
                          `Merge vulnerability #${choice.id} into #${vuln.id}? This will move versions, components, comments, and watchers.`,
                        );
                        if (!confirm) return;
                        const reason = (await promptModal({ title: "Merge reason", message: "Optionally provide a reason for this merge.", inputLabel: "Reason", placeholder: "Reason (optional)" })) || undefined;
                        await mergeVulnerability(vuln.id, choice.id, reason);
                        toast({ title: "Vulnerabilities merged", message: `Merged #${choice.id} into #${vuln.id}` });
                        await render();
                      }),
                    ),
                  ),
            )
          : null,

        el(
          "div",
          { class: "card", style: "margin-top:12px;" },
          el("h3", { style: "margin-top:0;", text: "Discussion" }),
          canComment ? el("div", { style: "display:flex; flex-direction:column; gap:8px;" }, commentInput, commentSubmit) : el("div", { class: "muted", text: "You do not have permission to add comments." }),
        ),
        renderList("Comment history", comments, (item) => renderCommentItem(item, currentUser, render)),
        renderList("Linked product versions", vuln.affected_versions, (item) =>
          el("div", { style: "padding:10px; border:1px solid #e2e8f0; border-radius:10px;" },
            el("div", { style: "font-weight:600;", text: `${item.product_name || "Product"} ${item.version || ""}` }),
            el("div", { class: "muted", text: `Affected: ${item.affected ? "Yes" : "No"} • Mitigation: ${item.mitigation_status || "-"}` }),
            item.fixed_in_version ? el("div", { text: `Fixed in: ${item.fixed_in_version}` }) : null,
            item.notes ? el("div", { class: "muted", text: item.notes }) : null,
          )
        ),
        renderList("History", history, renderHistoryItem),
        renderList("Activity timeline", activity, renderActivityItem),
      );
    } catch (err) {
      toast({ title: "Failed to load vulnerability", message: err?.message || "Unable to fetch vulnerability detail" });
      container.innerHTML = "";
      container.append(
        el("h1", { class: "page-title", text: "Vulnerability detail" }),
        el("p", { class: "muted", text: "Unable to load this vulnerability." }),
        el("button", { class: "btn", onClick: () => navigate("/vulnerabilities") }, "Back to list"),
      );
    }
  }

  await render();
  return container;
}
