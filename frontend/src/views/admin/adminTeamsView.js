import { el } from "../../ui/dom/el.js";
import { toast } from "../../ui/components/toast.js";
import { createDataTable } from "../../ui/components/dataTable.js";
import {
  addTeamMember,
  createTeam,
  deleteTeam,
  listTeamMembers,
  listTeams,
  removeTeamMember,
  updateTeam,
} from "../../api/teams.js";
import { listUsers } from "../../api/users.js";
import { setSessionTeams } from "../../state/store.js";
import { me } from "../../api/auth.js";

async function refreshSessionTeams() {
  try {
    const fresh = await me();
    setSessionTeams(fresh?.teams || [], fresh?.current_team_id ?? null);
  } catch {
    // ignore — background refresh
  }
}

export async function AdminTeamsView() {
  const teamsTableContainer = el("div");
  const membersSection = el("div", { class: "card mt-12", style: "display:none;" });
  let selectedTeam = null;

  const nameInput = el("input", { class: "input", placeholder: "Team name", required: "true" });
  const slugInput = el("input", { class: "input", placeholder: "team-slug (optional)" });
  const descInput = el("input", { class: "input", placeholder: "Description (optional)" });
  const createBtn = el("button", { class: "btn primary", type: "submit" }, "Create team");

  const createForm = el(
    "form",
    { class: "row gap-8 flex-wrap" },
    nameInput,
    slugInput,
    descInput,
    createBtn,
  );

  createForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    const name = nameInput.value.trim();
    if (!name) {
      toast({ title: "Missing field", message: "Team name is required." });
      return;
    }
    createBtn.disabled = true;
    try {
      await createTeam({
        name,
        slug: slugInput.value.trim() || undefined,
        description: descInput.value.trim() || undefined,
      });
      nameInput.value = "";
      slugInput.value = "";
      descInput.value = "";
      toast({ title: "Team created", message: name });
      await loadTeams();
      await refreshSessionTeams();
    } catch (err) {
      toast({ title: "Create failed", message: err?.message || "Unable to create team" });
    } finally {
      createBtn.disabled = false;
    }
  });

  async function onRenameTeam(team) {
    const nextName = window.prompt(`Rename team "${team.name}" to:`, team.name);
    if (!nextName || nextName.trim() === team.name) return;
    try {
      await updateTeam(team.id, { name: nextName.trim() });
      toast({ title: "Team renamed", message: nextName.trim() });
      await loadTeams();
      await refreshSessionTeams();
    } catch (err) {
      toast({ title: "Rename failed", message: err?.message || "Unable to rename team" });
    }
  }

  async function onDeleteTeam(team) {
    const ok = window.confirm(
      `Delete team "${team.name}"? This cannot be undone. Products in this team must be reassigned first.`,
    );
    if (!ok) return;
    try {
      await deleteTeam(team.id);
      toast({ title: "Team deleted", message: team.name });
      if (selectedTeam?.id === team.id) {
        selectedTeam = null;
        membersSection.style.display = "none";
      }
      await loadTeams();
      await refreshSessionTeams();
    } catch (err) {
      toast({ title: "Delete failed", message: err?.message || "Unable to delete team" });
    }
  }

  async function onManageMembers(team) {
    selectedTeam = team;
    membersSection.style.display = "block";
    await renderMembers();
  }

  async function renderMembers() {
    membersSection.innerHTML = "";
    if (!selectedTeam) return;
    membersSection.appendChild(el("div", { class: "row gap-8 flex-between" },
      el("h3", { style: "margin:0;", text: `Members of ${selectedTeam.name}` }),
      el("button", { class: "btn", onclick: () => { selectedTeam = null; membersSection.style.display = "none"; } }, "Close"),
    ));

    const memberTableContainer = el("div", { class: "mt-8" });
    membersSection.appendChild(memberTableContainer);
    memberTableContainer.appendChild(el("div", { class: "muted", text: "Loading…" }));

    let members = [];
    try {
      const res = await listTeamMembers(selectedTeam.id);
      members = res?.items || [];
    } catch (err) {
      memberTableContainer.innerHTML = "";
      memberTableContainer.appendChild(el("div", { class: "muted", text: err?.message || "Unable to load members" }));
      return;
    }

    memberTableContainer.innerHTML = "";
    memberTableContainer.appendChild(createDataTable({
      columns: [
        { key: "username", label: "Username" },
        { key: "role", label: "Role" },
        { key: "is_default", label: "Default?", render: (r) => (r.is_default ? "Yes" : "") },
        { key: "joined_at", label: "Joined", render: (r) => (r.joined_at || "").slice(0, 10) },
      ],
      rows: members,
      emptyText: "No members yet.",
      rowActions: selectedTeam.is_default
        ? null
        : (row) => {
            const btn = el("button", { class: "btn" }, "Remove");
            btn.addEventListener("click", async () => {
              const ok = window.confirm(`Remove ${row.username} from ${selectedTeam.name}?`);
              if (!ok) return;
              try {
                await removeTeamMember(selectedTeam.id, row.user_id);
                toast({ title: "Member removed", message: row.username });
                await renderMembers();
                await refreshSessionTeams();
              } catch (err) {
                toast({ title: "Remove failed", message: err?.message || "Unable to remove member" });
              }
            });
            return btn;
          },
    }));

    // Add-member form
    const userSelect = el("select", { class: "input" });
    userSelect.appendChild(el("option", { value: "", text: "Select user…" }));
    try {
      const usersRes = await listUsers({ page: 1, page_size: 200 });
      const memberIds = new Set(members.map((m) => m.user_id));
      (usersRes?.items || []).forEach((u) => {
        if (memberIds.has(u.id)) return;
        userSelect.appendChild(el("option", { value: String(u.id) }, `${u.username} (${u.role})`));
      });
    } catch {
      // tolerate — no-op
    }

    const addBtn = el("button", { class: "btn primary", type: "submit" }, "Add member");
    const addForm = el("form", { class: "row gap-8 mt-8" }, userSelect, addBtn);
    addForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      const uid = Number(userSelect.value);
      if (!Number.isInteger(uid) || !uid) return;
      addBtn.disabled = true;
      try {
        await addTeamMember(selectedTeam.id, uid);
        toast({ title: "Member added", message: userSelect.options[userSelect.selectedIndex]?.text || "" });
        await renderMembers();
        await refreshSessionTeams();
      } catch (err) {
        toast({ title: "Add failed", message: err?.message || "Unable to add member" });
      } finally {
        addBtn.disabled = false;
      }
    });
    membersSection.appendChild(addForm);
  }

  async function loadTeams() {
    teamsTableContainer.innerHTML = "";
    teamsTableContainer.appendChild(el("div", { class: "muted", text: "Loading…" }));
    try {
      const res = await listTeams();
      const items = res?.items || [];
      teamsTableContainer.innerHTML = "";
      teamsTableContainer.appendChild(createDataTable({
        columns: [
          { key: "name", label: "Name" },
          { key: "slug", label: "Slug" },
          { key: "member_count", label: "Members" },
          { key: "is_default", label: "Default?", render: (r) => (r.is_default ? "Yes" : "") },
          { key: "description", label: "Description", render: (r) => r.description || "" },
        ],
        rows: items,
        emptyText: "No teams yet.",
        rowActions: (team) => {
          const manageBtn = el("button", { class: "btn" }, "Members");
          manageBtn.addEventListener("click", () => onManageMembers(team));
          const renameBtn = el("button", { class: "btn" }, "Rename");
          renameBtn.addEventListener("click", () => onRenameTeam(team));
          const buttons = [manageBtn, renameBtn];
          if (!team.is_default) {
            const delBtn = el("button", { class: "btn danger" }, "Delete");
            delBtn.addEventListener("click", () => onDeleteTeam(team));
            buttons.push(delBtn);
          }
          return el("div", { class: "row gap-6" }, ...buttons);
        },
      }));
    } catch (err) {
      teamsTableContainer.innerHTML = "";
      teamsTableContainer.appendChild(el("div", { class: "muted", text: err?.message || "Unable to load teams" }));
    }
  }

  loadTeams();

  return el("div", { class: "flex-col-12" },
    el("div", { class: "card" },
      el("h1", { class: "page-title", text: "Admin: Teams" }),
      el("p", { class: "muted", text: "Teams scope access to products, vulnerabilities, and related resources. Every user is a member of the Default team." }),
    ),
    el("div", { class: "card" },
      el("h3", { style: "margin-top:0;", text: "Create a team" }),
      createForm,
    ),
    el("div", { class: "card" },
      el("h3", { style: "margin-top:0;", text: "Teams" }),
      teamsTableContainer,
    ),
    membersSection,
  );
}
