import { apiFetch } from "./client.js";

export async function listMyTeams() {
  return apiFetch("/api/me/teams", { method: "GET" });
}

export async function listTeams() {
  return apiFetch("/api/teams", { method: "GET" });
}

export async function createTeam({ name, slug, description }) {
  return apiFetch("/api/teams", {
    method: "POST",
    body: { name, slug, description },
  });
}

export async function updateTeam(teamId, data) {
  return apiFetch(`/api/teams/${teamId}`, { method: "PATCH", body: data });
}

export async function deleteTeam(teamId) {
  return apiFetch(`/api/teams/${teamId}`, { method: "DELETE" });
}

export async function listTeamMembers(teamId) {
  return apiFetch(`/api/teams/${teamId}/members`, { method: "GET" });
}

export async function addTeamMember(teamId, userId) {
  return apiFetch(`/api/teams/${teamId}/members`, {
    method: "POST",
    body: { user_id: userId },
  });
}

export async function removeTeamMember(teamId, userId) {
  return apiFetch(`/api/teams/${teamId}/members/${userId}`, { method: "DELETE" });
}
