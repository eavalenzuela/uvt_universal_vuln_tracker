import { el } from "../../ui/dom/el.js";
import { toast } from "../../ui/components/toast.js";
import { getMyPreferences, updateMyPreferences } from "../../api/userPreferences.js";

const THEMES = [
  { value: "auto", label: "Match system" },
  { value: "light", label: "Light" },
  { value: "dark", label: "Dark" },
];

const DIGESTS = [
  { value: "off", label: "Off" },
  { value: "daily", label: "Daily" },
  { value: "weekly", label: "Weekly" },
];

const COMMON_TIMEZONES = [
  "UTC",
  "America/Los_Angeles",
  "America/Denver",
  "America/Chicago",
  "America/New_York",
  "Europe/London",
  "Europe/Berlin",
  "Europe/Athens",
  "Asia/Tokyo",
  "Australia/Sydney",
];

function selectInput(id, label, options, value) {
  const select = el("select", { class: "input", id });
  for (const opt of options) {
    const optEl = el("option", { value: opt.value }, opt.label);
    if (opt.value === value) optEl.setAttribute("selected", "true");
    select.appendChild(optEl);
  }
  return el(
    "label",
    { class: "flex-col", style: "gap:4px" },
    el("span", { class: "muted" }, label),
    select,
  );
}

function checkboxInput(id, label, checked) {
  const cb = el("input", { type: "checkbox", id });
  if (checked) cb.setAttribute("checked", "true");
  return el(
    "label",
    { class: "row gap-8 items-center", style: "padding:4px 0" },
    cb,
    el("span", {}, label),
  );
}

export async function SettingsView() {
  const page = el("div", { class: "flex-col-10 p-16", style: "max-width:720px" });
  page.appendChild(el("h2", { class: "m-0" }, "Settings"));
  page.appendChild(el("p", { class: "muted m-0" }, "Your personal preferences. Saved per account."));

  const status = el("div", { class: "muted" }, "Loading…");
  page.appendChild(status);

  let prefs;
  try {
    prefs = await getMyPreferences();
  } catch (err) {
    status.textContent = `Failed to load preferences: ${err?.message || "unknown error"}`;
    return page;
  }
  status.remove();

  const tzOptions = [...new Set([prefs.timezone, ...COMMON_TIMEZONES])].map((tz) => ({
    value: tz,
    label: tz,
  }));

  const tzField = selectInput("pref-timezone", "Timezone", tzOptions, prefs.timezone);
  const themeField = selectInput("pref-theme", "Theme", THEMES, prefs.theme);
  const digestField = selectInput("pref-digest", "Email digest", DIGESTS, prefs.email_digest_frequency);

  const notifyMention = checkboxInput("pref-notify-mention", "Notify me when mentioned", prefs.notify_on_mention);
  const notifyAssignment = checkboxInput("pref-notify-assignment", "Notify me on vulnerability assignment", prefs.notify_on_assignment);
  const notifyWatch = checkboxInput("pref-notify-watch", "Notify me on watched vulnerability updates", prefs.notify_on_watched_vuln_update);
  const notifySla = checkboxInput("pref-notify-sla", "Notify me on SLA breach", prefs.notify_on_sla_breach);

  const saveBtn = el("button", { class: "btn primary", type: "submit" }, "Save preferences");

  const form = el(
    "form",
    { class: "flex-col-10 card p-16" },
    el("h3", { class: "m-0" }, "Display"),
    tzField,
    themeField,
    el("h3", { class: "m-0", style: "margin-top:16px" }, "Notifications"),
    notifyMention,
    notifyAssignment,
    notifyWatch,
    notifySla,
    digestField,
    el("div", { class: "row flex-end" }, saveBtn),
  );

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    saveBtn.disabled = true;
    const patch = {
      timezone: form.querySelector("#pref-timezone").value,
      theme: form.querySelector("#pref-theme").value,
      email_digest_frequency: form.querySelector("#pref-digest").value,
      notify_on_mention: form.querySelector("#pref-notify-mention").checked,
      notify_on_assignment: form.querySelector("#pref-notify-assignment").checked,
      notify_on_watched_vuln_update: form.querySelector("#pref-notify-watch").checked,
      notify_on_sla_breach: form.querySelector("#pref-notify-sla").checked,
    };
    try {
      await updateMyPreferences(patch);
      toast({ title: "Preferences saved", message: "Your settings are up to date." });
    } catch (err) {
      toast({ title: "Save failed", message: err?.message || "Unable to save preferences." });
    } finally {
      saveBtn.disabled = false;
    }
  });

  page.appendChild(form);
  return page;
}
