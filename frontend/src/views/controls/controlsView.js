import { el } from "../../ui/dom/el.js";
import { listControls, createControl } from "../../api/controls.js";
import { toast } from "../../ui/components/toast.js";
import { getState } from "../../state/store.js";
import { canWrite } from "../../state/permissions.js";

function formatDate(value) {
  if (!value) return "-";
  return value.slice(0, 10);
}

function renderFrameworkChip(framework) {
  const label = framework || "Unassigned";
  return el(
    "span",
    {
      class: "muted",
      style: "border: 1px solid rgba(255,255,255,0.18); padding: 2px 8px; border-radius: 999px;",
      text: label,
    },
  );
}

function renderControlCard(control) {
  return el(
    "div",
    { class: "card", style: "padding: 12px;" },
    el(
      "div",
      { class: "row", style: "justify-content: space-between; align-items: baseline; flex-wrap: wrap;" },
      el("div", { style: "font-weight: 600;", text: control.name || "Untitled control" }),
      renderFrameworkChip(control.framework),
    ),
    control.description
      ? el("p", { class: "muted", style: "margin: 8px 0 0;", text: control.description })
      : el("p", { class: "muted", style: "margin: 8px 0 0;", text: "No description provided." }),
    el(
      "div",
      { class: "row", style: "gap: 16px; margin-top: 10px; flex-wrap: wrap;" },
      el("div", {}, el("div", { class: "muted", text: "Created" }), el("div", { text: formatDate(control.created_at) })),
      el("div", {}, el("div", { class: "muted", text: "Updated" }), el("div", { text: formatDate(control.updated_at) })),
    ),
  );
}

export async function ControlsView() {
  const writable = canWrite(getState());
  const list = el("div", { style: "display: flex; flex-direction: column; gap: 10px; margin-top: 12px;" });
  const summary = el("div", { class: "muted", text: "Loading controls..." });
  const createToggle = el("button", { class: "btn primary", type: "button" }, "New control");
  const createName = el("input", { class: "input", placeholder: "Control name", required: "true", "aria-label": "Control name" });
  const createFramework = el("input", { class: "input", placeholder: "Framework (optional)", "aria-label": "Framework" });
  const createDescription = el("textarea", { class: "input", placeholder: "Description (optional)", "aria-label": "Description" });
  const createSubmit = el("button", { class: "btn", type: "submit" }, "Create control");

  const createForm = el(
    "form",
    { style: "display: flex; flex-direction: column; gap: 8px; margin-top: 12px;" },
    el("div", {}, el("div", { class: "muted", text: "New control" }), createName),
    el("div", {}, el("div", { class: "muted", text: "Framework" }), createFramework),
    el("div", {}, el("div", { class: "muted", text: "Description" }), createDescription),
    el("div", { class: "row", style: "justify-content: flex-end;" }, createSubmit),
  );

  const createCard = el(
    "div",
    { class: "card", style: "margin-top: 12px; display: none;" },
    el("h3", { style: "margin-top: 0;", text: "Add control" }),
    el("p", { class: "muted", text: "Create a new control for the shared inventory." }),
    createForm,
  );

  const page = el(
    "div",
    { class: "card" },
    el("h1", { class: "page-title", text: "Controls" }),
    el("p", { class: "muted", text: "Browse the full inventory of security controls." }),
    el("div", { class: "row", style: "justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 8px; margin: 12px 0;" }, summary, writable ? createToggle : null),
    writable ? createCard : null,
    list,
  );

  async function loadControls() {
    try {
      const controls = await listControls();
      summary.textContent = `${controls.length} control${controls.length === 1 ? "" : "s"} total.`;
      list.innerHTML = "";
      if (!controls.length) {
        list.appendChild(el("div", { class: "muted", text: "No controls found yet." }));
      } else {
        controls.forEach((control) => {
          list.appendChild(renderControlCard(control));
        });
      }
    } catch (err) {
      summary.textContent = "Unable to load controls.";
      list.innerHTML = "";
      list.appendChild(el("div", { class: "muted", text: "Try refreshing in a moment." }));
      toast({ title: "Failed to load controls", message: err?.message || "Unable to list controls" });
    }
  }

  if (writable) {
    createToggle.addEventListener("click", () => {
      const next = createCard.style.display === "none";
      createCard.style.display = next ? "block" : "none";
      if (next) {
        createName.focus();
      }
    });
  }

  if (writable) {
    createForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      const name = createName.value.trim();
      if (!name) {
        toast({ title: "Name required", message: "Please enter a control name." });
        return;
      }
      createSubmit.disabled = true;
      try {
        const created = await createControl({
          name,
          framework: createFramework.value.trim() || undefined,
          description: createDescription.value.trim() || undefined,
        });
        toast({ title: "Control created", message: `${created.name} added.` });
        createName.value = "";
        createFramework.value = "";
        createDescription.value = "";
        createCard.style.display = "none";
        await loadControls();
      } catch (err) {
        toast({ title: "Failed", message: err?.message || "Unable to create control" });
      } finally {
        createSubmit.disabled = false;
      }
    });
  }

  loadControls();

  return page;
}
