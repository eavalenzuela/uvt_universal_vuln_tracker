import { el } from "../../ui/dom/el.js";
import { toast } from "../../ui/components/toast.js";
import {
  deleteBrandingLogo,
  getBranding,
  updateBranding,
  uploadBrandingLogo,
} from "../../api/branding.js";

export async function AdminBrandingView() {
  const root = el("div", { class: "flex-col-12" });
  const header = el("div", { class: "flex-col-6" },
    el("h1", { class: "page-title", text: "PDF Report Branding" }),
    el("p", { class: "muted", text: "Admin-only. Applies to all rendered PDF reports (default and executive summary layouts)." }),
  );

  const colorInput = el("input", { type: "color", class: "input", style: "max-width: 120px;" });
  const colorHexInput = el("input", { type: "text", class: "input", maxlength: "7", placeholder: "#2563eb", style: "max-width: 120px;" });
  const footerInput = el("input", { type: "text", class: "input", maxlength: "255", placeholder: "Confidential — do not redistribute" });
  const saveBtn = el("button", { class: "btn primary", type: "button" }, "Save settings");

  const logoStatus = el("p", { class: "muted" }, "No logo uploaded.");
  const logoFileInput = el("input", { type: "file", accept: ".png,.svg,.jpg,.jpeg,image/png,image/svg+xml,image/jpeg" });
  const uploadBtn = el("button", { class: "btn", type: "button" }, "Upload logo");
  const removeBtn = el("button", { class: "btn", type: "button" }, "Remove logo");

  function syncColorInputs(hex) {
    colorInput.value = hex;
    colorHexInput.value = hex;
  }

  colorInput.addEventListener("input", () => {
    colorHexInput.value = colorInput.value;
  });
  colorHexInput.addEventListener("change", () => {
    if (/^#[0-9a-fA-F]{6}$/.test(colorHexInput.value)) {
      colorInput.value = colorHexInput.value;
    }
  });

  async function refresh() {
    try {
      const data = await getBranding();
      syncColorInputs((data.primary_color || "#2563eb").toLowerCase());
      footerInput.value = data.footer_text || "";
      logoStatus.textContent = data.has_logo ? "Logo uploaded." : "No logo uploaded.";
      removeBtn.disabled = !data.has_logo;
    } catch (err) {
      toast({ title: "Load failed", message: err?.message || "Unable to load branding settings" });
    }
  }

  saveBtn.addEventListener("click", async () => {
    saveBtn.disabled = true;
    try {
      const hex = colorHexInput.value.trim();
      if (!/^#[0-9a-fA-F]{6}$/.test(hex)) {
        toast({ title: "Invalid color", message: "Primary color must be a 6-digit hex like #2563eb." });
        return;
      }
      await updateBranding({ primary_color: hex.toLowerCase(), footer_text: footerInput.value });
      toast({ title: "Branding saved" });
      await refresh();
    } catch (err) {
      toast({ title: "Save failed", message: err?.message || "Unable to save branding" });
    } finally {
      saveBtn.disabled = false;
    }
  });

  uploadBtn.addEventListener("click", async () => {
    const file = logoFileInput.files?.[0];
    if (!file) {
      toast({ title: "No file selected" });
      return;
    }
    uploadBtn.disabled = true;
    try {
      await uploadBrandingLogo(file);
      toast({ title: "Logo uploaded" });
      logoFileInput.value = "";
      await refresh();
    } catch (err) {
      toast({ title: "Upload failed", message: err?.message || "Unable to upload logo" });
    } finally {
      uploadBtn.disabled = false;
    }
  });

  removeBtn.addEventListener("click", async () => {
    if (!window.confirm("Remove the current logo?")) return;
    removeBtn.disabled = true;
    try {
      await deleteBrandingLogo();
      toast({ title: "Logo removed" });
      await refresh();
    } catch (err) {
      toast({ title: "Remove failed", message: err?.message || "Unable to remove logo" });
    } finally {
      removeBtn.disabled = false;
    }
  });

  const settingsCard = el("div", { class: "card" },
    el("h2", { class: "page-subtitle", text: "Theme" }),
    el("div", { class: "flex-col-6" },
      el("label", {}, "Primary color"),
      el("div", { class: "row gap-8 flex-wrap" }, colorInput, colorHexInput),
      el("p", { class: "muted", text: "Used for KPI tile borders, chart accents, and the header rule on every PDF." }),
    ),
    el("div", { class: "flex-col-6 mt-12" },
      el("label", {}, "Footer text"),
      footerInput,
      el("p", { class: "muted", text: "Optional. Appears bottom-left of every page. Page number always shown bottom-right." }),
    ),
    el("div", { class: "row gap-8 mt-12" }, saveBtn),
  );

  const logoCard = el("div", { class: "card mt-12" },
    el("h2", { class: "page-subtitle", text: "Logo" }),
    logoStatus,
    el("p", { class: "muted", text: "PNG, SVG, or JPEG. Max 1 MB. Rendered up to ~36pt tall in the report header." }),
    el("div", { class: "row gap-8 flex-wrap mt-12" }, logoFileInput, uploadBtn, removeBtn),
  );

  root.appendChild(header);
  root.appendChild(settingsCard);
  root.appendChild(logoCard);

  refresh();
  return root;
}
