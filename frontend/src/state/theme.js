const KEY = "uvt.theme.v1";

/**
 * Load the saved theme preference, falling back to the OS preference.
 * @returns {"dark" | "light"}
 */
export function loadTheme() {
  try {
    const stored = localStorage.getItem(KEY);
    if (stored === "dark" || stored === "light") return stored;
  } catch {
    // localStorage unavailable — fall through to OS preference.
  }
  return window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark";
}

/**
 * Persist and apply a theme.
 * @param {"dark" | "light"} theme
 */
export function setTheme(theme) {
  try {
    localStorage.setItem(KEY, theme);
  } catch {
    // Ignore — the toggle still works for the current session.
  }
  applyTheme(theme);
}

/**
 * Apply the theme to the document without saving.
 * @param {"dark" | "light"} theme
 */
export function applyTheme(theme) {
  if (theme === "light") {
    document.documentElement.setAttribute("data-theme", "light");
  } else {
    document.documentElement.removeAttribute("data-theme");
  }
}

/**
 * Toggle between dark and light themes.
 * @returns {"dark" | "light"} The new theme.
 */
export function toggleTheme() {
  const current = document.documentElement.getAttribute("data-theme") === "light" ? "light" : "dark";
  const next = current === "dark" ? "light" : "dark";
  setTheme(next);
  return next;
}
