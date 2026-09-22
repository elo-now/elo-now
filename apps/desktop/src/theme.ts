export type Theme = "light" | "dark";
const preferenceKey = "elo.appearance";

export function readTheme(): Theme {
  try {
    return localStorage.getItem(preferenceKey) === "dark" ? "dark" : "light";
  } catch {
    return "light";
  }
}

export function applyTheme(theme: Theme): void {
  document.documentElement.dataset.theme = theme;
  window.eloAppearance?.setDarkMode(theme === "dark");
  try {
    localStorage.setItem(preferenceKey, theme);
  } catch {
    // Keep the selected theme for this session if preference storage is blocked.
  }
}
