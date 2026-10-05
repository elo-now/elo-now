export type Theme = "light" | "dark";
export type ThemePreference = Theme | "auto";
const preferenceKey = "elo.appearance";

export function readTheme(): ThemePreference {
  try {
    const value = localStorage.getItem(preferenceKey);
    return value === "light" || value === "auto" ? value : "dark";
  } catch {
    return "dark";
  }
}

export function resolveTheme(preference: ThemePreference): Theme {
  if (preference !== "auto") return preference;
  if (typeof window.matchMedia !== "function") return "dark";
  return window.matchMedia("(prefers-color-scheme: dark)").matches
    ? "dark"
    : "light";
}

export function watchSystemTheme(onChange: () => void): () => void {
  const query = window.matchMedia?.("(prefers-color-scheme: dark)");
  query?.addEventListener("change", onChange);
  window.addEventListener("focus", onChange);
  document.addEventListener("visibilitychange", onChange);
  return () => {
    query?.removeEventListener("change", onChange);
    window.removeEventListener("focus", onChange);
    document.removeEventListener("visibilitychange", onChange);
  };
}

export function applyTheme(preference: ThemePreference): Theme {
  const theme = resolveTheme(preference);
  document.documentElement.dataset.theme = theme;
  window.eloAppearance?.setDarkMode?.(theme === "dark");
  window.eloAppearance?.setPreference?.(preference);
  try {
    localStorage.setItem(preferenceKey, preference);
  } catch {
    // Keep the selected theme for this session if preference storage is blocked.
  }
  return theme;
}
