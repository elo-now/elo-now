export type ViewMode = "default" | "expert";
export function readViewMode(): ViewMode {
  try {
    return localStorage.getItem("elo.viewMode") === "expert"
      ? "expert"
      : "default";
  } catch {
    return "default";
  }
}
export function saveViewMode(mode: ViewMode): void {
  try {
    localStorage.setItem("elo.viewMode", mode);
  } catch {
    /* The view preference may remain session-only. */
  }
}
