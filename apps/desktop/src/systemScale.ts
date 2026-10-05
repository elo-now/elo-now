declare global {
  interface Window {
    eloAppearance?: {
      setDarkMode?(dark: boolean): void;
      setPreference?(preference: "dark" | "light" | "auto"): void;
      getTextScale?(): number;
      revealApp?(): void;
      /** Present only in an explicitly enabled local iOS diagnostic build. */
      recordUnlockFrame?(): void;
    };
  }
}

export async function readSystemTextScale(): Promise<number> {
  const android = window.eloAppearance?.getTextScale?.();
  if (typeof android === "number" && Number.isFinite(android)) return android;
  const ios = /iPhone|iPad|iPod/.test(navigator.userAgent);
  if (!ios || !CSS.supports("font", "-apple-system-body")) return 1;
  const probe = document.createElement("span");
  probe.style.cssText =
    "position:fixed;visibility:hidden;pointer-events:none;font:-apple-system-body";
  document.body.append(probe);
  const size = Number.parseFloat(getComputedStyle(probe).fontSize);
  probe.remove();
  return Number.isFinite(size) ? size / 17 : 1;
}
