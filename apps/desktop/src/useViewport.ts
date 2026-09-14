import { useEffect } from "react";

/** Keep the phone shell inside the area left visible by the native keyboard. */
export function useViewport() {
  useEffect(() => {
    const viewport = window.visualViewport;
    const style = document.documentElement.style;
    let frame = 0;
    let fullHeight = viewport?.height ?? window.innerHeight;
    let layoutWidth = window.innerWidth;
    const update = () => {
      cancelAnimationFrame(frame);
      frame = requestAnimationFrame(() => {
        const height = viewport?.height ?? window.innerHeight;
        // Some WebViews resize both layout and visual viewports for the IME.
        // Keep the unfocused height instead of comparing two shrunken values.
        if (window.innerWidth !== layoutWidth) {
          layoutWidth = window.innerWidth;
          fullHeight = window.innerHeight;
        }
        fullHeight = Math.max(fullHeight, height, window.innerHeight);
        const editing = document.activeElement?.matches(
          "input, textarea, [contenteditable='true']",
        );
        const keyboardOpen = !!editing && fullHeight - height > 120;
        document.documentElement.dataset.keyboardOpen = String(keyboardOpen);
        // iOS already reserves the keyboard area in its visual viewport.
        // Keep the home-indicator inset only when that keyboard is closed.
        style.setProperty(
          "--app-content-bottom-inset",
          keyboardOpen ? "0px" : "env(safe-area-inset-bottom)",
        );
        style.setProperty("--app-viewport-height", `${height}px`);
        style.setProperty("--app-layout-height", `${fullHeight}px`);
        // Keep document-positioned artwork anchored while iOS scrolls for IME.
        style.setProperty(
          "--app-layout-top",
          `${window.scrollY + (viewport?.offsetTop ?? 0)}px`,
        );
        style.setProperty(
          "--app-viewport-top",
          `${viewport?.offsetTop ?? 0}px`,
        );
      });
    };
    update();
    viewport?.addEventListener("resize", update);
    viewport?.addEventListener("scroll", update);
    window.addEventListener("resize", update);
    window.addEventListener("scroll", update, { passive: true });
    document.addEventListener("focusin", update);
    document.addEventListener("focusout", update);
    return () => {
      cancelAnimationFrame(frame);
      viewport?.removeEventListener("resize", update);
      viewport?.removeEventListener("scroll", update);
      window.removeEventListener("resize", update);
      window.removeEventListener("scroll", update);
      document.removeEventListener("focusin", update);
      document.removeEventListener("focusout", update);
      style.removeProperty("--app-viewport-height");
      style.removeProperty("--app-viewport-top");
      style.removeProperty("--app-content-bottom-inset");
      style.removeProperty("--app-layout-height");
      style.removeProperty("--app-layout-top");
      delete document.documentElement.dataset.keyboardOpen;
    };
  }, []);
}
