import { useEffect } from "react";

type ViewportState = {
  layoutWidth: number;
  fullHeight: number;
  keyboardOpen: boolean;
};

export function updateKeyboardViewport(
  previous: ViewportState | undefined,
  current: {
    layoutWidth: number;
    layoutHeight: number;
    height: number;
    scale: number;
    editing: boolean;
  },
): ViewportState {
  // Pinch zoom shrinks the visual viewport without opening the keyboard.
  const visibleHeight = current.height * current.scale;
  const widthChanged = previous?.layoutWidth !== current.layoutWidth;
  const wasOpen = !widthChanged && !!previous?.keyboardOpen;
  // Some WebViews shrink both viewports for the keyboard. Keep their previous
  // height during editing, but discard it after rotation or an unfocused resize.
  const fullHeight = Math.max(
    widthChanged || (!wasOpen && !current.editing)
      ? 0
      : (previous?.fullHeight ?? 0),
    current.layoutHeight,
    visibleHeight,
  );
  return {
    layoutWidth: current.layoutWidth,
    fullHeight,
    // A temporary blur during a composer tap must not restore the safe-area
    // inset while the keyboard still occupies the same viewport space.
    keyboardOpen:
      (wasOpen || current.editing) && fullHeight - visibleHeight > 120,
  };
}

/** Keep the phone shell inside the area left visible by the native keyboard. */
export function useViewport() {
  useEffect(() => {
    const viewport = window.visualViewport;
    const style = document.documentElement.style;
    let frame = 0;
    let state: ViewportState | undefined;
    const update = () => {
      cancelAnimationFrame(frame);
      frame = requestAnimationFrame(() => {
        const height = viewport?.height ?? window.innerHeight;
        state = updateKeyboardViewport(state, {
          layoutWidth: window.innerWidth,
          layoutHeight: window.innerHeight,
          height,
          scale: viewport?.scale ?? 1,
          editing: !!document.activeElement?.matches(
            "input, textarea, [contenteditable='true']",
          ),
        });
        const { fullHeight, keyboardOpen } = state;
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
