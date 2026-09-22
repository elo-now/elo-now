import { useEffect } from "react";

/** WebKit can treat modal autofocus and focus restoration as keyboard input.
 * Track navigation keys explicitly so touch never inherits a focus ring. */
export function useInputModality() {
  useEffect(() => {
    const root = document.documentElement;
    root.dataset.focusInput = "pointer";
    const pointer = () => {
      root.dataset.focusInput = "pointer";
    };
    const keyboard = (event: KeyboardEvent) => {
      if (
        !event.altKey &&
        !event.ctrlKey &&
        !event.metaKey &&
        [
          "Tab",
          "ArrowUp",
          "ArrowDown",
          "ArrowLeft",
          "ArrowRight",
          "Home",
          "End",
          "Escape",
        ].includes(event.key)
      )
        root.dataset.focusInput = "keyboard";
    };
    document.addEventListener("pointerdown", pointer, true);
    document.addEventListener("keydown", keyboard, true);
    return () => {
      document.removeEventListener("pointerdown", pointer, true);
      document.removeEventListener("keydown", keyboard, true);
      delete root.dataset.focusInput;
    };
  }, []);
}
