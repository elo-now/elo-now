import { useEffect } from "react";

declare global {
  interface Window {
    eloHandleBack?: () => boolean;
  }
}

/** Android asks the current UI before falling back to leaving the activity. */
export function handleSystemBack(): boolean {
  const visible = (element: Element) =>
    element.getBoundingClientRect().height > 0;
  const dialog = [
    ...document.querySelectorAll<HTMLDialogElement>("dialog[open]"),
  ]
    .filter(visible)
    .at(-1);
  if (dialog) {
    const event = new Event("cancel", { cancelable: true });
    if (dialog.dispatchEvent(event)) dialog.close();
    return true;
  }
  const menu = [...document.querySelectorAll<HTMLElement>('[role="menu"]')]
    .filter(visible)
    .at(-1);
  if (menu) {
    menu.dispatchEvent(
      new KeyboardEvent("keydown", { key: "Escape", bubbles: true }),
    );
    return true;
  }
  const back = [
    ...document.querySelectorAll<HTMLButtonElement>("[data-system-back]"),
  ]
    .filter(visible)
    .at(-1);
  if (!back) return false;
  if (!back.disabled) back.click();
  return true;
}

export function useSystemBack() {
  useEffect(() => {
    window.eloHandleBack = handleSystemBack;
    return () => {
      delete window.eloHandleBack;
    };
  }, []);
}
