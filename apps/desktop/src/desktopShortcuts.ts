export type ShortcutAction =
  | "switch"
  | "search"
  | "compose"
  | "attach"
  | "preferences"
  | "help"
  | "previous"
  | "next"
  | "unreadPrevious"
  | "unreadNext";

export function desktopShortcut(
  event: Pick<
    KeyboardEvent,
    | "key"
    | "metaKey"
    | "ctrlKey"
    | "altKey"
    | "shiftKey"
    | "isComposing"
    | "defaultPrevented"
    | "repeat"
  >,
  mac: boolean,
): ShortcutAction | undefined {
  if (event.defaultPrevented || event.isComposing || event.repeat) return;
  const key = event.key.toLowerCase();
  if (
    event.altKey &&
    !event.metaKey &&
    !event.ctrlKey &&
    ["arrowup", "arrowdown"].includes(key)
  )
    return key === "arrowup"
      ? event.shiftKey
        ? "unreadPrevious"
        : "previous"
      : event.shiftKey
        ? "unreadNext"
        : "next";
  if (
    event.altKey ||
    (mac ? !event.metaKey || event.ctrlKey : !event.ctrlKey || event.metaKey)
  )
    return;
  if (event.shiftKey) return key === "k" ? "compose" : undefined;
  const shortcuts: Partial<Record<string, ShortcutAction>> = {
    k: "switch",
    f: "search",
    n: "compose",
    o: "attach",
    ",": "preferences",
    "/": "help",
  };
  return shortcuts[key];
}
