/** Intersection alone does not mean the person is looking at the conversation. */
export function canReadVisibleMessages() {
  return (
    !document.hidden &&
    (!document.documentElement.dataset.windowPlatform || document.hasFocus()) &&
    !document.querySelector("dialog[open]")
  );
}
