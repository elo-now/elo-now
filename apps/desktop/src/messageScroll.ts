import { messageScrollTop } from "./streamFeed";

/** Keep a notification target visible while the native viewport and fonts settle.
 * Stop as soon as the reader interacts, so later updates never drag their history. */
export function settleMessageScroll(node: HTMLElement, target: HTMLElement) {
  let started = false;
  let stopped = false;
  let timer: ReturnType<typeof setTimeout> | undefined;
  let frame = 0;
  const stop = () => {
    stopped = true;
    observer.disconnect();
    clearTimeout(timer);
    cancelAnimationFrame(frame);
    for (const event of ["pointerdown", "touchstart", "wheel", "keydown"])
      window.removeEventListener(event, stop, true);
  };
  const align = () => {
    if (stopped || !node.clientHeight || !target.getClientRects().length)
      return;
    const bounds = node.getBoundingClientRect();
    const message = target.getBoundingClientRect();
    const top = bounds.top + node.clientTop;
    const bottom = top + node.clientHeight;
    if (!started) {
      node.scrollTop = messageScrollTop(
        node.scrollTop,
        top,
        node.clientHeight,
        message.top,
        message.height,
      );
      target.focus({ preventScroll: true });
      started = true;
      timer = setTimeout(stop, 1500);
    } else if (message.height > node.clientHeight) {
      node.scrollTop += message.top - top;
    } else if (message.bottom > bottom) {
      node.scrollTop += message.bottom - bottom;
    } else if (message.top < top) {
      node.scrollTop += message.top - top;
    }
  };
  const observer = new ResizeObserver(() => {
    cancelAnimationFrame(frame);
    frame = requestAnimationFrame(align);
  });
  observer.observe(node);
  // A preceding row can grow without changing the target's own size.
  node
    .querySelectorAll<HTMLElement>("[data-record-id]")
    .forEach((row) => observer.observe(row));
  for (const event of ["pointerdown", "touchstart", "wheel", "keydown"])
    window.addEventListener(event, stop, { capture: true, passive: true });
  align();
  return stop;
}
