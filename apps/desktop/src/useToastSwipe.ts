import { useEffect, useRef, type RefObject } from "react";

/** Dismiss a banner without activating its Read/Details action or the page below. */
export function useToastSwipe(
  ref: RefObject<HTMLElement | null>,
  onDismiss: () => void,
) {
  const dismiss = useRef(onDismiss);
  dismiss.current = onDismiss;
  useEffect(() => {
    const node = ref.current;
    if (!node) return;
    let start: { id: number; x: number; y: number } | undefined;
    let acquired = false;
    let suppressClick = false;
    const reset = () => {
      start = undefined;
      acquired = false;
    };
    const begin = (event: TouchEvent) => {
      event.stopPropagation();
      reset();
      suppressClick = false;
      if (event.touches.length !== 1) return;
      const text =
        event.target instanceof Element
          ? event.target.closest<HTMLElement>(".toast-message")
          : null;
      // Long summaries keep their own scrolling. The close-button area still swipes.
      if (text && text.scrollHeight > text.clientHeight + 1) return;
      const touch = event.touches[0];
      start = { id: touch.identifier, x: touch.clientX, y: touch.clientY };
    };
    const move = (event: TouchEvent) => {
      event.stopPropagation();
      if (!start) return;
      const touch = event.touches[0];
      if (event.touches.length !== 1 || touch.identifier !== start.id) {
        reset();
        return;
      }
      const up = start.y - touch.clientY;
      const across = Math.abs(touch.clientX - start.x);
      if (!acquired && Math.max(Math.abs(up), across) < 8) return;
      if (up <= 0 || up < across * 1.3 || !event.cancelable) {
        reset();
        return;
      }
      event.preventDefault();
      acquired = true;
    };
    const end = (event: TouchEvent) => {
      event.stopPropagation();
      if (!start || !acquired) {
        reset();
        return;
      }
      event.preventDefault();
      suppressClick = true;
      const touch = [...event.changedTouches].find(
        (t) => t.identifier === start!.id,
      );
      const finish =
        event.touches.length === 0 &&
        touch &&
        start.y - touch.clientY >= 32 &&
        start.y - touch.clientY >= Math.abs(touch.clientX - start.x) * 1.3;
      reset();
      if (finish) dismiss.current();
    };
    const click = (event: MouseEvent) => {
      if (suppressClick && event.detail !== 0) {
        event.preventDefault();
        event.stopImmediatePropagation();
      }
      suppressClick = false;
    };
    node.addEventListener("touchstart", begin, { passive: true });
    node.addEventListener("touchmove", move, { passive: false });
    node.addEventListener("touchend", end, { passive: false });
    node.addEventListener("touchcancel", reset);
    node.addEventListener("click", click, true);
    return () => {
      node.removeEventListener("touchstart", begin);
      node.removeEventListener("touchmove", move);
      node.removeEventListener("touchend", end);
      node.removeEventListener("touchcancel", reset);
      node.removeEventListener("click", click, true);
    };
  }, [ref]);
}
