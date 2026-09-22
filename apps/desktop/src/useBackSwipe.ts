import { useEffect, useRef, type RefObject } from "react";
import {
  backSwipeDirection,
  backSwipeStartArea,
  shouldFinishBackSwipe,
} from "./backSwipe";

/** Only a visible header with Back owns navigation. Tabs without Back, including
 * Buzz, never register handlers. A modal prevents its background from reacting. */
export function useBackSwipe(
  ref: RefObject<HTMLElement | null>,
  onBack?: () => void,
) {
  const callback = useRef(onBack);
  callback.current = onBack;
  useEffect(() => {
    if (!onBack) return;
    let start: { x: number; y: number; id: number } | undefined;
    let distance = 0;
    let last = { x: 0, time: 0, velocity: 0 };
    const reset = () => {
      start = undefined;
      distance = 0;
    };
    const available = () => {
      const header = ref.current;
      const modal = [
        ...document.querySelectorAll<HTMLDialogElement>("dialog[open]"),
      ].at(-1);
      return (
        callback.current &&
        header &&
        header.getBoundingClientRect().height > 0 &&
        (!modal || modal.contains(header))
      );
    };
    const begin = (event: TouchEvent) => {
      reset();
      if (
        !available() ||
        innerWidth > 760 ||
        event.touches.length !== 1 ||
        !(event.target instanceof Element)
      )
        return;
      const page = ref.current?.parentElement;
      if (
        !page?.contains(event.target) ||
        event.target.closest(
          'input, textarea, select, [contenteditable="true"], [role="slider"], [data-no-back-swipe]',
        )
      )
        return;
      const touch = event.touches[0];
      if (touch.clientX < 0 || touch.clientX > backSwipeStartArea(innerWidth))
        return;
      start = { x: touch.clientX, y: touch.clientY, id: touch.identifier };
      last = { x: 0, time: event.timeStamp, velocity: 0 };
    };
    const move = (event: TouchEvent) => {
      if (!start) return;
      if (!available() || event.touches.length !== 1) {
        reset();
        return;
      }
      const touch = event.touches[0];
      const dx = touch.clientX - start.x;
      const direction = backSwipeDirection(dx, touch.clientY - start.y);
      if (touch.identifier !== start.id || direction === "cancel") {
        reset();
        return;
      }
      if (direction === "wait" && !distance) return;
      if (!event.cancelable) {
        reset();
        return;
      }
      event.preventDefault();
      event.stopPropagation();
      distance = Math.max(0, Math.min(innerWidth, dx));
      const elapsed = event.timeStamp - last.time;
      last = {
        x: distance,
        time: event.timeStamp,
        velocity: elapsed > 0 ? (distance - last.x) / elapsed : 0,
      };
    };
    const end = (event: TouchEvent) => {
      if (!start) return;
      const velocity = event.timeStamp - last.time < 100 ? last.velocity : 0;
      const finish =
        !!available() && shouldFinishBackSwipe(distance, innerWidth, velocity);
      if (distance > 0) {
        event.preventDefault();
        event.stopPropagation();
      }
      reset();
      // The header owns the same transition for a swipe and a Back tap.
      if (finish) callback.current?.();
    };
    const cancel = reset;
    document.addEventListener("touchstart", begin, {
      passive: true,
      capture: true,
    });
    document.addEventListener("touchmove", move, {
      passive: false,
      capture: true,
    });
    document.addEventListener("touchend", end, {
      passive: false,
      capture: true,
    });
    document.addEventListener("touchcancel", cancel, true);
    window.addEventListener("resize", cancel);
    return () => {
      reset();
      document.removeEventListener("touchstart", begin, true);
      document.removeEventListener("touchmove", move, true);
      document.removeEventListener("touchend", end, true);
      document.removeEventListener("touchcancel", cancel, true);
      window.removeEventListener("resize", cancel);
    };
  }, [!!onBack, ref]);
}
