import { useEffect, useLayoutEffect, useRef, useState } from "react";
import { MessageEntrance } from "./messageEntrance";
import type { MessageRow } from "./messageThreads";
import "./messageMotion.css";

/** Run on committed nodes once, rather than attaching an animation to a row's
 * render output. A virtualized or remounted row therefore cannot replay it. */
export function useMessageEntrance(
  scope: string,
  rows: readonly MessageRow[],
  active: boolean,
) {
  const list = useRef<HTMLDivElement>(null);
  const [tracker] = useState(() => new MessageEntrance());
  const previousScope = useRef(scope);
  const running = useRef(new Map<HTMLElement, () => void>());
  const stop = () => {
    for (const finish of running.current.values()) finish();
  };
  useLayoutEffect(() => {
    if (previousScope.current !== scope) stop();
    previousScope.current = scope;
    const visible = active && document.visibilityState === "visible";
    const arriving = tracker.observe(scope, rows, visible, Date.now());
    if (!visible) stop();
    if (
      !list.current ||
      !arriving.length ||
      window.matchMedia("(prefers-reduced-motion: reduce)").matches
    )
      return;
    const viewport = list.current.querySelector<HTMLElement>(".messages");
    if (!viewport) return;
    const arrivals = new Set(arriving);
    for (const node of viewport.querySelectorAll<HTMLElement>(
      ".message[data-record-id]",
    )) {
      if (!arrivals.has(node.dataset.recordId!)) continue;
      // Follow-latest scrolling settles in the next frame. Start on the new
      // node now; an offscreen arrival also consumes its motion exactly once.
      const finish = () => {
        clearTimeout(timer);
        node.classList.remove("message-enter");
        node.removeEventListener("animationend", finish);
        running.current.delete(node);
      };
      const timer = setTimeout(finish, 200);
      running.current.set(node, finish);
      node.addEventListener("animationend", finish);
      node.classList.add("message-enter");
    }
  }, [scope, rows, active, tracker]);
  useEffect(() => {
    const pause = () => {
      tracker.pause();
      stop();
    };
    document.addEventListener("visibilitychange", pause);
    window.addEventListener("pageshow", pause);
    return () => {
      document.removeEventListener("visibilitychange", pause);
      window.removeEventListener("pageshow", pause);
      pause();
    };
  }, []);
  return {
    list,
    receive: (receivedRows: readonly MessageRow[], ids: readonly string[]) => {
      if (active && document.visibilityState === "visible")
        tracker.receive(scope, receivedRows, ids, Date.now());
    },
  };
}
