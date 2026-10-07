import {
  useLayoutEffect,
  useRef,
  useState,
  type ReactNode,
  type PointerEvent,
} from "react";
import { createPortal } from "react-dom";
import { GripVertical } from "lucide-react";
import { t } from "../i18n";
import {
  floatingAnchor,
  floatingPosition,
  type FloatingBounds,
  type Point,
} from "./floatingPosition";

/** Only the controls float; media and the call controller keep their existing lifetime. */
export function FloatingCall({
  title,
  children,
  label,
  hidden = false,
}: {
  title: ReactNode;
  children: ReactNode;
  label: string;
  hidden?: boolean;
}) {
  const [layer] = useState(() => {
    if (typeof document === "undefined") return null;
    const element = document.createElement("div");
    element.className = "call-widget-layer";
    return element;
  });
  const widget = useRef<HTMLElement>(null);
  const anchor = useRef<Point>({
    x: typeof innerWidth === "number" && innerWidth >= 768 ? 1 : 0,
    y: 1,
  });
  const bounds = useRef<FloatingBounds>({
    left: 0,
    top: 0,
    width: 0,
    height: 0,
  });
  const drag = useRef<{ id: number; pointer: Point; origin: Point } | null>(
    null,
  );
  const reposition = useRef(() => {});

  useLayoutEffect(() => {
    if (!layer) return;
    let frame = 0;
    const observed = new Set<Element>();
    const schedule = () => {
      cancelAnimationFrame(frame);
      frame = requestAnimationFrame(measure);
    };
    const resize = new ResizeObserver(schedule);
    function measure() {
      // Full-page mobile workflows use the top layer. Ordinary confirmation
      // dialogs still cover/inert the widget, as they do the rest of the app.
      const pages = document.querySelectorAll<HTMLDialogElement>(
        "dialog.page-surface[open]",
      );
      const host = pages[pages.length - 1] ?? document.body;
      if (layer!.parentElement !== host) host.append(layer!);
      const node = widget.current;
      if (!node) return;
      for (const element of [layer!, node])
        if (!observed.has(element)) {
          resize.observe(element);
          observed.add(element);
        }
      if (!node.offsetHeight) return;
      const area = layer!.getBoundingClientRect();
      let top = area.top;
      let bottom = area.bottom;
      const next = new Set<Element>([layer!, node]);
      for (const element of host.querySelectorAll<HTMLElement>(
        ".screen-header, .composer, .mobile-tabbar",
      )) {
        if (
          !element.getClientRects().length ||
          getComputedStyle(element).visibility !== "visible" ||
          element.closest(".call-widget-layer")
        )
          continue;
        const rect = element.getBoundingClientRect();
        if (
          !rect.height ||
          !rect.width ||
          rect.bottom <= area.top ||
          rect.top >= area.bottom
        )
          continue;
        next.add(element);
        if (element.matches(".screen-header"))
          top = Math.max(top, rect.bottom + 8);
        else bottom = Math.min(bottom, rect.top - 12);
      }
      for (const element of observed)
        if (!next.has(element)) {
          resize.unobserve(element);
          observed.delete(element);
        }
      for (const element of next)
        if (!observed.has(element)) {
          resize.observe(element);
          observed.add(element);
        }
      // On a very short viewport the controls stay reachable above the keyboard.
      top = Math.min(top, Math.max(area.top, bottom - node.offsetHeight));
      bounds.current = {
        left: area.left,
        top,
        width: area.width,
        height: Math.max(0, bottom - top),
      };
      const point = floatingPosition(
        bounds.current,
        node.getBoundingClientRect(),
        anchor.current,
      );
      node.style.left = `${point.x - area.left}px`;
      node.style.top = `${point.y - area.top}px`;
      node.style.visibility = "visible";
    }
    reposition.current = measure;
    const changes = new MutationObserver((records) => {
      if (records.some((record) => !layer.contains(record.target))) schedule();
    });
    changes.observe(document.body, {
      subtree: true,
      childList: true,
      attributes: true,
      attributeFilter: [
        "class",
        "open",
        "data-conversation",
        "data-settings",
        "data-thread",
        "data-page-open",
      ],
    });
    const viewport = window.visualViewport;
    viewport?.addEventListener("resize", schedule);
    viewport?.addEventListener("scroll", schedule);
    window.addEventListener("resize", schedule);
    measure();
    return () => {
      cancelAnimationFrame(frame);
      changes.disconnect();
      resize.disconnect();
      viewport?.removeEventListener("resize", schedule);
      viewport?.removeEventListener("scroll", schedule);
      window.removeEventListener("resize", schedule);
      layer.remove();
    };
  }, [layer]);

  useLayoutEffect(() => {
    if (!hidden) reposition.current();
  }, [hidden]);

  const moveTo = (point: Point) => {
    if (!widget.current) return;
    anchor.current = floatingAnchor(
      bounds.current,
      widget.current.getBoundingClientRect(),
      point,
    );
    reposition.current();
  };
  const finishDrag = (event: PointerEvent<HTMLButtonElement>) => {
    if (drag.current?.id !== event.pointerId) return;
    drag.current = null;
    if (event.currentTarget.hasPointerCapture(event.pointerId))
      event.currentTarget.releasePointerCapture(event.pointerId);
  };
  return (
    layer &&
    createPortal(
      <section
        ref={widget}
        className="call-widget"
        aria-label={label}
        hidden={hidden}
      >
        <div className="call-widget-header">
          <button
            type="button"
            className="call-widget-grip"
            aria-label={t("calls.moveControls")}
            aria-description={t("calls.moveControlsHelp")}
            title={t("calls.moveControlsHelp")}
            onPointerDown={(event) => {
              if (!event.isPrimary || event.button !== 0 || !widget.current)
                return;
              event.preventDefault();
              const rect = widget.current.getBoundingClientRect();
              drag.current = {
                id: event.pointerId,
                pointer: { x: event.clientX, y: event.clientY },
                origin: { x: rect.left, y: rect.top },
              };
              event.currentTarget.setPointerCapture(event.pointerId);
            }}
            onPointerMove={(event) => {
              const start = drag.current;
              if (!start || start.id !== event.pointerId) return;
              moveTo({
                x: start.origin.x + event.clientX - start.pointer.x,
                y: start.origin.y + event.clientY - start.pointer.y,
              });
            }}
            onPointerUp={finishDrag}
            onPointerCancel={finishDrag}
            onLostPointerCapture={() => {
              drag.current = null;
            }}
            onKeyDown={(event) => {
              const direction: Record<string, Point> = {
                ArrowLeft: { x: -1, y: 0 },
                ArrowRight: { x: 1, y: 0 },
                ArrowUp: { x: 0, y: -1 },
                ArrowDown: { x: 0, y: 1 },
              };
              const delta = direction[event.key];
              if (!delta || !widget.current) return;
              event.preventDefault();
              event.stopPropagation();
              const rect = widget.current.getBoundingClientRect();
              const step = event.shiftKey ? 60 : 20;
              moveTo({
                x: rect.left + delta.x * step,
                y: rect.top + delta.y * step,
              });
            }}
          >
            <GripVertical size={16} aria-hidden="true" />
          </button>
          {title}
        </div>
        <div className="call-widget-controls">{children}</div>
      </section>,
      layer,
    )
  );
}
