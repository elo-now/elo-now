import {
  useEffect,
  useLayoutEffect,
  useRef,
  type ComponentPropsWithoutRef,
  type RefObject,
} from "react";
import { useRealtimePresentation } from "./useRealtime";

/** Share draft sizing between the conversation and its thread. */
export function ComposerInput({
  inputRef,
  resetRevision,
  ...props
}: ComponentPropsWithoutRef<"textarea"> & {
  inputRef?: RefObject<HTMLTextAreaElement | null>;
  resetRevision?: number;
}) {
  const localRef = useRef<HTMLTextAreaElement>(null);
  const realtime = useRealtimePresentation();
  useEffect(() => {
    if (!props.value || props.disabled) realtime.typing(false);
  }, [props.value, props.disabled]);
  const input = inputRef ?? localRef;
  const setExpanded = (expanded: boolean) => {
    const form = input.current?.form;
    if (!form) return;
    if (expanded) form.dataset.composerExpanded = "true";
    else delete form.dataset.composerExpanded;
  };
  const resize = () => {
    const node = input.current;
    if (!node || !node.getClientRects().length) return;
    const style = getComputedStyle(node);
    const minimum =
      Number.parseFloat(style.minHeight) *
      (node.form?.dataset.composerExpanded === "true" ? 3 : 1);
    const maximum = Math.max(
      minimum,
      (window.visualViewport?.height ?? window.innerHeight) / 3,
    );
    const borders =
      Number.parseFloat(style.borderTopWidth) +
      Number.parseFloat(style.borderBottomWidth);
    // Reset before measuring so deletion and successful sending also shrink it.
    node.style.height = "0px";
    const height = Math.max(minimum, node.scrollHeight + borders);
    node.style.height = `${Math.min(height, maximum)}px`;
    node.style.overflowY = height > maximum ? "auto" : "hidden";
  };
  useLayoutEffect(() => {
    setExpanded(false);
  }, [resetRevision]);
  // Includes preference changes and restored drafts, not just keystrokes.
  useLayoutEffect(resize);
  useLayoutEffect(() => {
    const node = input.current;
    if (!node) return;
    let width = node.getBoundingClientRect().width;
    let resizeFrame = 0;
    const observer = new ResizeObserver(() => {
      const next = node.getBoundingClientRect().width;
      if (next !== width) {
        width = next;
        cancelAnimationFrame(resizeFrame);
        resizeFrame = requestAnimationFrame(resize);
      }
    });
    observer.observe(node);
    const viewport = window.visualViewport;
    viewport?.addEventListener("resize", resize);
    window.addEventListener("resize", resize);
    document.fonts.addEventListener("loadingdone", resize);
    const form = node.form;
    let outsidePointer = false;
    let finishFrame = 0;
    const finishEditing = () => {
      cancelAnimationFrame(finishFrame);
      finishFrame = requestAnimationFrame(() => {
        setExpanded(false);
        resize();
      });
    };
    // WebKit can blur the textarea without focusing the tapped button. Keep
    // the editing layout until the user actually leaves this composer, so a
    // chip cannot move or disappear between touch-down and click.
    const focusChanged = (event: FocusEvent) => {
      const inside = event.target instanceof Node && !!form?.contains(event.target);
      if (inside) {
        cancelAnimationFrame(finishFrame);
        setExpanded(true);
        resize();
      } else if (!outsidePointer) finishEditing();
    };
    const pointerDown = (event: PointerEvent) => {
      cancelAnimationFrame(finishFrame);
      outsidePointer = event.target instanceof Node && !form?.contains(event.target);
    };
    const pointerFinished = () => {
      if (outsidePointer) {
        outsidePointer = false;
        // Wait until the click target is fixed before moving the message list.
        finishEditing();
      }
    };
    document.addEventListener("focusin", focusChanged);
    document.addEventListener("pointerdown", pointerDown, true);
    document.addEventListener("click", pointerFinished, true);
    document.addEventListener("pointercancel", pointerFinished, true);
    return () => {
      observer.disconnect();
      cancelAnimationFrame(finishFrame);
      cancelAnimationFrame(resizeFrame);
      viewport?.removeEventListener("resize", resize);
      window.removeEventListener("resize", resize);
      document.fonts.removeEventListener("loadingdone", resize);
      document.removeEventListener("focusin", focusChanged);
      document.removeEventListener("pointerdown", pointerDown, true);
      document.removeEventListener("click", pointerFinished, true);
      document.removeEventListener("pointercancel", pointerFinished, true);
      if (form) delete form.dataset.composerExpanded;
    };
  }, [input]);
  return (
    <textarea
      {...props}
      ref={input}
      rows={1}
      onChange={(event) => {
        setExpanded(true);
        props.onChange?.(event);
        realtime.typing(!!event.target.value.trim());
      }}
      onPointerDown={(event) => {
        props.onPointerDown?.(event);
        if (!event.defaultPrevented && !props.disabled) {
          setExpanded(true);
          resize();
        }
      }}
      onFocus={(event) => {
        props.onFocus?.(event);
        setExpanded(true);
        resize();
      }}
      onBlur={(event) => {
        realtime.typing(false);
        props.onBlur?.(event);
        requestAnimationFrame(resize);
      }}
      onKeyDown={(event) => {
        props.onKeyDown?.(event);
        if (
          !event.defaultPrevented &&
          event.key === "Enter" &&
          !event.shiftKey &&
          !event.ctrlKey &&
          !event.metaKey &&
          !event.altKey &&
          !event.nativeEvent.isComposing &&
          window.matchMedia("(min-width: 768px)").matches
        ) {
          event.preventDefault();
          const form = event.currentTarget.form;
          const submit = form?.querySelector<HTMLButtonElement>(
            'button:not([type]), button[type="submit"]',
          );
          if (submit && !submit.disabled) form?.requestSubmit(submit);
        }
      }}
    />
  );
}
