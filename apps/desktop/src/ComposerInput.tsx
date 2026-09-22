import {
  useLayoutEffect,
  useRef,
  type ComponentPropsWithoutRef,
  type RefObject,
} from "react";

/** Share draft sizing between the conversation and its thread. */
export function ComposerInput({
  inputRef,
  ...props
}: ComponentPropsWithoutRef<"textarea"> & {
  inputRef?: RefObject<HTMLTextAreaElement | null>;
}) {
  const localRef = useRef<HTMLTextAreaElement>(null);
  const input = inputRef ?? localRef;
  const resize = () => {
    const node = input.current;
    if (!node || !node.getClientRects().length) return;
    const style = getComputedStyle(node);
    const minimum = Number.parseFloat(style.minHeight);
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
  // Includes preference changes and restored drafts, not just keystrokes.
  useLayoutEffect(resize);
  useLayoutEffect(() => {
    const node = input.current;
    if (!node) return;
    let width = node.getBoundingClientRect().width;
    const observer = new ResizeObserver(() => {
      const next = node.getBoundingClientRect().width;
      if (next !== width) {
        width = next;
        resize();
      }
    });
    observer.observe(node);
    const viewport = window.visualViewport;
    viewport?.addEventListener("resize", resize);
    window.addEventListener("resize", resize);
    document.fonts.addEventListener("loadingdone", resize);
    return () => {
      observer.disconnect();
      viewport?.removeEventListener("resize", resize);
      window.removeEventListener("resize", resize);
      document.fonts.removeEventListener("loadingdone", resize);
    };
  }, [input]);
  return (
    <textarea
      {...props}
      ref={input}
      rows={1}
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
