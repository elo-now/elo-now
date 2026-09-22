import { useEffect, useId, useRef, useState } from "react";
import { Icon, NewIndicator } from "./Icon";
import { t } from "./i18n";
import type { MessageThread } from "./messageThreads";

export function ThreadLink({
  thread,
  onOpen,
}: {
  thread?: MessageThread;
  onOpen: () => void;
}) {
  const count = Math.max(thread?.count ?? 0, thread?.replies.length ?? 0);
  const label = count
    ? t(count === 1 ? "thread.oneReply" : "thread.replies", { count })
    : t("thread.reply");
  return (
    <button
      type="button"
      className="thread-link"
      onClick={onOpen}
      aria-label={
        thread?.unreadCount
          ? t("thread.newReplies", {
              replies: label,
              count: thread.unreadCount,
            })
          : label
      }
    >
      {count === 0 && <Icon name="reply" />}
      <span>{label}</span>
      {!!thread?.unreadCount && <NewIndicator />}
    </button>
  );
}

/** Reveal the action inside the bubble without navigating or focusing a composer. */
export function MessageBubble({
  text,
  thread,
  canReply,
  onOpen,
}: {
  text: string;
  thread?: MessageThread;
  canReply: boolean;
  onOpen: () => void;
}) {
  const [revealed, setRevealed] = useState(false);
  const footerId = useId();
  const bubble = useRef<HTMLDivElement>(null);
  const footer = useRef<HTMLDivElement>(null);
  const revealInView = useRef(false);
  const pointer = useRef({ x: 0, y: 0, moved: false });
  const hasReplies = !!(thread?.count || thread?.replies.length);
  const canToggle = canReply && !hasReplies;
  const expanded = hasReplies || (canReply && revealed);
  const toggle = () => {
    const node = bubble.current;
    const list = node?.closest<HTMLElement>(".messages");
    // Only assist a bubble whose end is already visible. A long message must
    // never jump several screens just because the reader tapped its beginning.
    revealInView.current =
      !!node &&
      !!list &&
      !expanded &&
      node.getBoundingClientRect().bottom <=
        list.getBoundingClientRect().bottom;
    setRevealed((value) => !value);
  };
  useEffect(() => {
    const node = footer.current;
    const list = node?.closest<HTMLElement>(".messages");
    if (!expanded || !revealInView.current || !node || !list) return;
    let active = true;
    const keepVisible = () => {
      if (!active) return;
      // Respect the list's existing clearance for the floating search control.
      const edge =
        list.getBoundingClientRect().bottom -
        Number.parseFloat(getComputedStyle(list).paddingBottom);
      const overflow = node.getBoundingClientRect().bottom - edge;
      if (overflow > 0) list.scrollTop += overflow;
    };
    const observer = new ResizeObserver(keepVisible);
    const stop = () => {
      active = false;
      observer.disconnect();
    };
    observer.observe(node);
    const timer = setTimeout(() => {
      keepVisible();
      stop();
    }, 240);
    list.addEventListener("touchstart", stop, { once: true });
    return () => {
      clearTimeout(timer);
      stop();
      list.removeEventListener("touchstart", stop);
    };
  }, [expanded]);
  return (
    <div ref={bubble} className="message-bubble" data-expanded={expanded}>
      <p
        role={canToggle ? "button" : undefined}
        tabIndex={canToggle ? 0 : undefined}
        aria-expanded={canToggle ? expanded : undefined}
        aria-controls={canToggle ? footerId : undefined}
        aria-description={
          canToggle
            ? t(expanded ? "thread.hideReply" : "thread.showReply")
            : undefined
        }
        onPointerDown={(event) => {
          pointer.current = {
            x: event.clientX,
            y: event.clientY,
            moved: false,
          };
        }}
        onPointerMove={(event) => {
          if (
            Math.hypot(
              event.clientX - pointer.current.x,
              event.clientY - pointer.current.y,
            ) > 10
          )
            pointer.current.moved = true;
        }}
        onPointerCancel={() => {
          pointer.current.moved = true;
        }}
        onClick={() => {
          // Preserve native scrolling, long-press selection and copying.
          if (
            canToggle &&
            !pointer.current.moved &&
            !window.getSelection()?.toString()
          )
            toggle();
        }}
        onKeyDown={(event) => {
          if (
            canToggle &&
            !event.repeat &&
            (event.key === "Enter" || event.key === " ")
          ) {
            event.preventDefault();
            toggle();
          }
        }}
      >
        {text}
      </p>
      {(canReply || hasReplies) && (
        <div
          ref={footer}
          id={footerId}
          className="message-reply-footer"
          inert={!expanded}
          aria-hidden={!expanded}
        >
          <div>
            <ThreadLink thread={thread} onOpen={onOpen} />
          </div>
        </div>
      )}
    </div>
  );
}
