import {
  cloneElement,
  useEffect,
  useRef,
  useState,
  type ButtonHTMLAttributes,
  type PointerEvent,
  type ReactElement,
} from "react";
import { Icon } from "./Icon";
import { t } from "./i18n";
import "./SwipeChatRow.css";

const revealWidth = 64;
type Gesture = {
  pointer: number;
  x: number;
  y: number;
  initial: number;
  distance: number;
  horizontal: boolean;
};

/** Swiping only exposes an action. Deletion always requires a separate tap
 * and the caller's confirmation dialog. Vertical movement belongs to scrolling. */
export function SwipeChatRow({
  children,
  chatName,
  revealed,
  onReveal,
  onRequestDelete,
}: {
  children: ReactElement<ButtonHTMLAttributes<HTMLButtonElement>>;
  chatName: string;
  revealed: boolean;
  onReveal: (open: boolean) => void;
  onRequestDelete: () => void;
}) {
  const container = useRef<HTMLDivElement>(null);
  const gesture = useRef<Gesture | null>(null);
  const suppressClick = useRef(false);
  const [dragOffset, setDragOffset] = useState<number | null>(null);
  const offset = dragOffset ?? (revealed ? revealWidth : 0);
  useEffect(() => {
    if (!revealed) return;
    const closeOutside = (event: globalThis.PointerEvent) => {
      if (!container.current?.contains(event.target as Node)) onReveal(false);
    };
    document.addEventListener("pointerdown", closeOutside, true);
    return () =>
      document.removeEventListener("pointerdown", closeOutside, true);
  }, [revealed, onReveal]);
  const cancel = () => {
    gesture.current = null;
    setDragOffset(null);
  };
  const requestDelete = () => {
    // Restore focus to the visible row after cancelling the dialog, rather than
    // to the action button that is about to be hidden.
    container.current
      ?.querySelector<HTMLButtonElement>(".swipe-chat-open")
      ?.focus({ preventScroll: true });
    onReveal(false);
    onRequestDelete();
  };
  const finish = (event: PointerEvent<HTMLDivElement>) => {
    const current = gesture.current;
    if (!current || current.pointer !== event.pointerId) return;
    if (current.horizontal) {
      event.preventDefault();
      onReveal(current.distance >= revealWidth / 2);
    }
    cancel();
  };
  return (
    <div
      ref={container}
      className="swipe-chat-row"
      data-no-back-swipe
      data-dragging={dragOffset !== null || undefined}
      onPointerDown={(event) => {
        if (
          event.pointerType === "mouse" ||
          event.button !== 0 ||
          !event.isPrimary ||
          !(event.target instanceof Element) ||
          event.target.closest(".swipe-chat-delete")
        )
          return;
        suppressClick.current = false;
        gesture.current = {
          pointer: event.pointerId,
          x: event.clientX,
          y: event.clientY,
          initial: revealed ? revealWidth : 0,
          distance: revealed ? revealWidth : 0,
          horizontal: false,
        };
      }}
      onPointerMove={(event) => {
        const current = gesture.current;
        if (!current || current.pointer !== event.pointerId) return;
        const dx = event.clientX - current.x;
        const dy = event.clientY - current.y;
        if (!current.horizontal) {
          if (Math.max(Math.abs(dx), Math.abs(dy)) < 8) return;
          if (
            Math.abs(dx) < Math.abs(dy) * 1.3 ||
            (!current.initial && dx > 0)
          ) {
            cancel();
            return;
          }
          current.horizontal = true;
          suppressClick.current = true;
          event.currentTarget.setPointerCapture(event.pointerId);
        }
        event.preventDefault();
        current.distance = Math.min(
          revealWidth,
          Math.max(0, current.initial - dx),
        );
        setDragOffset(current.distance);
      }}
      onPointerUp={finish}
      onPointerCancel={cancel}
      onLostPointerCapture={(event) => {
        // Touch initially captures the child button. Moving capture to this row
        // bubbles the child's loss event; only this row's own loss cancels it.
        if (event.target === event.currentTarget) cancel();
      }}
      onKeyDown={(event) => {
        if (event.key === "Escape" && revealed) {
          event.preventDefault();
          event.stopPropagation();
          onReveal(false);
        }
      }}
    >
      <div className="swipe-chat-action" style={{ width: offset }}>
        <button
          type="button"
          className="swipe-chat-delete"
          aria-label={t("chat.deleteLocalLabel", { name: chatName })}
          aria-hidden={!revealed}
          tabIndex={revealed ? 0 : -1}
          onClick={(event) => {
            event.stopPropagation();
            requestDelete();
          }}
        >
          <Icon name="delete" />
        </button>
      </div>
      {cloneElement(children, {
        className: `${children.props.className ?? ""} swipe-chat-open`,
        style: {
          ...children.props.style,
          transform: `translateX(${-offset}px)`,
        },
        "aria-keyshortcuts": "Delete",
        onClick: (event) => {
          if (suppressClick.current && event.detail !== 0) {
            suppressClick.current = false;
            event.preventDefault();
            event.stopPropagation();
            return;
          }
          if (revealed) {
            event.preventDefault();
            event.stopPropagation();
            onReveal(false);
            return;
          }
          children.props.onClick?.(event);
        },
        onKeyDown: (event) => {
          if (event.key === "Delete") {
            event.preventDefault();
            event.stopPropagation();
            requestDelete();
          } else children.props.onKeyDown?.(event);
        },
      })}
    </div>
  );
}
