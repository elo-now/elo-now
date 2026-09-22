import { useRef, useState, type ReactNode } from "react";
import { ChevronLeft, ChevronRight } from "lucide-react";
import { t } from "./i18n";
import { FloatingSearch } from "./Search";

const swipeDistance = 18;

/** Edge drawer for mobile conversation controls that should not cover messages. */
export function ConversationTools({
  call,
  searchKey,
  label,
  value,
  onChange,
}: {
  call?: ReactNode;
  searchKey?: string;
  label: string;
  value: string;
  onChange: (value: string) => void;
}) {
  const [open, setOpen] = useState(false);
  const [searchRevision, setSearchRevision] = useState(0);
  const gesture = useRef<
    | {
        x: number;
        y: number;
        moved: boolean;
      }
    | undefined
  >(undefined);
  const suppressClick = useRef(false);
  const hide = () => {
    setOpen(false);
    onChange("");
    setSearchRevision((revision) => revision + 1);
  };

  return (
    <div
      className="conversation-edge-tools mobile-only"
      data-open={open}
      onClickCapture={(event) => {
        if (!suppressClick.current) return;
        suppressClick.current = false;
        event.preventDefault();
        event.stopPropagation();
      }}
      onTouchStartCapture={(event) => {
        // A prevented swipe may produce no click at all. A new touch is a new
        // gesture, so never consume its first deliberate tap as the old swipe.
        suppressClick.current = false;
        if (event.touches.length !== 1) return;
        const touch = event.touches[0];
        gesture.current = {
          x: touch.clientX,
          y: touch.clientY,
          moved: false,
        };
      }}
      onTouchMoveCapture={(event) => {
        const start = gesture.current;
        if (!start || event.touches.length !== 1) return;
        const touch = event.touches[0];
        if (
          Math.abs(touch.clientX - start.x) > 8 ||
          Math.abs(touch.clientY - start.y) > 8
        )
          start.moved = true;
      }}
      onTouchEndCapture={(event) => {
        const start = gesture.current;
        gesture.current = undefined;
        const touch = event.changedTouches[0];
        if (!start || !touch) return;
        const dx = touch.clientX - start.x;
        const dy = touch.clientY - start.y;
        if (
          start.moved &&
          Math.abs(dx) >= swipeDistance &&
          Math.abs(dx) > Math.abs(dy)
        ) {
          if (dx < 0) setOpen(true);
          else hide();
          suppressClick.current = true;
          if (event.cancelable) event.preventDefault();
        }
      }}
      onTouchCancelCapture={() => {
        gesture.current = undefined;
        suppressClick.current = false;
      }}
    >
      <button
        type="button"
        className="conversation-edge-tools-tab"
        aria-label={t(
          open ? "conversationTools.hide" : "conversationTools.show",
        )}
        aria-expanded={open}
        onClick={() => {
          if (open) hide();
          else setOpen(true);
        }}
      >
        {open ? (
          <ChevronRight aria-hidden="true" size={16} />
        ) : (
          <ChevronLeft aria-hidden="true" size={16} />
        )}
      </button>
      <div className="conversation-edge-tools-actions">
        {call}
        <FloatingSearch
          key={`${searchKey ?? "conversation"}:${searchRevision}`}
          label={label}
          value={value}
          onChange={onChange}
        />
      </div>
    </div>
  );
}
