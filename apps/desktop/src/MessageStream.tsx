import {
  Fragment,
  useEffect,
  useLayoutEffect,
  useMemo,
  useRef,
  useState,
  type CSSProperties,
  type PointerEvent,
} from "react";
import { MessageContent } from "./MessageContent";
import { EmptyState } from "./EmptyState";
import { Icon } from "./Icon";
import { ScreenHeader } from "./ScreenHeader";
import { PullToRefresh } from "./PullToRefresh";
import { messageDayKey, formatMessageDay, t } from "./i18n";
import { senderName, type View } from "./model";
import {
  streamSwipe,
  swipeDirection,
  unreadStreamEntries,
  type StreamEntry,
} from "./streamFeed";

type Lift = {
  entry: StreamEntry;
  from: { top: number; left: number; width: number; height: number };
  progress: number;
  phase: "drag" | "open" | "return";
};
type Gesture = {
  pointer: number;
  x: number;
  y: number;
  dx: number;
  direction: "waiting" | "horizontal";
  entry: StreamEntry;
  from: Lift["from"];
};

function EntryBody({ entry }: { entry: StreamEntry }) {
  const { row } = entry;
  return row.body.kind === "chat.message" ? (
    <p>
      <span className="stream-text">{row.body.payload?.text}</span>
    </p>
  ) : (
    <p className="stream-file">
      <span className="stream-text">
        <Icon name="file" />
        {row.body.filename || t("stream.attachment")}
      </span>
    </p>
  );
}

export function MessageStream({
  view,
  active,
  mobile,
  busy,
  hideAvatars,
  onRefresh,
  onRead,
  onOpen,
  onChats,
  onYou,
}: {
  view: View;
  active: boolean;
  mobile: boolean;
  busy: boolean;
  hideAvatars: boolean;
  onRefresh: () => Promise<void>;
  onRead: (entry: StreamEntry) => Promise<boolean>;
  onOpen: (entry: StreamEntry) => void;
  onChats: () => void;
  onYou: () => void;
}) {
  const entries = useMemo(() => unreadStreamEntries(view), [view]);
  const [limit, setLimit] = useState(60);
  const viewport = useRef<HTMLDivElement>(null);
  const more = useRef<HTMLButtonElement>(null);
  const closeButton = useRef<HTMLButtonElement>(null);
  const [size, setSize] = useState({ width: 0, height: 0 });
  const [lift, setLift] = useState<Lift | null>(null);
  const [slide, setSlide] = useState<{
    key: string;
    x: number;
    dragging: boolean;
  } | null>(null);
  const [reading, setReading] = useState<string | null>(null);
  const gesture = useRef<Gesture | null>(null);
  const suppressClick = useRef(false);
  const returnTimer = useRef<ReturnType<typeof setTimeout> | undefined>(
    undefined,
  );
  const liftRef = useRef(lift);
  liftRef.current = lift;
  const reduced = () =>
    window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  const rememberFocus = useRef<HTMLButtonElement | null>(null);
  const restoreFocus = () =>
    requestAnimationFrame(() => {
      if (rememberFocus.current?.isConnected)
        rememberFocus.current.focus({ preventScroll: true });
      else
        viewport.current
          ?.querySelector<HTMLButtonElement>(".stream-preview")
          ?.focus({ preventScroll: true });
    });
  const collapse = () => {
    clearTimeout(returnTimer.current);
    if (reduced()) {
      setLift(null);
      restoreFocus();
      return;
    }
    setLift((current) =>
      current ? { ...current, progress: 0, phase: "return" } : null,
    );
    returnTimer.current = setTimeout(() => {
      setLift(null);
      restoreFocus();
    }, 220);
  };
  useEffect(() => () => clearTimeout(returnTimer.current), []);
  useEffect(() => {
    if (!active) {
      gesture.current = null;
      setLift(null);
      setSlide(null);
    }
  }, [active]);
  useEffect(() => {
    const key = (event: KeyboardEvent) => {
      if (event.key === "Escape" && liftRef.current?.phase === "open") {
        event.preventDefault();
        collapse();
      }
    };
    if (active) document.addEventListener("keydown", key);
    return () => document.removeEventListener("keydown", key);
  }, [active]);
  useLayoutEffect(() => {
    const node = viewport.current;
    if (!node) return;
    const observer = new ResizeObserver(() =>
      setSize({ width: node.clientWidth, height: node.clientHeight }),
    );
    observer.observe(node);
    return () => observer.disconnect();
  }, []);
  useEffect(() => {
    if (lift?.phase === "open")
      closeButton.current?.focus({ preventScroll: true });
  }, [lift?.phase]);
  useEffect(() => {
    const button = more.current;
    if (!active || !button) return;
    const observer = new IntersectionObserver(
      ([entry]) => {
        if (entry.isIntersecting) setLimit((current) => current + 60);
      },
      { root: button.closest(".stream-list"), rootMargin: "180px" },
    );
    observer.observe(button);
    return () => observer.disconnect();
  }, [active, limit, entries.length]);
  const geometry = (element: HTMLElement): Lift["from"] => {
    const rect = element.getBoundingClientRect(),
      parent = viewport.current!.getBoundingClientRect();
    return {
      top: rect.top - parent.top,
      left: rect.left - parent.left,
      width: rect.width,
      height: rect.height,
    };
  };
  const open = (entry: StreamEntry, element: HTMLButtonElement) => {
    if (reading || busy || lift) return;
    rememberFocus.current = element;
    const from = geometry(element.closest<HTMLElement>(".stream-card")!);
    setLift({ entry, from, progress: 0, phase: "drag" });
    requestAnimationFrame(() =>
      requestAnimationFrame(() => {
        setLift((current) =>
          current?.entry.key === entry.key
            ? { ...current, progress: 1, phase: "open" }
            : current,
        );
      }),
    );
  };
  const read = async (entry: StreamEntry) => {
    if (reading || busy) return;
    setReading(entry.key);
    setSlide({
      key: entry.key,
      x: -Math.max(size.width, 320),
      dragging: false,
    });
    const ok = await onRead(entry);
    if (ok) {
      setLift(null);
      restoreFocus();
    }
    setReading(null);
    setSlide(null);
  };
  const readAndOpen = async (entry: StreamEntry) => {
    if (reading || busy) return;
    setReading(entry.key);
    const ok = await onRead(entry);
    setReading(null);
    if (ok) {
      setLift(null);
      onOpen(entry);
    }
  };
  const start = (event: PointerEvent<HTMLElement>, entry: StreamEntry) => {
    suppressClick.current = false;
    if (!event.isPrimary) {
      finish(true);
      return;
    }
    if (event.button !== 0 || !event.isPrimary || reading || busy || lift)
      return;
    suppressClick.current = false;
    const from = geometry(event.currentTarget);
    gesture.current = {
      pointer: event.pointerId,
      x: event.clientX,
      y: event.clientY,
      dx: 0,
      direction: "waiting",
      entry,
      from,
    };
  };
  const move = (event: PointerEvent<HTMLElement>) => {
    const current = gesture.current;
    if (!current || current.pointer !== event.pointerId) return;
    const dx = event.clientX - current.x,
      dy = event.clientY - current.y;
    if (current.direction === "waiting") {
      const direction = swipeDirection(dx, dy);
      if (direction === "vertical") {
        gesture.current = null;
        return;
      }
      if (direction === "waiting") return;
      current.direction = "horizontal";
      event.currentTarget.setPointerCapture(event.pointerId);
      rememberFocus.current =
        event.currentTarget.querySelector(".stream-preview");
      suppressClick.current = true;
    }
    current.dx = dx;
    event.preventDefault();
    if (dx > 0) {
      setSlide(null);
      setLift({
        entry: current.entry,
        from: current.from,
        progress: streamSwipe(dx, current.from.width).progress,
        phase: "drag",
      });
    } else {
      setLift(null);
      setSlide({
        key: current.entry.key,
        x: Math.max(-current.from.width, dx),
        dragging: true,
      });
    }
  };
  const finish = (cancelled: boolean) => {
    const current = gesture.current;
    gesture.current = null;
    if (!current || current.direction !== "horizontal") return;
    const intent = streamSwipe(current.dx, current.from.width);
    if (!cancelled && intent.expand) {
      setLift({
        entry: current.entry,
        from: current.from,
        progress: 1,
        phase: "open",
      });
    } else if (!cancelled && intent.read) {
      void read(current.entry);
    } else {
      if (liftRef.current) collapse();
      setSlide(null);
    }
  };
  const style: CSSProperties | undefined = lift
    ? {
        top: lift.from.top + (4 - lift.from.top) * lift.progress,
        left: lift.from.left + (8 - lift.from.left) * lift.progress,
        width:
          lift.from.width + (size.width - 16 - lift.from.width) * lift.progress,
        height:
          lift.from.height +
          (size.height - 8 - lift.from.height) * lift.progress,
      }
    : undefined;
  return (
    <section
      className="message-stream"
      hidden={!active}
      aria-label={t("nav.stream")}
    >
      <ScreenHeader
        title={t("nav.stream")}
        actions={
          !mobile && (
            <>
              <button
                className="icon"
                aria-label={t("nav.chats")}
                onClick={onChats}
              >
                <Icon name="chats" />
              </button>
              <button
                className="icon"
                aria-label={t("nav.you")}
                onClick={onYou}
              >
                <Icon name="person" />
              </button>
            </>
          )
        }
      />
      <div className="stream-viewport" ref={viewport}>
        <div
          className="stream-list-host"
          inert={!!lift && lift.phase !== "drag"}
        >
          <PullToRefresh
            className="stream-list"
            enabled={active && !lift}
            disabled={busy || !!reading}
            onRefresh={onRefresh}
            resetKey={view.identity}
          >
            {!entries.length && <EmptyState message={t("stream.empty")} />}
            {entries.slice(0, limit).map((entry, index) => {
              const shifted = slide?.key === entry.key;
              return (
                <Fragment key={entry.key}>
                  {index > 0 &&
                    messageDayKey(entry.row.body.created_at) !==
                      messageDayKey(entries[index - 1].row.body.created_at) && (
                      <h3 className="message-day">
                        <span>
                          {formatMessageDay(entry.row.body.created_at)}
                        </span>
                      </h3>
                    )}
                  <div className="stream-card-slot">
                    <div className="stream-read-hint" aria-hidden="true">
                      <Icon name="check" />
                      <span>{t("stream.read")}</span>
                    </div>
                    <article
                      className="stream-card message"
                      data-hide-avatars={hideAvatars || undefined}
                      data-stream-entry={entry.key}
                      data-lifted={lift?.entry.key === entry.key || undefined}
                      data-dragging={(shifted && slide.dragging) || undefined}
                      style={
                        shifted
                          ? { transform: `translateX(${slide.x}px)` }
                          : undefined
                      }
                      onPointerDown={(event) => start(event, entry)}
                      onPointerMove={move}
                      onPointerUp={(event) => {
                        if (gesture.current?.pointer === event.pointerId)
                          finish(false);
                      }}
                      onPointerCancel={(event) => {
                        if (gesture.current?.pointer === event.pointerId)
                          finish(true);
                      }}
                      onLostPointerCapture={(event) => {
                        // Capture moves from a touched child to this card. The
                        // child's bubbling lost event must not cancel our drag.
                        if (
                          event.target === event.currentTarget &&
                          gesture.current?.pointer === event.pointerId
                        )
                          finish(true);
                      }}
                      onClickCapture={(event) => {
                        if (suppressClick.current && event.detail !== 0) {
                          event.preventDefault();
                          event.stopPropagation();
                          suppressClick.current = false;
                        }
                      }}
                    >
                      <MessageContent
                        view={view}
                        chat={entry.chat}
                        row={entry.row}
                        showDate={index === 0}
                        hideAvatars={hideAvatars}
                        context={
                          <span
                            className="stream-chat-name"
                            title={entry.chat.name}
                          >
                            {entry.chat.name}
                          </span>
                        }
                      >
                        <button
                          className="stream-preview"
                          disabled={!!reading || busy}
                          aria-label={t("stream.expandLabel", {
                            sender: senderName(
                              view,
                              entry.row.body.issuer_identity,
                              entry.chat,
                            ),
                            chat: entry.chat.name,
                          })}
                          onClick={(event) => open(entry, event.currentTarget)}
                        >
                          <EntryBody entry={entry} />
                        </button>
                      </MessageContent>
                    </article>
                  </div>
                </Fragment>
              );
            })}
            {entries.length > limit && (
              <button
                ref={more}
                className="quiet stream-load"
                onClick={() => setLimit((current) => current + 60)}
              >
                {t("stream.more")}
              </button>
            )}
          </PullToRefresh>
        </div>
        {lift && (
          <div className="stream-lift-layer">
            <div
              className="stream-lift-scrim"
              onClick={() => {
                if (lift.phase === "open") collapse();
              }}
            />
            <section
              className="stream-card stream-lift"
              style={style}
              data-phase={lift.phase}
              data-ready={lift.progress >= 0.9 || undefined}
              aria-label={t("stream.expanded")}
              role="region"
            >
              <div
                className="stream-reading-message message"
                data-hide-avatars={hideAvatars || undefined}
              >
                <MessageContent
                  view={view}
                  chat={lift.entry.chat}
                  row={lift.entry.row}
                  showDate
                  hideAvatars={hideAvatars}
                  context={
                    <span
                      className="stream-chat-name"
                      title={lift.entry.chat.name}
                    >
                      {lift.entry.chat.name}
                    </span>
                  }
                >
                  <div className="stream-card-body is-expanded">
                    <EntryBody entry={lift.entry} />
                  </div>
                </MessageContent>
              </div>
              {lift.phase === "open" && (
                <>
                  <footer className="stream-card-actions">
                    <button
                      ref={closeButton}
                      className="icon stream-collapse"
                      aria-label={t("stream.collapse")}
                      onClick={collapse}
                    >
                      <Icon name="close" />
                    </button>
                    <button
                      className="secondary"
                      disabled={!!reading || busy}
                      onClick={() => void read(lift.entry)}
                    >
                      {t("stream.markRead")}
                    </button>
                    <button
                      disabled={!!reading || busy}
                      onClick={() => void readAndOpen(lift.entry)}
                    >
                      {t("stream.open")}
                    </button>
                  </footer>
                </>
              )}
            </section>
          </div>
        )}
      </div>
    </section>
  );
}
