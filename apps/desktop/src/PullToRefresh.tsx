import {
  useEffect,
  useLayoutEffect,
  useRef,
  useState,
  type ReactNode,
} from "react";
import { t } from "./i18n";
import { createPortal } from "react-dom";
import { Icon } from "./Icon";
import { useToast } from "./Toast";

import { settleMessageScroll } from "./messageScroll";

const threshold = 64;

export function PullToRefresh({
  children,
  className,
  enabled,
  disabled,
  onRefresh,
  resetKey,
  scrollToEndKey,
  scrollToRecord,
  onVisibleUnread,
  onLoadOlder,
  loadingOlder = false,
  historyReady = true,
  followLatest = false,
  newMessage,
  onJumpToLatest,
  showNewMessageButton = true,
}: {
  children: ReactNode;
  className: string;
  enabled: boolean;
  disabled: boolean;
  onRefresh: () => Promise<void>;
  resetKey: string;
  scrollToEndKey?: string;
  scrollToRecord?: { id: string; key: number };
  onVisibleUnread?: (records: string[]) => void;
  onLoadOlder?: () => Promise<void>;
  loadingOlder?: boolean;
  historyReady?: boolean;
  followLatest?: boolean;
  newMessage?: { id: string; key: number };
  onJumpToLatest?: (id: string) => void;
  showNewMessageButton?: boolean;
}) {
  const { reportError } = useToast();
  const element = useRef<HTMLDivElement>(null);
  const followingEnd = useRef(false);
  const [below, setBelow] = useState<string>();
  const arrivals = useRef(newMessage?.key);
  const latestPage = useRef(followLatest);
  latestPage.current = followLatest;
  useLayoutEffect(() => {
    setBelow(undefined);
    arrivals.current = newMessage?.key;
  }, [resetKey]);
  useLayoutEffect(() => {
    if (!newMessage || arrivals.current === newMessage.key) return;
    arrivals.current = newMessage.key;
    if (!followingEnd.current || !followLatest) setBelow(newMessage.id);
  }, [newMessage, followLatest]);
  const atEnd = (node: HTMLElement) =>
    node.clientHeight > 0 &&
    node.scrollHeight - node.scrollTop - node.clientHeight <= 32;
  // Opening/own sends explicitly request the end. Incoming updates follow only
  // if the reader was already there before React changed the message list.
  useLayoutEffect(() => {
    const node = element.current;
    if (node && historyReady && scrollToEndKey !== undefined) {
      node.scrollTop = node.scrollHeight;
      followingEnd.current = true;
      setBelow(undefined);
    }
  }, [scrollToEndKey, historyReady]);
  const handledTarget = useRef<string | undefined>(undefined);
  const stopSettling = useRef<(() => void) | undefined>(undefined);
  useLayoutEffect(
    () => () => {
      stopSettling.current?.();
      handledTarget.current = undefined;
    },
    [],
  );
  useLayoutEffect(() => {
    const node = element.current;
    if (!scrollToRecord) {
      stopSettling.current?.();
      handledTarget.current = undefined;
      return;
    }
    if (!node || !historyReady) return;
    const key = JSON.stringify(scrollToRecord);
    if (handledTarget.current === key) return;
    const target = [
      ...node.querySelectorAll<HTMLElement>("[data-record-id]"),
    ].find((message) => message.dataset.recordId === scrollToRecord.id);
    if (!target) return;
    stopSettling.current?.();
    handledTarget.current = key;
    stopSettling.current = settleMessageScroll(node, target);
    followingEnd.current = atEnd(node);
  }, [scrollToRecord, historyReady, children]);
  const older = useRef(onLoadOlder);
  older.current = onLoadOlder;
  const loading = useRef(loadingOlder);
  loading.current = loadingOlder;
  const anchor = useRef<{ id: string; top: number } | undefined>(undefined);
  useLayoutEffect(() => {
    const node = element.current;
    if (!node || !anchor.current) return;
    followingEnd.current = false;
    const target = [
      ...node.querySelectorAll<HTMLElement>("[data-record-id]"),
    ].find((item) => item.dataset.recordId === anchor.current!.id);
    if (target)
      node.scrollTop += target.getBoundingClientRect().top - anchor.current.top;
    if (!loadingOlder) anchor.current = undefined;
  }, [children, loadingOlder]);
  useLayoutEffect(() => {
    const node = element.current;
    if (!node) return;
    if (historyReady && node.clientHeight) followingEnd.current = atEnd(node);
    const scroll = () => {
      if (node.clientHeight) followingEnd.current = atEnd(node);
      if (followingEnd.current && latestPage.current) setBelow(undefined);
    };
    node.addEventListener("scroll", scroll, { passive: true });
    return () => node.removeEventListener("scroll", scroll);
  }, [resetKey, historyReady]);
  useLayoutEffect(() => {
    const node = element.current;
    if (!node || !followLatest || !historyReady || anchor.current) return;
    let frame = 0;
    const align = () => {
      if (!followingEnd.current || !node.clientHeight || anchor.current) return;
      node.scrollTop = node.scrollHeight;
    };
    if (followingEnd.current) stopSettling.current?.();
    align();
    // Keyboard dismissal and message/reaction layout can finish after the
    // render. Continue following the bottom until the reader scrolls away.
    const observer = new ResizeObserver(() => {
      cancelAnimationFrame(frame);
      frame = requestAnimationFrame(align);
    });
    observer.observe(node);
    node
      .querySelectorAll<HTMLElement>("[data-record-id]")
      .forEach((row) => observer.observe(row));
    return () => {
      observer.disconnect();
      cancelAnimationFrame(frame);
    };
  }, [children, followLatest, historyReady, resetKey]);
  useEffect(() => {
    const node = element.current;
    if (!node || !onLoadOlder) return;
    const scroll = () => {
      if (node.scrollTop > 120 || loading.current || !older.current) return;
      const bounds = node.getBoundingClientRect();
      const first = [
        ...node.querySelectorAll<HTMLElement>("[data-record-id]"),
      ].find((item) => item.getBoundingClientRect().bottom > bounds.top);
      if (first?.dataset.recordId)
        anchor.current = {
          id: first.dataset.recordId,
          top: first.getBoundingClientRect().top,
        };
      loading.current = true;
      void older.current().finally(() => {
        loading.current = false;
      });
    };
    node.addEventListener("scroll", scroll, { passive: true });
    return () => node.removeEventListener("scroll", scroll);
  }, [resetKey, !!onLoadOlder]);
  const callback = useRef(onRefresh);
  callback.current = onRefresh;
  const blocked = useRef(disabled);
  blocked.current = disabled;
  const visibleUnread = useRef(onVisibleUnread);
  visibleUnread.current = onVisibleUnread;
  const running = useRef(false);
  const [distance, setDistance] = useState(0);
  const [refreshing, setRefreshing] = useState(false);
  const refresh = async () => {
    if (running.current || blocked.current) return;
    running.current = true;
    setRefreshing(true);
    setDistance(48);
    try {
      await callback.current();
    } catch (error) {
      reportError(error);
    } finally {
      running.current = false;
      setRefreshing(false);
      setDistance(0);
    }
  };
  const refreshRef = useRef(refresh);
  refreshRef.current = refresh;
  useEffect(() => {
    const node = element.current;
    if (!node || !enabled) return;
    let start: { x: number; y: number } | null = null;
    let pull = 0;
    const reset = () => {
      start = null;
      pull = 0;
      if (!running.current) setDistance(0);
    };
    const begin = (event: TouchEvent) => {
      reset();
      if (
        blocked.current ||
        running.current ||
        node.scrollTop > 0 ||
        event.touches.length !== 1
      )
        return;
      if (
        event.target instanceof Element &&
        event.target.closest(
          "input, textarea, select, [contenteditable='true']",
        )
      )
        return;
      const touch = event.touches[0];
      start = { x: touch.clientX, y: touch.clientY };
    };
    const move = (event: TouchEvent) => {
      if (!start) return;
      if (event.touches.length !== 1 || blocked.current || node.scrollTop > 0) {
        reset();
        return;
      }
      const touch = event.touches[0];
      const dy = touch.clientY - start.y;
      const dx = touch.clientX - start.x;
      if (dy < 0 || Math.abs(dx) > Math.max(12, Math.abs(dy))) {
        reset();
        return;
      }
      if (dy < 8) return;
      event.preventDefault();
      pull = Math.min(96, dy * 0.5);
      setDistance(pull);
    };
    const end = () => {
      const ready = pull >= threshold;
      reset();
      if (ready) void refreshRef.current();
    };
    // An explicit non-passive listener is required to own only the downward
    // gesture at scrollTop=0. Normal scrolling and taps remain native.
    node.addEventListener("touchstart", begin, { passive: true });
    node.addEventListener("touchmove", move, { passive: false });
    node.addEventListener("touchend", end);
    node.addEventListener("touchcancel", reset);
    return () => {
      node.removeEventListener("touchstart", begin);
      node.removeEventListener("touchmove", move);
      node.removeEventListener("touchend", end);
      node.removeEventListener("touchcancel", reset);
      reset();
    };
  }, [enabled, resetKey]);
  useEffect(() => {
    const node = element.current;
    if (!node || !onVisibleUnread) return;
    const observer = new IntersectionObserver(
      (entries) => {
        // Geometric intersection does not account for a modal covering the list.
        if (document.hidden || document.querySelector("dialog[open]")) return;
        const records = entries
          .filter((entry) => entry.isIntersecting)
          .map((entry) => (entry.target as HTMLElement).dataset.unreadId)
          .filter((id): id is string => !!id);
        if (!records.length) return;
        entries
          .filter((entry) => entry.isIntersecting)
          .forEach((entry) => observer.unobserve(entry.target));
        visibleUnread.current?.(records);
      },
      { root: node, threshold: 0.15 },
    );
    const attach = () =>
      node
        .querySelectorAll<HTMLElement>("[data-unread-id]")
        .forEach((message) => observer.observe(message));
    attach();
    const mutations = new MutationObserver(attach);
    mutations.observe(node, { childList: true, subtree: true });
    const resume = () => {
      observer.disconnect();
      attach();
    };
    const modals = new MutationObserver((changes) => {
      if (
        changes.some(
          (change) =>
            change.type === "attributes" ||
            [...change.addedNodes, ...change.removedNodes].some(
              (item) =>
                item instanceof Element &&
                (item.matches("dialog") || item.querySelector("dialog")),
            ),
        )
      )
        resume();
    });
    modals.observe(document.body, {
      attributes: true,
      attributeFilter: ["open"],
      subtree: true,
      childList: true,
    });
    document.addEventListener("visibilitychange", resume);
    return () => {
      document.removeEventListener("visibilitychange", resume);
      modals.disconnect();
      mutations.disconnect();
      observer.disconnect();
    };
  }, [onVisibleUnread, resetKey]);
  const jump = () => {
    const node = element.current;
    if (!node || !below) return;
    const loaded = [
      ...node.querySelectorAll<HTMLElement>("[data-record-id]"),
    ].some((row) => row.dataset.recordId === below);
    if (!followLatest || !loaded) {
      onJumpToLatest?.(below);
      return;
    }
    stopSettling.current?.();
    followingEnd.current = true;
    node.scrollTop = node.scrollHeight;
    setBelow(undefined);
  };
  return (
    <>
      <div
        ref={element}
        className={`${className} pull-surface`}
        data-refreshing={refreshing}
      >
        {enabled && (
          <>
            <button
              type="button"
              className="refresh-accessible"
              disabled={disabled || refreshing}
              onClick={() => void refreshRef.current()}
            >
              {t("refresh.action")}
            </button>
            <div
              className="pull-indicator"
              style={{ height: distance }}
              aria-hidden={distance === 0}
            >
              {distance > 0 && (
                <span role="status">
                  {refreshing
                    ? t("refresh.busy")
                    : distance >= threshold
                      ? t("refresh.release")
                      : t("refresh.pull")}
                </span>
              )}
            </div>
          </>
        )}
        {children}
      </div>
      {below &&
        showNewMessageButton &&
        element.current?.parentElement &&
        createPortal(
          <button
            type="button"
            className="search-orb new-messages-orb"
            aria-label={t("history.newBelow")}
            onPointerDown={(event) => event.preventDefault()}
            onClick={jump}
          >
            <Icon name="down" />
          </button>,
          element.current.parentElement,
        )}
    </>
  );
}
