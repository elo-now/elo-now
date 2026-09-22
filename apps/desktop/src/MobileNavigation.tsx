import { useEffect, useRef, useState, type PointerEvent } from "react";
import { Icon, NewIndicator } from "./Icon";
import { t } from "./i18n";

export type MobileTab = "stream" | "chats" | "contacts" | "profile";
const tabs = [
  { id: "stream", icon: "buzz", label: "nav.stream" },
  { id: "chats", icon: "chats", label: "nav.chats" },
  { id: "contacts", icon: "people", label: "nav.contacts" },
  { id: "profile", icon: "more", label: "nav.moreTab" },
] as const;

export function MobileNavigation({
  active,
  notifications = 0,
  unreadMessages = 0,
  onNavigate,
}: {
  active: MobileTab;
  notifications?: number;
  unreadMessages?: number;
  onNavigate: (tab: MobileTab) => void;
}) {
  const [hint, setHint] = useState<{
    tab: MobileTab;
    phase: "hold" | "exit";
    key: number;
  } | null>(null);
  const start = useRef(0);
  const pointer = useRef<{ x: number; y: number } | null>(null);
  const cancelled = useRef(false);
  const serial = useRef(0);
  const releaseTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const clearTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const clearTimers = () => {
    if (releaseTimer.current !== null) clearTimeout(releaseTimer.current);
    if (clearTimer.current !== null) clearTimeout(clearTimer.current);
  };
  useEffect(() => clearTimers, []);
  const show = (tab: MobileTab) => {
    clearTimers();
    if (tab === "profile") {
      setHint(null);
      return;
    }
    start.current = performance.now();
    setHint({ tab, phase: "hold", key: ++serial.current });
  };
  const release = () => {
    const key = serial.current;
    // A quick tap still completes the rise before fading out.
    const remaining = Math.max(0, 250 - (performance.now() - start.current));
    releaseTimer.current = setTimeout(() => {
      setHint((value) =>
        value?.key === key ? { ...value, phase: "exit" } : value,
      );
      clearTimer.current = setTimeout(() => {
        setHint((value) => (value?.key === key ? null : value));
      }, 240);
    }, remaining);
  };
  const cancel = () => {
    cancelled.current = true;
    pointer.current = null;
    clearTimers();
    setHint(null);
  };
  const press = (event: PointerEvent<HTMLButtonElement>, tab: MobileTab) => {
    if (event.button !== 0) return;
    cancelled.current = false;
    pointer.current = { x: event.clientX, y: event.clientY };
    show(tab);
  };
  return (
    <nav className="mobile-only mobile-tabbar" aria-label={t("nav.primary")}>
      {tabs.map((tab) => (
        <button
          key={tab.id}
          type="button"
          aria-label={
            tab.id === "profile" && notifications > 0
              ? t("nav.moreNew", { count: notifications })
              : tab.id === "stream" && unreadMessages > 0
                ? t("nav.streamNew", { count: unreadMessages })
                : t(tab.label)
          }
          aria-current={active === tab.id ? "page" : undefined}
          onContextMenu={(event) => event.preventDefault()}
          onPointerDown={(event) => press(event, tab.id)}
          onPointerMove={(event) => {
            if (
              pointer.current &&
              Math.hypot(
                event.clientX - pointer.current.x,
                event.clientY - pointer.current.y,
              ) > 12
            )
              cancel();
          }}
          onPointerLeave={() => {
            if (pointer.current) cancel();
          }}
          onPointerCancel={cancel}
          onPointerUp={() => {
            if (pointer.current && !cancelled.current) release();
            pointer.current = null;
          }}
          onClick={(event) => {
            if (event.detail === 0) {
              cancelled.current = false;
              show(tab.id);
              release();
            }
            if (cancelled.current) return;
            onNavigate(tab.id);
          }}
        >
          <span className="tab-symbol">
            <Icon
              name={tab.icon}
              attention={tab.id === "stream" && unreadMessages > 0}
            />
            {tab.id === "profile" && notifications > 0 && <NewIndicator />}
          </span>
          {hint?.tab === tab.id && (
            <span
              key={hint.key}
              className="tab-hint"
              data-phase={hint.phase}
              aria-hidden="true"
            >
              {t(tab.label)}
            </span>
          )}
        </button>
      ))}
    </nav>
  );
}
