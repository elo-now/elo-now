import { useEffect, useRef, useState } from "react";
import { invoke, isTauri } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import type { Stream, View } from "./model";
import { senderName } from "./model";
import type { StreamEntry } from "./streamFeed";
import { t } from "./i18n";
import { useToast } from "./Toast";
import { NotificationSoundSettings } from "./NotificationSoundSettings";
import { NotificationOffer } from "./NotificationOffer";
import {
  NotificationSoundGate,
  playNotificationSound,
  readNotificationSound,
  stopNotificationSound,
} from "./notificationSounds";
import { resolveNotificationEntry } from "./usePushNotifications";
import type { HistoryPage } from "./messageHistory";

export type DesktopNotificationTarget = {
  identity: string;
  space: string;
  stream: string;
  space_context?: string;
  record?: string;
  call_id?: string;
  category: "message" | "session";
};
type DesktopStatus = {
  available: boolean;
  enabled: boolean;
  permission: "granted" | "denied" | "prompt" | "system";
  click_supported: boolean;
  custom_sound?: "supported" | "server_dependent" | "system_default";
};
type Notice = {
  target: DesktopNotificationTarget;
  label: string;
  time: number;
  inbox?: boolean;
};
const empty: DesktopStatus = {
  available: false,
  enabled: false,
  permission: "prompt",
  click_supported: false,
};
const desktopOfferKey = "elo.desktop-notification-offer.v1";

export function appHasAttention() {
  return document.visibilityState === "visible" && document.hasFocus();
}

export function messageNoticeLabel(entries: StreamEntry[], view: View) {
  const entry = entries.at(-1)!;
  const chats = new Set(
    entries.map(
      ({ chat }) =>
        `${chat.space_context ?? view.active_space ?? ""}:${chat.space}:${chat.stream}`,
    ),
  );
  const context = view.spaces?.find(
    (space) => space.id === entry.chat.space_context,
  );
  if (entries.length > 1) {
    if (chats.size > 1)
      return t("notifications.messagesInChats", {
        count: entries.length,
        chats: chats.size,
      });
    if (context && context.id !== view.active_space)
      return t("notifications.messagesInSpace", {
        count: entries.length,
        chat: entry.chat.name,
        space: context.name,
      });
    return t("notifications.messagesInChat", {
      count: entries.length,
      chat: entry.chat.name,
    });
  }
  const name = senderName(view, entry.row.body.issuer_identity, entry.chat);
  const message = (entry.row.body.payload?.text ?? "")
    .slice(0, 160)
    .replace(/\s+/g, " ");
  return t(
    context && context.id !== view.active_space
      ? "notifications.messageInSpace"
      : entry.chat.chat_kind === "direct" && entry.chat.members.length === 2
        ? "notifications.directMessage"
        : "notifications.message",
    {
      name,
      chat: entry.chat.name,
      space: context?.name ?? "",
      message,
    },
  );
}

export function useActivityNotifications(options: {
  view: View | null;
  mobile: boolean;
  ready: boolean;
  onMessage: (entry: StreamEntry) => Promise<boolean>;
  onChat: (chat: Stream, callId?: string) => void | Promise<void>;
  onInbox: () => void;
  onError: (error: unknown) => void;
  isSessionAvailable?: (target: DesktopNotificationTarget) => boolean;
}) {
  const { view, mobile, ready } = options;
  const { showMessage } = useToast();
  const [status, setStatus] = useState<DesktopStatus>(empty);
  const [changing, setChanging] = useState(false);
  const [handled, setHandled] = useState(
    () => localStorage.getItem(desktopOfferKey) === "handled",
  );
  const latest = useRef({ ...options, status, showMessage });
  latest.current = { ...options, status, showMessage };
  const pending = useRef(new Map<string, Notice>());
  const gate = useRef(new NotificationSoundGate());
  const opening = useRef(false);
  const refreshing = useRef(false);

  const findChat = (
    target: DesktopNotificationTarget,
    current = latest.current.view,
  ) => {
    if (!current || current.identity !== target.identity) return;
    return (current.all_streams ?? current.streams).find(
      (chat) =>
        chat.space === target.space &&
        chat.stream === target.stream &&
        !chat.forked &&
        chat.members.some(
          (member) =>
            member.identity_id === current.identity &&
            member.capabilities.includes("READ"),
        ) &&
        (!target.space_context ||
          (chat.space_context ?? current.active_space) ===
            target.space_context),
    );
  };
  const open = async (target: DesktopNotificationTarget, inbox = false) => {
    const current = latest.current.view;
    const chat = findChat(target);
    if (!current || !chat) return;
    if (inbox) {
      latest.current.onInbox();
      return;
    }
    if (target.category === "session") {
      await latest.current.onChat(chat, target.call_id);
      return;
    }
    const entry = await resolveNotificationEntry(
      current,
      target,
      async (request) =>
        invoke<{ history: HistoryPage }>("operate", { request }),
    );
    if (entry && latest.current.view?.identity === current.identity)
      await latest.current.onMessage(entry);
  };
  const show = (notice: Notice, arrivedView?: View) => {
    if (latest.current.view?.identity !== notice.target.identity) return;
    const chat = findChat(notice.target, arrivedView ?? latest.current.view);
    if (!chat || chat.muted || Date.now() - notice.time > 60_000) return;
    if (
      notice.target.category === "session" &&
      !latest.current.isSessionAvailable?.(notice.target)
    )
      return;
    if (notice.target.category === "message") {
      const row = chat.rows.find((row) => row.id === notice.target.record);
      if (row && (!row.unread || row.body.kind === "deleted")) return;
    }
    latest.current.showMessage(
      notice.label,
      () =>
        void open(notice.target, notice.inbox).catch(latest.current.onError),
      t(
        notice.target.category === "session"
          ? "notifications.open"
          : "notifications.read",
      ),
    );
  };
  const announce = (notice: Notice, arrivedView?: View) => {
    if (latest.current.view?.identity !== notice.target.identity) return;
    if (
      notice.target.category === "session" &&
      !latest.current.isSessionAvailable?.(notice.target)
    )
      return;
    const chat = findChat(notice.target, arrivedView ?? latest.current.view);
    if (!chat || chat.muted) return;
    const kind = notice.target.category;
    const sound = gate.current.allow(kind, performance.now())
      ? readNotificationSound()
      : "none";
    if (!appHasAttention()) {
      if (!latest.current.mobile && latest.current.status.enabled && isTauri())
        void invoke("desktop_notification_task", {
          op: "show",
          expectedIdentity: notice.target.identity,
          target: notice.target,
          sound,
        }).catch(() => {
          /* The OS may reject delivery; never bypass it with background audio. */
        });
      return;
    }
    if (!latest.current.mobile && sound !== "none")
      void playNotificationSound(sound).catch(() => {});
    if (document.querySelector("dialog[open]")) {
      const key = `${notice.target.category}:${notice.target.space_context ?? ""}:${notice.target.space}:${notice.target.stream}`;
      pending.current.delete(key);
      pending.current.set(key, notice);
      if (pending.current.size > 20)
        pending.current.delete(pending.current.keys().next().value!);
      return;
    }
    show(notice, arrivedView);
  };
  const functions = useRef({ show, open });
  functions.current = { show, open };

  useEffect(() => {
    pending.current.clear();
    gate.current.reset();
    stopNotificationSound();
  }, [view?.identity]);

  useEffect(() => {
    const observer = new MutationObserver(() => {
      if (!appHasAttention() || document.querySelector("dialog[open]")) return;
      const notice = [...pending.current.values()].at(-1);
      pending.current.clear();
      if (notice) functions.current.show(notice);
    });
    observer.observe(document.body, {
      subtree: true,
      attributes: true,
      attributeFilter: ["open"],
      childList: true,
    });
    return () => observer.disconnect();
  }, []);

  useEffect(() => {
    if (mobile || !isTauri()) return;
    let cancelled = false;
    const refresh = async () => {
      if (refreshing.current) return;
      refreshing.current = true;
      try {
        const next = await invoke<DesktopStatus>("desktop_notification_task", {
          op: "status",
        });
        if (!cancelled) setStatus(next);
      } catch {
        /* Older binaries have no desktop receiver. */
      } finally {
        refreshing.current = false;
      }
    };
    const takeOpened = async () => {
      if (
        opening.current ||
        !latest.current.view ||
        !latest.current.status.available
      )
        return;
      opening.current = true;
      try {
        const result = await invoke<{
          target: DesktopNotificationTarget | null;
          pending: boolean;
        }>("desktop_notification_task", {
          op: "take_opened",
          expectedIdentity: latest.current.view.identity,
        });
        if (result.target && !cancelled)
          await functions.current.open(result.target);
      } catch (error) {
        if (!cancelled) latest.current.onError(error);
      } finally {
        opening.current = false;
      }
    };
    const focus = () => {
      void refresh();
      void takeOpened();
    };
    const unlisten = listen(
      "desktop-notification-opened",
      () => void takeOpened(),
    );
    window.addEventListener("focus", focus);
    void refresh();
    // Native keeps a click pending across lock/unlock; resolve only for the active profile.
    if (view && status.available) void takeOpened();
    return () => {
      cancelled = true;
      window.removeEventListener("focus", focus);
      void unlisten.then((stop) => stop()).catch(() => {});
    };
  }, [mobile, view?.identity, status.available]);

  const dismissOffer = () => {
    localStorage.setItem(desktopOfferKey, "handled");
    setHandled(true);
  };
  const toggle = async () => {
    if (changing || !view) return;
    setChanging(true);
    try {
      const updated = await invoke<DesktopStatus>("desktop_notification_task", {
        op: status.enabled ? "disable" : "enable",
        expectedIdentity: view.identity,
      });
      setStatus(updated);
      if (updated.enabled || status.enabled) dismissOffer();
    } catch (error) {
      options.onError(error);
    } finally {
      setChanging(false);
    }
  };

  return {
    messages(entries: StreamEntry[], current: View) {
      if (!entries.length) return;
      const { chat, row } = entries.at(-1)!;
      // receiveSync has verified this view, but React may not have rendered it yet.
      announce(
        {
          target: {
            identity: current.identity,
            space: chat.space,
            stream: chat.stream,
            space_context:
              chat.space_context ?? current.active_space ?? undefined,
            record: row.id,
            category: "message",
          },
          label: messageNoticeLabel(entries, current),
          time: Date.now(),
          inbox:
            new Set(
              entries.map(
                ({ chat }) =>
                  `${chat.space_context ?? current.active_space ?? ""}:${chat.space}:${chat.stream}`,
              ),
            ).size > 1,
        },
        current,
      );
    },
    session(chat: Stream, callId: string, label: string) {
      const identity = latest.current.view?.identity;
      if (!identity || chat.muted) return;
      announce({
        target: {
          identity,
          space: chat.space,
          stream: chat.stream,
          space_context:
            chat.space_context ??
            latest.current.view?.active_space ??
            undefined,
          call_id: callId,
          category: "session",
        },
        label,
        time: Date.now(),
      });
    },
    settings: !mobile ? (
      <>
        {status.available && (
          <div className="push-settings">
            <button
              type="button"
              className="settings-toggle"
              role="switch"
              aria-checked={status.enabled}
              disabled={changing}
              onClick={() => void toggle()}
            >
              <span>{t("notifications.system")}</span>
              <span className="toggle-track" aria-hidden="true">
                <span />
              </span>
            </button>
            <p className="muted" role="status">
              {t(
                status.permission === "denied"
                  ? "notifications.desktopDenied"
                  : status.enabled
                    ? "notifications.desktopHelp"
                    : "notifications.desktopDisabled",
              )}
            </p>
          </div>
        )}
      </>
    ) : null,
    soundSettings: !mobile ? (
      <NotificationSoundSettings nativeSupport={status.custom_sound} />
    ) : null,
    offer:
      !mobile &&
      view &&
      ready &&
      status.available &&
      !status.enabled &&
      status.permission !== "denied" &&
      !handled &&
      !changing ? (
        <NotificationOffer
          help={t("notifications.desktopHelp")}
          onDecline={dismissOffer}
          onAccept={() => void toggle()}
        />
      ) : null,
  };
}
