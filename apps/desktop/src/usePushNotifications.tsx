import { useEffect, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import type { View } from "./model";
import { invitationCount, notificationCount } from "./model";
import type { StreamEntry } from "./streamFeed";
import type { SyncResult } from "./liveSync";
import { sameHistoryScope, type HistoryPage } from "./messageHistory";
import { t } from "./i18n";
import { replyRoot } from "./messageThreads";
import {
  NotificationOffer,
  notificationOfferHandled,
  markNotificationOfferHandled,
  shouldOfferNotifications,
} from "./NotificationOffer";

export type NotificationTarget = {
  identity: string;
  category?: string;
  space?: string | null;
  stream?: string | null;
  record?: string | null;
};
type Opened = { id: string; target: NotificationTarget | null };
type Status = {
  available: boolean;
  enabled: boolean;
  pending: boolean;
  wake?: boolean;
  opened?: Opened | null;
};
const unavailable: Status = {
  available: false,
  enabled: false,
  pending: false,
};

/** Only navigate through verified local rows, never directly through push data. */
export function notificationEntry(
  view: View,
  target: NotificationTarget | null,
): StreamEntry | undefined {
  if (target?.identity !== view.identity) return;
  const chat = (view.all_streams ?? view.streams).find(
    (s) => s.space === target.space && s.stream === target.stream,
  );
  const row = chat?.rows.find((r) => r.id === target.record);
  if (chat && row)
    return { chat, row, key: `${chat.space}:${chat.stream}:${row.id}` };
}

export async function resolveNotificationEntry(
  view: View,
  target: NotificationTarget | null,
  read: (request: Record<string, unknown>) => Promise<{ history: HistoryPage }>,
): Promise<StreamEntry | undefined> {
  const loaded = notificationEntry(view, target);
  if (!view.paged) return loaded;
  if (target?.identity !== view.identity || !target.record) return;
  const chat = (view.all_streams ?? view.streams).find(
    (s) => s.space === target.space && s.stream === target.stream,
  );
  if (!chat) return;
  const context = chat.space_context ?? view.active_space;
  const request = {
    op: "history_page",
    expected_identity: view.identity,
    expected_space: view.active_space,
    target_space: context,
    space: chat.space,
    stream: chat.stream,
    around: target.record,
  };
  let { history } = await read(request);
  if (
    !sameHistoryScope(history, view.identity, context, chat.space, chat.stream)
  )
    return;
  let row = history.rows.find((r) => r.id === target.record);
  if (!row) return;
  const thread = replyRoot(row);
  if (thread) {
    ({ history } = await read({ ...request, thread }));
    if (
      !sameHistoryScope(
        history,
        view.identity,
        context,
        chat.space,
        chat.stream,
      ) ||
      history.thread !== thread
    )
      return;
    row = history.rows.find((r) => r.id === target.record);
    if (!row) return;
  }
  return { chat, row, key: `${chat.space}:${chat.stream}:${row.id}`, history };
}

/** Old or already handled invitations must not send the user to an empty inbox. */
export function notificationPage(
  view: View,
  target: NotificationTarget | null,
) {
  if (target?.identity !== view.identity || target.record) return;
  if (target.category === "membership" && notificationCount(view) > 0)
    return "notifications" as const;
  if (target.category === "invitation" && invitationCount(view) > 0)
    return "activity" as const;
}

/** Receive only within a locally joined chat's compartment. Unknown chats or
 * missing authority proofs need discovery before any message can be shown. */
export function notificationCatchUpRequest(
  view: View,
  target: NotificationTarget | null,
  needsProof = false,
): Record<string, unknown> | undefined {
  if (target?.identity !== view.identity) return;
  const chat = (view.all_streams ?? view.streams).find(
    (s) => s.space === target.space && s.stream === target.stream,
  );
  return chat && !needsProof
    ? {
        op: "sync_live",
        receive_only: true,
        target_space: chat.space_context ?? view.active_space,
        expected_identity: view.identity,
        expected_space: view.active_space,
      }
    : { op: "invitation_sync", force: true, expected_identity: view.identity };
}

export function usePushNotifications(
  view: View | null,
  busy: boolean,
  requestSync: (membership?: boolean) => void,
  onSync: (result: SyncResult) => void,
  onOpen: (
    entry: StreamEntry | undefined,
    page: "activity" | "notifications" | undefined,
  ) => boolean | Promise<boolean>,
  onError: (error: unknown) => void,
  offerReady = false,
  deferMaintenance: () => boolean = () => false,
) {
  const [status, setStatus] = useState<Status>(unavailable);
  const [changing, setChanging] = useState(false);
  const [showOpening, setShowOpening] = useState(false);
  const [offerHandled, setOfferHandled] = useState(notificationOfferHandled);
  const dismissOffer = () => {
    markNotificationOfferHandled();
    setOfferHandled(true);
  };
  useEffect(() => {
    // An existing opt-in (including pending registration) is already a decision.
    if (status.enabled && !offerHandled) dismissOffer();
  }, [status.enabled, offerHandled]);
  const [opened, setOpened] = useState<(Opened & { received: number }) | null>(
    null,
  );
  const latest = useRef({
    deferMaintenance,
    view,
    busy,
    changing,
    requestSync,
    onSync,
    onOpen,
    onError,
  });
  latest.current = {
    deferMaintenance,
    view,
    busy,
    changing,
    requestSync,
    onSync,
    onOpen,
    onError,
  };
  const running = useRef(false);
  const refresh = useRef<() => void>(() => {});
  const acknowledged = useRef<string | undefined>(undefined);
  const opening = useRef(false);
  const activeOpened = useRef<Opened | null>(null);
  const nextCatchUp = useRef(0);
  const catchingUp = useRef(false);
  const needsProof = useRef(false);
  const hintSerial = useRef(0);
  const receive = (result: Status, identity: string) => {
    if (latest.current.view?.identity !== identity) return;
    hintSerial.current++;
    setStatus(result);
    if (result.wake) {
      latest.current.requestSync();
      latest.current.requestSync(true);
    }
    if (result.opened && result.opened.id !== acknowledged.current) {
      const incoming = result.opened;
      const fresh = activeOpened.current?.id !== incoming.id;
      activeOpened.current = incoming;
      opening.current = true;
      setShowOpening(true);
      setOpened((old) =>
        old?.id === incoming.id ? old : { ...incoming, received: Date.now() },
      );
      if (fresh) {
        nextCatchUp.current = 0;
        needsProof.current = false;
      }
    } else if (!activeOpened.current) {
      opening.current = false;
      setShowOpening(false);
    }
  };
  useEffect(() => {
    setStatus(unavailable);
    setOpened(null);
    setShowOpening(false);
    hintSerial.current++;
    acknowledged.current = undefined;
    activeOpened.current = null;
    opening.current = !!view;
    if (!view) return;
    const identity = view.identity;
    let active = true;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const tick = async () => {
      clearTimeout(timer);
      if (!active || document.visibilityState !== "visible") return;
      if (
        !running.current &&
        !latest.current.busy &&
        !latest.current.changing
      ) {
        running.current = true;
        try {
          // Keep the switch usable even if the following network maintenance fails.
          // A tap must be consumed before network maintenance, including on resume.
          const snapshot = await invoke<Status>("push_task", {
            op: "status",
            expectedIdentity: identity,
          });
          if (active) receive(snapshot, identity);
          if (
            active &&
            !activeOpened.current &&
            !latest.current.deferMaintenance()
          ) {
            const result = await invoke<Status>("push_task", {
              op: "maintain",
              expectedIdentity: identity,
            });
            if (active) receive(result, identity);
          }
        } catch {
          if (active && !activeOpened.current) {
            opening.current = false;
            setShowOpening(false);
          }
          // Delivery and chat sync are independent; retry settings when connectivity returns.
          if (active)
            setStatus((old) =>
              old.available ? { ...old, pending: true } : old,
            );
        } finally {
          running.current = false;
        }
      }
      if (active) timer = setTimeout(() => void tick(), 8000);
    };
    const hint = async () => {
      if (document.visibilityState !== "visible") return;
      const serial = ++hintSerial.current;
      try {
        const pending = await invoke<{ opened?: string | null }>("push_task", {
          op: "hint",
          expectedIdentity: identity,
        });
        if (
          active &&
          serial === hintSerial.current &&
          pending.opened &&
          pending.opened !== acknowledged.current
        ) {
          opening.current = true;
          setShowOpening(true);
        }
      } catch {
        // This optional hint never controls navigation or message verification.
      }
    };
    const wake = () => {
      if (document.visibilityState === "visible") opening.current = true;
      void hint();
      void tick();
    };
    refresh.current = () => void tick();
    document.addEventListener("visibilitychange", wake);
    window.addEventListener("online", wake);
    wake();
    return () => {
      active = false;
      hintSerial.current++;
      clearTimeout(timer);
      document.removeEventListener("visibilitychange", wake);
      window.removeEventListener("online", wake);
    };
  }, [view?.identity]);
  // A membership edit or mute must update the recipient's server-side policy.
  const scopes = view?.streams
    .map((s) => `${s.stream}:${s.head}:${!!s.muted}`)
    .join("|");
  useEffect(() => refresh.current(), [scopes]);
  useEffect(() => {
    if (!view || !opened || busy || document.visibilityState !== "visible")
      return;
    let cancelled = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const finish = async (entry: StreamEntry | undefined) => {
      if (
        cancelled ||
        activeOpened.current?.id !== opened.id ||
        acknowledged.current === opened.id ||
        latest.current.view?.identity !== view.identity
      )
        return;
      const current = latest.current.view;
      acknowledged.current = opened.id;
      const navigated = await latest.current.onOpen(
        entry,
        notificationPage(current, opened.target),
      );
      if (
        latest.current.view?.identity !== current.identity ||
        activeOpened.current?.id !== opened.id
      )
        return;
      if (!navigated) {
        acknowledged.current = undefined;
        return;
      }
      opening.current = false;
      hintSerial.current++;
      setShowOpening(false);
      activeOpened.current = null;
      setOpened(null);
      void invoke("push_task", {
        op: `ack:${opened.id}`,
        expectedIdentity: view.identity,
      }).catch(() => {
        acknowledged.current = undefined;
      });
    };
    const resolve = async () => {
      let entry: StreamEntry | undefined;
      try {
        entry = await resolveNotificationEntry(view, opened.target, (request) =>
          invoke("operate", { request }),
        );
      } catch {
        // Catch-up may still be importing the chat, or the profile/Space changed.
      }
      if (cancelled) return;
      if (
        entry ||
        notificationPage(view, opened.target) ||
        !opened.target ||
        Date.now() - opened.received >= 60000
      ) {
        void finish(entry);
      } else {
        if (!catchingUp.current && Date.now() >= nextCatchUp.current) {
          const request = notificationCatchUpRequest(
            view,
            opened.target,
            needsProof.current,
          );
          if (request) {
            catchingUp.current = true;
            nextCatchUp.current = Date.now() + 4000;
            try {
              const result = await invoke<SyncResult>("operate", { request });
              if (
                activeOpened.current?.id === opened.id &&
                latest.current.view?.identity === view.identity
              ) {
                needsProof.current =
                  (result.result?.waiting_for_proof ?? 0) > 0;
                latest.current.onSync(result);
              }
            } catch {
              // Offline or switched profiles retry through the same scoped path.
            } finally {
              catchingUp.current = false;
            }
          }
        }
        if (cancelled) return;
        timer = setTimeout(() => void resolve(), 1000);
      }
    };
    void resolve();
    return () => {
      cancelled = true;
      clearTimeout(timer);
    };
  }, [view, opened, busy]);
  const toggle = async (enable = !status.enabled) => {
    if (!view || changing) return;
    const identity = view.identity;
    dismissOffer();
    setChanging(true);
    try {
      receive(
        await invoke<Status>("push_task", {
          op: enable ? "enable" : "disable",
          expectedIdentity: identity,
        }),
        identity,
      );
      if (latest.current.view?.identity === identity)
        latest.current.requestSync(true);
    } catch (error) {
      if (latest.current.view?.identity === identity) {
        latest.current.onError(error);
        refresh.current();
      }
    } finally {
      setChanging(false);
    }
  };
  const settings = status.available ? (
    <div className="push-settings">
      <button
        type="button"
        className="settings-toggle"
        role="switch"
        aria-checked={status.enabled}
        disabled={changing || busy}
        onClick={() => void toggle()}
      >
        <span>{t("notifications.system")}</span>
        <span className="toggle-track" aria-hidden="true">
          <span />
        </span>
      </button>
      <p className="muted" role="status">
        {t(
          changing
            ? "notifications.settingUp"
            : status.pending
              ? "notifications.pending"
              : "notifications.systemHelp",
        )}
      </p>
    </div>
  ) : null;
  return {
    isOpening: () => opening.current,
    showOpening,
    settings,
    offer: shouldOfferNotifications(
      !!view && offerReady && !busy && !changing,
      status,
      offerHandled,
    ) ? (
      <NotificationOffer
        onDecline={dismissOffer}
        onAccept={() => void toggle(true)}
      />
    ) : null,
  };
}
