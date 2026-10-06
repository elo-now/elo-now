import { updateRequired, subscribeUpdateRequired } from "./releasePolicy";
import { useEffect, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import type { Stream, View } from "./model";
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
  space_context?: string;
  call_id?: string;
  expires?: number;
  space?: string | null;
  stream?: string | null;
  record?: string | null;
  chat?: { space: string; stream: string; invitation: string } | null;
};
/** A preapproved invitation may already be a joined chat. Resolve only against
 * verified local membership; an encrypted target alone never grants access. */
export function notificationChat(
  view: View,
  target: NotificationTarget | null,
): Stream | undefined {
  if (target?.identity !== view.identity || target.record) return;
  const scope =
    target.category === "invitation"
      ? target.chat
      : target.category === "session_start" &&
          target.call_id &&
          /^[0-9a-f]{32}$/.test(target.call_id)
        ? target
        : undefined;
  if (!scope?.space || !scope.stream) return;
  return (view.all_streams ?? view.streams).find(
    (chat) =>
      chat.space === scope.space &&
      chat.stream === scope.stream &&
      !chat.forked &&
      matchesNotificationContext(view, chat, target) &&
      chat.members.some(
        (member) =>
          member.identity_id === view.identity &&
          member.capabilities.includes("READ"),
      ),
  );
}

function matchesNotificationContext(
  view: View,
  chat: Stream,
  target: NotificationTarget,
) {
  return (
    !target.space_context ||
    (chat.space_context ?? view.active_space) === target.space_context
  );
}

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

export const NOTIFICATION_OPEN_TIMEOUT_MS = 8000;
const handledOpenKey = "elo.notificationOpening.handled.v1";
type HandledOpen = { identity: string; id: string };
function handledOpens(): HandledOpen[] {
  try {
    const value: unknown = JSON.parse(
      localStorage.getItem(handledOpenKey) ?? "[]",
    );
    return Array.isArray(value)
      ? value
          .filter(
            (item): item is HandledOpen =>
              typeof item?.identity === "string" &&
              item.identity.length <= 512 &&
              typeof item?.id === "string" &&
              item.id.length <= 512,
          )
          .slice(-32)
      : [];
  } catch {
    return [];
  }
}
function rememberOpen(identity: string, id: string) {
  try {
    const previous = handledOpens().filter(
      (item) => item.identity !== identity || item.id !== id,
    );
    localStorage.setItem(
      handledOpenKey,
      JSON.stringify([...previous, { identity, id }].slice(-32)),
    );
  } catch {
    /* Storage availability must never control the UI deadline. */
  }
}
function openWasHandled(identity: string, id: string) {
  return handledOpens().some(
    (item) => item.identity === identity && item.id === id,
  );
}

/** A wall-clock UI budget independent of any pending native/network promise.
 * Only opaque local tap IDs are retained; this never marks content as read. */
export class NotificationOpeningAttempt {
  private active?: { identity: string; id?: string; deadline: number };
  private timer?: ReturnType<typeof setTimeout>;
  constructor(
    private readonly change: (active: boolean, visible: boolean) => void,
    private readonly timedOut: (identity: string, id?: string) => void,
  ) {}
  begin(identity: string, id?: string): boolean {
    if (id && openWasHandled(identity, id)) {
      this.clearMatching(identity, id);
      return false;
    }
    const previous = this.active;
    if (
      previous?.identity === identity &&
      (!id || !previous.id || previous.id === id)
    ) {
      if (id) previous.id = id;
      if (!this.current(identity, id)) return false;
      this.change(true, !!previous.id);
      return true;
    }
    this.reset();
    const attempt = {
      identity,
      id,
      deadline: Date.now() + NOTIFICATION_OPEN_TIMEOUT_MS,
    };
    this.active = attempt;
    this.change(true, !!id);
    this.timer = setTimeout(
      () => this.expire(attempt),
      NOTIFICATION_OPEN_TIMEOUT_MS,
    );
    return true;
  }
  current(identity: string, id?: string): boolean {
    const attempt = this.active;
    if (!attempt || attempt.identity !== identity || (id && attempt.id !== id))
      return false;
    if (Date.now() >= attempt.deadline) {
      this.expire(attempt);
      return false;
    }
    return true;
  }
  complete(identity: string, id: string) {
    if (!this.current(identity, id)) return;
    rememberOpen(identity, id);
    this.reset();
  }
  deadline() {
    return this.active?.deadline ?? 0;
  }
  ignore(identity: string, id: string) {
    rememberOpen(identity, id);
    this.clearMatching(identity, id);
  }
  private clearMatching(identity: string, id: string) {
    if (
      this.active?.identity === identity &&
      (!this.active.id || this.active.id === id)
    )
      this.reset();
  }
  reset() {
    clearTimeout(this.timer);
    this.timer = undefined;
    this.active = undefined;
    this.change(false, false);
  }
  private expire(attempt: { identity: string; id?: string; deadline: number }) {
    if (this.active !== attempt) return;
    if (attempt.id) rememberOpen(attempt.identity, attempt.id);
    this.reset();
    this.timedOut(attempt.identity, attempt.id);
  }
}

/** Only navigate through verified local rows, never directly through push data. */
export function notificationEntry(
  view: View,
  target: NotificationTarget | null,
): StreamEntry | undefined {
  if (target?.identity !== view.identity) return;
  const chat = (view.all_streams ?? view.streams).find(
    (s) =>
      s.space === target.space &&
      s.stream === target.stream &&
      matchesNotificationContext(view, s, target),
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
    (s) =>
      s.space === target.space &&
      s.stream === target.stream &&
      matchesNotificationContext(view, s, target),
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
  if (notificationChat(view, target)) return;
  if (target.space && view.spaces) {
    const space = view.spaces.find(
      (space) => space.id === target.space && space.status === "joined",
    );
    if (!space || !space.activity) return;
  }
  if (target.category === "membership" && notificationCount(view) > 0)
    return "notifications" as const;
  if (target.category === "invitation" && invitationCount(view) > 0)
    return "activity" as const;
}

export function notificationSpace(
  view: View,
  target: NotificationTarget | null,
): string | undefined {
  const chat = notificationChat(view, target);
  if (chat) return chat.space_context ?? view.active_space ?? undefined;
  if (target?.identity !== view.identity || !target.space || target.record)
    return;
  return view.spaces?.find(
    (space) => space.id === target.space && space.status === "joined",
  )?.id;
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
    (s) =>
      s.space === target.space &&
      s.stream === target.stream &&
      matchesNotificationContext(view, s, target),
  );
  const context =
    chat?.space_context ??
    (chat
      ? view.active_space
      : view.spaces?.find(
          (space) => space.id === target.space && space.status === "joined",
        )?.id);
  return chat && !needsProof
    ? {
        op: "sync_live",
        foreground: true,
        receive_only: true,
        target_space: chat.space_context ?? view.active_space,
        expected_identity: view.identity,
        expected_space: view.active_space,
      }
    : {
        op: "invitation_sync",
        foreground: true,
        force: true,
        ...(context ? { target_space: context } : {}),
        ...(context && target.category === "invitation" && target.chat
          ? { receive_only: true }
          : {}),
        expected_identity: view.identity,
      };
}

export function usePushNotifications(
  view: View | null,
  busy: boolean,
  requestSync: (membership?: boolean) => void,
  onSync: (result: SyncResult) => void,
  onOpen: (
    entry: StreamEntry | undefined,
    page: "activity" | "notifications" | undefined,
    space: string | undefined,
    chat: Stream | undefined,
    isCurrent: () => boolean,
    deadline: number,
    openId: string,
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
  const [opened, setOpened] = useState<Opened | null>(null);
  const latest = useRef({
    status,
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
    status,
    deferMaintenance,
    view,
    busy,
    changing,
    requestSync,
    onSync,
    onOpen,
    onError,
  };
  const settingsRevision = useRef(0);
  const refresh = useRef<() => void>(() => {});
  const acknowledged = useRef<string | undefined>(undefined);
  const opening = useRef(false);
  const activeOpened = useRef<Opened | null>(null);
  const nextCatchUp = useRef(0);
  const catchingUp = useRef(false);
  const needsProof = useRef(false);
  const hintSerial = useRef(0);
  const hintEpoch = useRef(0);
  const acknowledging = useRef(new Set<string>());
  const acknowledgeTap = (identity: string, id: string) => {
    const key = `${identity}:${id}`;
    if (acknowledging.current.has(key)) return;
    acknowledging.current.add(key);
    void invoke("push_task", { op: `ack:${id}`, expectedIdentity: identity })
      .catch(() => {})
      .finally(() => acknowledging.current.delete(key));
  };
  const attempt = useRef<NotificationOpeningAttempt | null>(null);
  attempt.current ??= new NotificationOpeningAttempt(
    (active, visible) => {
      opening.current = active;
      setShowOpening(visible);
    },
    (identity, id) => {
      if (latest.current.view?.identity !== identity) return;
      const verified = activeOpened.current;
      activeOpened.current = null;
      hintSerial.current++;
      setOpened(null);
      if (id) {
        if (
          verified?.id === id &&
          (!verified.target || verified.target.identity === identity)
        )
          acknowledgeTap(identity, id);
        latest.current.onError(t("notifications.openingTimeout"));
      }
    },
  );
  const receive = (
    result: Status,
    identity: string,
    requestDeadline: number,
  ) => {
    if (latest.current.view?.identity !== identity) return;
    hintSerial.current++;
    latest.current.status = result;
    setStatus(result);
    if (result.wake) {
      latest.current.requestSync();
      latest.current.requestSync(true);
    }
    if (result.opened && result.opened.id !== acknowledged.current) {
      const incoming = result.opened;
      if (
        !attempt.current!.current(identity, incoming.id) &&
        Date.now() >= requestDeadline
      ) {
        const handled = openWasHandled(identity, incoming.id);
        attempt.current!.ignore(identity, incoming.id);
        if (!incoming.target || incoming.target.identity === identity)
          acknowledgeTap(identity, incoming.id);
        if (!handled) latest.current.onError(t("notifications.openingTimeout"));
        return;
      }
      if (!attempt.current!.begin(identity, incoming.id)) {
        if (!incoming.target || incoming.target.identity === identity)
          acknowledgeTap(identity, incoming.id);
        return;
      }
      const fresh = activeOpened.current?.id !== incoming.id;
      activeOpened.current = incoming;
      setOpened((old) => (old?.id === incoming.id ? old : incoming));
      if (fresh) {
        nextCatchUp.current = 0;
        needsProof.current = false;
      }
    } else if (!activeOpened.current) {
      attempt.current!.reset();
    }
  };
  useEffect(() => {
    setStatus(unavailable);
    setOpened(null);
    setShowOpening(false);
    hintSerial.current++;
    acknowledged.current = undefined;
    activeOpened.current = null;
    attempt.current!.reset();
    if (!view) return;
    const identity = view.identity;
    let active = true;
    let running = false;
    let refreshQueued = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const tick = async () => {
      clearTimeout(timer);
      if (!active || updateRequired() || document.visibilityState !== "visible")
        return;
      if (running) {
        refreshQueued = true;
        return;
      }
      if (!latest.current.busy && !latest.current.changing) {
        running = true;
        refreshQueued = false;
        const revision = settingsRevision.current;
        const requestDeadline =
          attempt.current!.deadline() ||
          Date.now() + NOTIFICATION_OPEN_TIMEOUT_MS;
        const requestEpoch = hintEpoch.current;
        const current = () =>
          active &&
          revision === settingsRevision.current &&
          requestEpoch === hintEpoch.current;
        try {
          // Keep the switch usable even if the following network maintenance fails.
          // A tap must be consumed before network maintenance, including on resume.
          const snapshot = await invoke<Status>("push_task", {
            op: "status",
            expectedIdentity: identity,
          });
          if (current()) receive(snapshot, identity, requestDeadline);
          if (
            current() &&
            !latest.current.changing &&
            !activeOpened.current &&
            !latest.current.deferMaintenance()
          ) {
            const result = await invoke<Status>("push_task", {
              op: "maintain",
              expectedIdentity: identity,
            });
            if (current()) receive(result, identity, requestDeadline);
          }
        } catch {
          if (current() && !activeOpened.current) {
            attempt.current!.reset();
          }
          // Delivery and chat sync are independent; retry settings when connectivity returns.
          if (current())
            setStatus((old) =>
              old.available ? { ...old, pending: true } : old,
            );
        } finally {
          running = false;
        }
      }
      if (active)
        timer = setTimeout(
          () => void tick(),
          refreshQueued
            ? latest.current.busy || latest.current.changing
              ? 500
              : 100
            : latest.current.status.pending
              ? 1000
              : 8000,
        );
    };
    const hint = async () => {
      if (updateRequired() || document.visibilityState !== "visible") return;
      // A snapshot already waiting for native state belongs to the previous tap.
      // Neither its target, an empty result nor its error may reset the new one.
      hintEpoch.current++;
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
          attempt.current!.begin(identity, pending.opened);
        }
      } catch {
        // This optional hint never controls navigation or message verification.
      }
    };
    const wake = () => {
      refreshQueued = true;
      if (!updateRequired() && document.visibilityState === "visible")
        attempt.current!.begin(identity);
      void hint();
      void tick();
    };
    const unsubscribePolicy = subscribeUpdateRequired(wake);
    refresh.current = () => {
      refreshQueued = true;
      void tick();
    };
    const listener = listen("push-changed", () => {
      if (active) wake();
    }).catch(() => undefined);
    document.addEventListener("visibilitychange", wake);
    window.addEventListener("online", wake);
    wake();
    return () => {
      active = false;
      unsubscribePolicy();
      hintSerial.current++;
      attempt.current!.reset();
      clearTimeout(timer);
      void listener.then((unlisten) => unlisten?.());
      document.removeEventListener("visibilitychange", wake);
      window.removeEventListener("online", wake);
    };
  }, [view?.identity]);
  useEffect(() => {
    if (!changing) refresh.current();
  }, [changing]);
  // A membership edit or mute must update the recipient's server-side policy.
  const scopes = (view?.all_streams ?? view?.streams)
    ?.map((s) => `${s.stream}:${s.head}:${!!s.muted}`)
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
        !attempt.current!.current(view.identity, opened.id) ||
        latest.current.view?.identity !== view.identity
      )
        return;
      const current = latest.current.view;
      acknowledged.current = opened.id;
      let navigated = false;
      const isCurrent = () =>
        latest.current.view?.identity === current.identity &&
        activeOpened.current?.id === opened.id &&
        attempt.current!.current(current.identity, opened.id);
      try {
        navigated = await latest.current.onOpen(
          entry,
          notificationPage(current, opened.target),
          notificationSpace(current, opened.target),
          notificationChat(current, opened.target),
          isCurrent,
          attempt.current!.deadline(),
          opened.id,
        );
      } catch (error) {
        acknowledged.current = undefined;
        if (isCurrent()) latest.current.onError(error);
        return;
      }
      if (
        latest.current.view?.identity !== current.identity ||
        activeOpened.current?.id !== opened.id ||
        !isCurrent()
      )
        return;
      if (!navigated) {
        acknowledged.current = undefined;
        return;
      }
      attempt.current!.complete(current.identity, opened.id);
      hintSerial.current++;
      setShowOpening(false);
      activeOpened.current = null;
      setOpened(null);
      if (notificationChat(current, opened.target) && opened.target?.chat) {
        // The core checks the signed membership approval before issuing a receipt.
        void invoke("operate", {
          request: {
            op: "invitation_activity_seen",
            expected_identity: current.identity,
            ids: [`invitation:${opened.target.chat.invitation}`],
          },
        }).catch(latest.current.onError);
      }
      acknowledgeTap(view.identity, opened.id);
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
      if (cancelled || !attempt.current!.current(view.identity, opened.id))
        return;
      if (
        entry ||
        notificationChat(view, opened.target) ||
        notificationPage(view, opened.target) ||
        !opened.target ||
        (opened.target.category === "session_start" &&
          (!opened.target.expires || opened.target.expires <= Date.now()))
      ) {
        void finish(entry);
      } else {
        let delay = 1000;
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
                attempt.current!.current(view.identity, opened.id) &&
                latest.current.view?.identity === view.identity
              ) {
                needsProof.current =
                  (result.result?.waiting_for_proof ?? 0) > 0;
                if (
                  result.delivery?.more &&
                  (!result.delivery.retry || result.delivery.progressed)
                ) {
                  // Continue a bounded inbox batch without the idle retry gap.
                  delay = 250;
                  nextCatchUp.current = Date.now() + delay;
                }
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
        timer = setTimeout(() => void resolve(), delay);
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
    if (!enable) dismissOffer();
    settingsRevision.current++;
    latest.current.changing = true;
    setChanging(true);
    const requestDeadline = Date.now() + NOTIFICATION_OPEN_TIMEOUT_MS;
    try {
      const updated = await invoke<Status>("push_task", {
        op: enable ? "enable" : "disable",
        expectedIdentity: identity,
      });
      receive(updated, identity, requestDeadline);
      if (updated.enabled) dismissOffer();
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
      <p
        className={changing || status.pending ? "muted danger" : "muted"}
        role="status"
      >
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
