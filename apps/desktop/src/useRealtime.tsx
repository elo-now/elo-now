import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { updateRequired, useUpdateRequired } from "./releasePolicy";
import { formatFileSize, t } from "./i18n";
import { senderInitials, senderName, type Stream, type View } from "./model";
import { Icon } from "./Icon";
import {
  onlineInScope,
  pendingRemoteUploads,
  realtimeScope,
  realtimeScopes,
  realtimeStateKey,
  sameRealtimeScope,
  typingPeople,
  visibleRealtimeEvents,
  type RealtimeEvent,
  type RealtimeNotice,
  type RealtimeScope,
} from "./realtime";
import "./realtime.css";

type RealtimeValue = {
  view: View | null;
  events: readonly RealtimeEvent[];
  now: number;
  typing: (active: boolean) => void;
};
const empty: RealtimeValue = {
  view: null,
  events: [],
  now: 0,
  typing: () => {},
};
const RealtimeContext = createContext(empty);
export const RealtimeProvider = RealtimeContext.Provider;
export const useRealtimePresentation = () => useContext(RealtimeContext);

export function useRealtime(
  view: View | null,
  chat: Stream | undefined,
  onSync: (space: string) => void,
) {
  const restricted = useUpdateRequired();
  const profile = JSON.stringify([
    view?.identity,
    view?.credential,
    view?.active_space,
  ]);
  const scopesKey = useMemo(
    () => JSON.stringify(view ? realtimeScopes(view, chat) : []),
    [view, chat?.space_context, chat?.space, chat?.stream],
  );
  const typingScope = view && chat ? realtimeScope(view, chat) : undefined;
  const typingKey = JSON.stringify(typingScope);
  const latest = useRef({ view, profile, onSync, scopesKey, typingScope });
  latest.current = { view, profile, onSync, scopesKey, typingScope };
  const [snapshot, setSnapshot] = useState({
    profile,
    events: [] as RealtimeEvent[],
    connected: [] as string[],
  });
  const [now, setNow] = useState(Date.now);
  const controller = useRef<{
    publish: () => void;
    typing: (active: boolean) => void;
  } | null>(null);
  useEffect(() => {
    if (!view) return;
    const identity = view.identity;
    const currentProfile = profile;
    let alive = true;
    let listening = false;
    let contextRevision = 0;
    let typingUntil = 0;
    let lastTyping = 0;
    let typingTimer: ReturnType<typeof setTimeout> | undefined;
    let lastContext = "";
    let lastSnapshot = "";
    const valid = () => alive && latest.current.profile === currentProfile;
    const foreground = () =>
      document.visibilityState === "visible" &&
      navigator.onLine !== false &&
      !updateRequired();
    const clearState = () => {
      lastSnapshot = "";
      setSnapshot((previous) =>
        previous.profile === currentProfile &&
        previous.events.length === 0 &&
        previous.connected.length === 0
          ? previous
          : { profile: currentProfile, events: [], connected: [] },
      );
    };
    clearState();
    const publish = (forceTyping = false) => {
      if (!valid() || !listening) return;
      const scopes = JSON.parse(latest.current.scopesKey) as RealtimeScope[];
      const active = foreground() && scopes.length > 0;
      const context = {
        expected_identity: identity,
        expected_space: latest.current.view?.active_space,
        active,
        scopes,
        ...(active && latest.current.typingScope
          ? { focus: latest.current.typingScope }
          : {}),
        ...(active && typingUntil > Date.now() && latest.current.typingScope
          ? { typing: latest.current.typingScope }
          : {}),
      };
      const key = JSON.stringify(context);
      if (!forceTyping && key === lastContext) return;
      lastContext = key;
      const revision = ++contextRevision;
      void invoke("realtime_context", { context }).catch(() => {
        if (valid() && revision === contextRevision) {
          lastContext = "";
          clearState();
        }
      });
    };
    const typing = (active: boolean) => {
      if (!valid() || !foreground() || !latest.current.typingScope) return;
      if (typingTimer) clearTimeout(typingTimer);
      const time = Date.now();
      const alreadyTyping = typingUntil > time;
      typingUntil = active ? time + 8_000 : 0;
      if (!active || !alreadyTyping || time - lastTyping >= 3_000) {
        if (active) lastTyping = time;
        publish(active);
      }
      if (active)
        typingTimer = setTimeout(() => {
          typingUntil = 0;
          publish();
        }, 8_000);
    };
    const changed = () => {
      typingUntil = 0;
      if (typingTimer) clearTimeout(typingTimer);
      if (!foreground()) clearState();
      publish();
    };
    controller.current = { publish, typing };
    const listener = listen<RealtimeNotice>("realtime-event", ({ payload }) => {
      if (!valid() || payload.identity !== identity || !foreground()) return;
      if (payload.type === "sync") {
        latest.current.onSync(payload.space_context);
      } else {
        const scopes = JSON.parse(latest.current.scopesKey) as RealtimeScope[];
        const blocked = new Set(
          latest.current.view?.blocked_users?.map((person) => person.identity),
        );
        const next = {
          profile: currentProfile,
          connected: payload.connected_spaces,
          events: payload.events.filter(
            (event) =>
              !blocked.has(event.issuer_identity) &&
              scopes.some((scope) => sameRealtimeScope(event, scope)),
          ),
        };
        const key = realtimeStateKey(next.connected, next.events);
        if (key === lastSnapshot) return;
        lastSnapshot = key;
        setNow(Date.now());
        setSnapshot(next);
      }
    });
    void listener
      .then(() => {
        if (valid()) {
          listening = true;
          publish();
        }
      })
      .catch(() => {
        if (valid()) clearState();
      });
    document.addEventListener("visibilitychange", changed);
    window.addEventListener("online", changed);
    window.addEventListener("offline", changed);
    window.addEventListener("pageshow", changed);
    return () => {
      alive = false;
      controller.current = null;
      if (typingTimer) clearTimeout(typingTimer);
      document.removeEventListener("visibilitychange", changed);
      window.removeEventListener("online", changed);
      window.removeEventListener("offline", changed);
      window.removeEventListener("pageshow", changed);
      void listener.then((unlisten) => unlisten()).catch(() => {});
      void invoke("realtime_context", {
        context: {
          expected_identity: identity,
          expected_space: view.active_space,
          active: false,
          scopes: [],
        },
      }).catch(() => {});
    };
  }, [profile]);
  useEffect(() => {
    controller.current?.typing(false);
    controller.current?.publish();
  }, [scopesKey, typingKey, restricted]);
  const current =
    snapshot.profile === profile ? snapshot : { events: [], connected: [] };
  // One expiry timer; no network polling or per-avatar timers.
  useEffect(() => {
    const time = Date.now();
    const deadlines = current.events
      .flatMap((event) => [
        event.expires_at_ms,
        ...(event.payload.kind === "upload" &&
        ["uploading", "ready"].includes(event.payload.status)
          ? [event.expires_at_ms + 60_000]
          : []),
      ])
      .filter((deadline) => deadline > time);
    if (!deadlines.length) return;
    const timer = setTimeout(
      () => setNow(Date.now()),
      Math.min(...deadlines) - time + 1,
    );
    return () => clearTimeout(timer);
  }, [snapshot, now, profile]);
  const typing = useCallback(
    (active: boolean) => controller.current?.typing(active),
    [],
  );
  const value = useMemo(
    () => ({
      view,
      events: view ? visibleRealtimeEvents(view, current.events) : [],
      now,
      typing,
    }),
    [view, current.events, now, typing],
  );
  return {
    value,
    connectedSpaces: current.connected,
  };
}

export function OnlineIndicator({
  identity,
  chat,
}: {
  identity: string;
  chat?: Stream;
}) {
  const { view, events, now } = useRealtimePresentation();
  if (
    !view ||
    view.blocked_users?.some((person) => person.identity === identity)
  )
    return null;
  const chats = chat ? [chat] : view.streams;
  const online = chats.some((candidate) => {
    if (!candidate.members.some((member) => member.identity_id === identity))
      return false;
    const scope = realtimeScope(view, candidate);
    return scope && onlineInScope(events, identity, scope, now);
  });
  return online ? (
    <span
      className="online-indicator"
      role="img"
      aria-label={t("realtime.online")}
      title={t("realtime.online")}
    />
  ) : null;
}

export function DirectOnlineIndicator({
  chat,
  identity,
}: {
  chat: Stream;
  identity: string;
}) {
  const peers = chat.members.filter(
    (member) => member.identity_id !== identity,
  );
  return peers.length === 1 ? (
    <OnlineIndicator identity={peers[0].identity_id} chat={chat} />
  ) : null;
}

export function TypingIndicator({ chat }: { chat?: Stream }) {
  const { view, events, now } = useRealtimePresentation();
  if (!view || !chat) return null;
  const scope = realtimeScope(view, chat);
  const people = scope ? typingPeople(events, scope, view.identity, now) : [];
  if (!people.length) return null;
  const label =
    people.length === 1
      ? t("realtime.typingOne", { name: senderName(view, people[0], chat) })
      : people.length === 2
        ? t("realtime.typingTwo", {
            first: senderName(view, people[0], chat),
            second: senderName(view, people[1], chat),
          })
        : t("realtime.typingMany", { count: people.length });
  return (
    <div className="typing-indicator" role="status">
      {label}
    </div>
  );
}

export function RemoteUploads({
  view,
  chat,
  hideAvatars,
}: {
  view: View;
  chat?: Stream;
  hideAvatars: boolean;
}) {
  const { events, now } = useRealtimePresentation();
  if (!chat) return null;
  return pendingRemoteUploads(events, view, chat, now).map((event) => (
    <article
      className="message remote-upload"
      data-hide-avatars={hideAvatars || undefined}
      key={`${event.issuer_identity}:${event.payload.attachment_id}`}
    >
      {!hideAvatars && (
        <div className="avatar">
          {senderInitials(view, event.issuer_identity, chat)}
          <OnlineIndicator identity={event.issuer_identity} chat={chat} />
        </div>
      )}
      <div className="message-content">
        <div className="message-meta">
          <strong>{senderName(view, event.issuer_identity, chat)}</strong>
        </div>
        <div className="remote-upload-tile">
          <Icon name="attachment" />
          <span className="remote-upload-details">
            <strong>{event.payload.name}</strong>
            <small>{formatFileSize(event.payload.size)}</small>
            <span role="status">
              {t(
                event.payload.status === "interrupted"
                  ? "realtime.uploadInterrupted"
                  : "file.uploading",
              )}
            </span>
          </span>
        </div>
      </div>
    </article>
  ));
}
