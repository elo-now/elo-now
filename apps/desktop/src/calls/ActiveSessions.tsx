import { useSyncExternalStore } from "react";
import { Phone } from "lucide-react";
import { locale, t } from "../i18n";
import type { Stream, View } from "../model";
import type { Calls } from "./controller";
import { activeSessions, type ActiveSession } from "./sessionPresence";
import { scopeKey } from "./types";
import "./calls.css";

function SessionDetails({ session }: { session: ActiveSession }) {
  const names = new Intl.ListFormat(locale, {
    style: "short",
    type: "conjunction",
  }).format(session.participantNames);
  return (
    <span className="active-session-details">
      <strong>{session.chat.name}</strong>
      <small>{t("calls.inSpace", { name: session.spaceName })}</small>
      <small className="active-session-participants">
        {t("calls.sessionParticipants", { names })}
      </small>
    </span>
  );
}

export function ActiveSessions({
  calls,
  view,
  onOpen,
  compact = false,
}: {
  calls: Calls;
  view: View;
  onOpen: (chat: Stream) => void;
  compact?: boolean;
}) {
  const state = useSyncExternalStore(
    calls.subscribe,
    calls.getSnapshot,
    calls.getSnapshot,
  );
  const sessions = activeSessions(view, state.available);
  if (!sessions.length) return null;
  return (
    <section
      className={
        compact ? "desktop-nav-section active-sessions" : "active-sessions"
      }
      aria-label={t("calls.activeSessions")}
    >
      <h2>{t("calls.activeSessions")}</h2>
      {sessions.map((session) => (
        <button
          type="button"
          className={
            compact
              ? "desktop-nav-item active-session-row"
              : "active-session-row"
          }
          key={`${scopeKey(session.chat)}:${session.call.call_id}`}
          aria-label={t("calls.openSession", {
            chat: session.chat.name,
            space: session.spaceName,
          })}
          onClick={() => onOpen(session.chat)}
        >
          <Phone size={18} aria-hidden="true" />
          <SessionDetails session={session} />
          <span className="active-session-dot" aria-hidden="true" />
        </button>
      ))}
    </section>
  );
}

export function ActiveSessionJoin({
  calls,
  view,
  chat,
}: {
  calls: Calls;
  view: View;
  chat: Stream;
}) {
  const state = useSyncExternalStore(
    calls.subscribe,
    calls.getSnapshot,
    calls.getSnapshot,
  );
  const key = scopeKey({
    ...chat,
    space_context: chat.space_context ?? view.active_space ?? undefined,
  });
  const session = activeSessions(view, state.available).find(
    (entry) => scopeKey(entry.chat) === key,
  );
  if (!session) return null;
  return (
    <div className="active-session-join">
      <Phone size={18} aria-hidden="true" />
      <SessionDetails session={session} />
      <button
        type="button"
        className="secondary"
        disabled={!!state.active || state.phase !== "idle"}
        onClick={() => void calls.start(session.chat, session.call)}
      >
        {t("calls.joinSession")}
      </button>
    </div>
  );
}
