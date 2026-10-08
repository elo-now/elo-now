import { useSyncExternalStore } from "react";
import { Phone } from "lucide-react";
import { EmptyState } from "../EmptyState";
import { locale, t } from "../i18n";
import type { Stream, View } from "../model";
import type { Calls } from "./controller";
import { activeSessions, type ActiveSession } from "./sessionPresence";
import { callKey, scopeKey } from "./types";
import "./calls.css";

function SessionDetails({
  session,
  showSpace,
}: {
  session: ActiveSession;
  showSpace: boolean;
}) {
  const names = new Intl.ListFormat(locale, {
    style: "short",
    type: "conjunction",
  }).format(session.participantNames);
  return (
    <span className="active-session-details">
      <strong>{session.chat.name}</strong>
      {showSpace && (
        <small>{t("calls.inSpace", { name: session.spaceName })}</small>
      )}
      <small className="active-session-participants">
        {t("calls.sessionParticipants", { names })}
      </small>
    </span>
  );
}

export function CallList({
  calls,
  view,
  onOpen,
}: {
  calls: Calls;
  view: View;
  onOpen: (chat: Stream) => void;
}) {
  const state = useSyncExternalStore(
    calls.subscribe,
    calls.getSnapshot,
    calls.getSnapshot,
  );
  const sessions = activeSessions(view, state.available);
  if (!sessions.length) return <EmptyState message={t("calls.none")} />;
  return (
    <section className="call-list" aria-label={t("calls.activeSessions")}>
      {sessions.map((session) => {
        const joined =
          state.active?.call_id === session.call.call_id &&
          callKey(state.active) === callKey(session.call);
        return (
          <article
            className="call-list-row"
            key={`${scopeKey(session.chat)}:${session.call.call_id}`}
          >
            <button
              type="button"
              className="call-list-chat"
              onClick={() => {
                calls.reveal(session.chat);
                onOpen(session.chat);
              }}
            >
              <SessionDetails
                session={session}
                showSpace={
                  session.call.scope.hosting_space_id !== view.active_space
                }
              />
            </button>
            <button
              type="button"
              className="call-list-open"
              disabled={state.answering}
              aria-label={t(joined ? "calls.open" : "calls.joinSession")}
              title={t(joined ? "calls.open" : "calls.joinSession")}
              onClick={() => calls.requestStart(session.chat, session.call)}
            >
              <Phone size={20} aria-hidden="true" />
            </button>
          </article>
        );
      })}
    </section>
  );
}
