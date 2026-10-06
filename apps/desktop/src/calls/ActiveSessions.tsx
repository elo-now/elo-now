import { useSyncExternalStore } from "react";
import { Phone } from "lucide-react";
import { locale, t } from "../i18n";
import type { Stream, View } from "../model";
import type { Calls } from "./controller";
import { activeSessions, type ActiveSession } from "./sessionPresence";
import { callKey, scopeKey } from "./types";
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
  if (!sessions.length)
    return <p className="call-list-empty">{t("calls.none")}</p>;
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
              <Phone size={20} aria-hidden="true" />
              <SessionDetails session={session} />
            </button>
            <button
              type="button"
              className="quiet"
              disabled={state.answering}
              onClick={() =>
                joined
                  ? calls.expand()
                  : calls.requestStart(session.chat, session.call)
              }
            >
              {t(joined ? "calls.open" : "calls.joinSession")}
            </button>
          </article>
        );
      })}
    </section>
  );
}
