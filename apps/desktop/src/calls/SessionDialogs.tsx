import { useSyncExternalStore } from "react";
import { ActionDialog } from "../ActionDialog";
import { t } from "../i18n";
import type { View } from "../model";
import type { Calls } from "./controller";
import { activeSessions } from "./sessionPresence";
import { isRingingFor, sessionKey } from "./attention";

export function SessionDialogs({ calls, view }: { calls: Calls; view: View }) {
  const state = useSyncExternalStore(calls.subscribe, calls.getSnapshot);
  const incoming = state.incoming?.find((call) =>
    isRingingFor(call, view.identity),
  );
  const session =
    incoming && activeSessions(view, { [sessionKey(incoming)]: incoming })[0];
  const busy = state.answering === true;
  const nativePresented =
    session &&
    state.nativePresented?.some(
      (item) =>
        item.call_id === session.call.call_id &&
        item.invitation_id ===
          session.call.invitations?.[view.identity]?.invitation_id,
    );
  if (session && !nativePresented) {
    const invitation = session.call.invitations![view.identity];
    const caller =
      session.chat.member_names?.[invitation.invited_by] ??
      view.contacts?.find((contact) => contact.id === invitation.invited_by)
        ?.name ??
      t("calls.participant");
    return (
      <ActionDialog
        title={t("calls.incoming")}
        onClose={() => {
          if (!busy) void calls.decline(session.call);
        }}
      >
        <p>
          {t(
            session.call.kind === "direct"
              ? "calls.incomingDirect"
              : "calls.incomingGroup",
            { name: caller, chat: session.chat.name, space: session.spaceName },
          )}
        </p>
        {state.active && (
          <p>
            {t("calls.answerEndsCurrent", {
              chat: state.chat?.name ?? t("calls.active"),
            })}
          </p>
        )}
        <div className="call-choice">
          <button
            type="button"
            disabled={busy}
            onClick={() =>
              void calls.answer(
                session.chat,
                session.call,
                !!state.active,
                invitation.invitation_id,
              )
            }
          >
            {t(state.active ? "calls.endAndAnswer" : "calls.answer")}
          </button>
          <button
            type="button"
            className="secondary"
            disabled={busy}
            onClick={() => void calls.decline(session.call)}
          >
            {t("calls.decline")}
          </button>
        </div>
      </ActionDialog>
    );
  }
  const request = state.joinRequest;
  if (!request) return null;
  return (
    <ActionDialog
      title={t("calls.switchTitle")}
      onClose={() => {
        if (!busy) calls.cancelJoin();
      }}
    >
      <p>
        {t("calls.switchHelp", {
          current: state.chat?.name ?? t("calls.active"),
          next: request.chat.name,
        })}
      </p>
      <div className="call-choice">
        <button
          type="button"
          disabled={busy}
          onClick={() => void calls.answer(request.chat, request.call, true)}
        >
          {t("calls.endAndJoin")}
        </button>
        <button
          type="button"
          className="secondary"
          disabled={busy}
          onClick={calls.cancelJoin}
        >
          {t("dialog.cancel")}
        </button>
      </div>
    </ActionDialog>
  );
}
