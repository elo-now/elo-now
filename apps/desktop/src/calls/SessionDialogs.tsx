import { useSyncExternalStore } from "react";
import { ActionDialog } from "../ActionDialog";
import { t } from "../i18n";
import type { View } from "../model";
import type { Calls } from "./controller";

export function SessionDialogs({ calls }: { calls: Calls; view: View }) {
  const state = useSyncExternalStore(calls.subscribe, calls.getSnapshot);
  const busy = state.answering === true;
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
          onClick={() =>
            void calls.answer(
              request.chat,
              request.call,
              true,
              request.invitation_id,
            )
          }
        >
          {t(request.invitation_id ? "calls.endAndAnswer" : "calls.endAndJoin")}
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
