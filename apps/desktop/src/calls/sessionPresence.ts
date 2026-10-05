import { t } from "../i18n";
import type { Stream, View } from "../model";
import { callKey, scopeKey, type ActiveCall } from "./types";

export type ActiveSession = {
  call: ActiveCall;
  chat: Stream;
  spaceName: string;
  participantNames: string[];
  starterName: string;
};
export type SessionStarted = ActiveSession;

export function sessionAvailable(call: ActiveCall): boolean {
  return (
    call.ready === true &&
    Object.values(call.participants).some((person) => person.ready === true)
  );
}

export function activeSessions(
  view: View,
  available: Record<string, ActiveCall>,
): ActiveSession[] {
  const chats = (view.all_streams ?? view.streams).map((chat) => ({
    ...chat,
    space_context: chat.space_context ?? view.active_space ?? undefined,
  }));
  return Object.values(available)
    .flatMap((call) => {
      if (!sessionAvailable(call)) return [];
      const chat = chats.find((entry) => scopeKey(entry) === callKey(call));
      const space = view.spaces?.find(
        (entry) => entry.id === call.scope.hosting_space_id,
      );
      if (
        !chat ||
        chat.forked ||
        !chat.can_post ||
        chat.head !== call.config_id ||
        space?.status !== "joined"
      )
        return [];
      const name = (identity: string) =>
        identity === view.identity
          ? view.name || t("calls.you")
          : chat.member_names?.[identity] ||
            view.contacts?.find((entry) => entry.id === identity)?.name ||
            t("calls.participant");
      return [
        {
          call,
          chat,
          spaceName: space.name,
          participantNames: Object.values(call.participants)
            .filter((person) => person.ready === true)
            .map((person) => name(person.identity_id)),
          starterName: name(call.started_by),
        },
      ];
    })
    .sort(
      (left, right) =>
        right.call.started_at - left.call.started_at ||
        callKey(left.call).localeCompare(callKey(right.call)),
    );
}
