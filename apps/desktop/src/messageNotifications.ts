import type { Stream, View } from "./model";
import type { StreamEntry } from "./streamFeed";
import { replyRoot } from "./messageThreads";

export type MessageLocation = { stream: string; thread?: string } | null;

/** The in-chat hint also applies to muted conversations. Arrival IDs come
 * from verified sync, never from an unread count or a history-page refresh. */
export function newMessageInChat(
  view: View,
  ids: string[],
  chat: Stream,
  thread?: string,
) {
  const received = new Set(ids);
  const current = view.streams.find(
    (item) =>
      item.space === chat.space &&
      item.stream === chat.stream &&
      item.space_context === chat.space_context,
  );
  return current?.rows
    .filter(
      (row) =>
        received.has(row.id) &&
        row.body.issuer_identity !== view.identity &&
        row.body.kind !== "chat.action" &&
        replyRoot(row) === thread,
    )
    .at(-1);
}

/** Only the native sync's newly verified IDs can trigger alerts. Old unread
 * records, Mark unread, reactions, pins and history imports cannot do so. */
export function incomingMessages(
  view: View,
  ids: string[],
  location: MessageLocation,
): StreamEntry[] {
  const received = new Set(ids);
  return (view.all_streams ?? view.streams)
    .filter((chat) => !chat.muted)
    .flatMap((chat: Stream) =>
      chat.rows
        .filter((row) => {
          if (
            !received.has(row.id) ||
            row.body.kind !== "chat.message" ||
            row.body.issuer_identity === view.identity ||
            !row.unread
          )
            return false;
          if (location?.stream !== chat.stream) return true;
          return (
            (row.body.payload?.thread_root ?? undefined) !== location?.thread
          );
        })
        .map((row) => ({
          key: `${chat.space}:${chat.stream}:${row.id}`,
          chat,
          row,
        })),
    );
}
