import type { Stream, View } from "./model";
import type { HistoryPage } from "./messageHistory";

export type StreamEntry = {
  key: string;
  chat: Stream;
  row: Stream["rows"][number];
  history?: HistoryPage;
};

/** A view of verified, locally available records; never change chat ordering. */
export function unreadStreamEntries(view: View): StreamEntry[] {
  const entries = view.streams
    .filter((chat) => !chat.muted)
    .flatMap((chat) =>
      chat.rows
        .filter(
          (row) =>
            row.unread &&
            (row.body.issuer_identity !== view.identity || row.marked_unread),
        )
        .map((row) => ({
          key: `${chat.space}:${chat.stream}:${row.id}`,
          chat,
          row,
        })),
    );
  const timestamp = (entry: StreamEntry) => {
    const value = Date.parse(entry.row.body.created_at ?? "");
    return Number.isFinite(value) ? value : 0;
  };
  return entries.sort((a, b) => {
    const time = timestamp(b) - timestamp(a);
    return time || (a.key < b.key ? -1 : a.key > b.key ? 1 : 0);
  });
}

export type SwipeDirection = "waiting" | "vertical" | "horizontal";
export function swipeDirection(dx: number, dy: number): SwipeDirection {
  if (Math.max(Math.abs(dx), Math.abs(dy)) < 10) return "waiting";
  return Math.abs(dx) > Math.abs(dy) * 1.3 ? "horizontal" : "vertical";
}

export function streamSwipe(dx: number, width: number) {
  const progress = Math.max(0, Math.min(1, dx / Math.min(220, width * 0.65)));
  return {
    progress,
    expand: progress >= 0.9,
    read: dx <= -Math.min(96, width * 0.28),
  };
}

/** Center a normal message; show the beginning of a message taller than the view. */
export function messageScrollTop(
  scrollTop: number,
  viewportTop: number,
  viewportHeight: number,
  messageTop: number,
  messageHeight: number,
): number {
  return Math.max(
    0,
    scrollTop +
      messageTop -
      viewportTop -
      Math.max(8, (viewportHeight - messageHeight) / 2),
  );
}
