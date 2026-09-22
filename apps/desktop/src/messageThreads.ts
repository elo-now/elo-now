import { searchMessages, type Stream } from "./model";
export type MessageRow = Stream["rows"][number];
export type MessageThread = {
  rootId: string;
  root?: MessageRow;
  replies: MessageRow[];
  unreadCount: number;
  count?: number;
};
export function messageIdentity(row: MessageRow): string {
  return (
    row.body.deleted_record_id ??
    (row.body.kind === "unavailable"
      ? (row.body.locator?.message_record_id ?? row.id)
      : row.id)
  );
}
export function replyRoot(row: MessageRow): string | undefined {
  return ["chat.message", "unavailable", "deleted"].includes(row.body.kind)
    ? row.body.payload?.thread_root
    : undefined;
}
/** References are resolved only inside this verified chat; missing history stays visible. */
export function messageThreads(rows: MessageRow[]): Map<string, MessageThread> {
  const byId = new Map(rows.map((row) => [messageIdentity(row), row]));
  const threads = new Map<string, MessageThread>();
  for (const row of rows) {
    if (!replyRoot(row) && row.reply_count) {
      const id = messageIdentity(row);
      threads.set(id, {
        rootId: id,
        root: row,
        replies: [],
        unreadCount: 0,
        count: row.reply_count,
      });
    }
  }
  for (const row of rows) {
    const rootId = replyRoot(row);
    if (!rootId) continue;
    let thread = threads.get(rootId);
    if (!thread) {
      const candidate = byId.get(rootId);
      thread = {
        rootId,
        root: candidate && !replyRoot(candidate) ? candidate : undefined,
        replies: [],
        unreadCount: 0,
      };
      threads.set(rootId, thread);
    }
    thread.replies.push(row);
    if (row.unread) thread.unreadCount++;
  }
  return threads;
}
export function findThread(rows: MessageRow[], rootId: string): MessageThread {
  const existing = messageThreads(rows).get(rootId);
  if (existing) return existing;
  return {
    rootId,
    root: rows.find(
      (row) => messageIdentity(row) === rootId && !replyRoot(row),
    ),
    replies: [],
    unreadCount: 0,
  };
}
export type ChatTimelineEntry = {
  row: MessageRow;
  thread?: MessageThread;
  placeholder: boolean;
};
export function chatTimeline(
  rows: MessageRow[],
  query: string,
): ChatTimelineEntry[] {
  const threads = messageThreads(rows);
  if (query.trim())
    return searchMessages(rows, query).map((row) => ({
      row,
      thread: threads.get(replyRoot(row) ?? messageIdentity(row)),
      placeholder: false,
    }));
  return rows.flatMap<ChatTimelineEntry>((row) => {
    const rootId = replyRoot(row);
    if (!rootId)
      return [
        {
          row,
          thread: threads.get(messageIdentity(row)),
          placeholder: false,
        },
      ];
    const thread = threads.get(rootId)!;
    // One reachable summary for an orphan thread; never turn its preview into a read marker.
    return !thread.root && thread.replies[0].id === row.id
      ? [{ row, thread, placeholder: true }]
      : [];
  });
}
