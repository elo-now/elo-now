import { searchMessages, type Stream } from "./model";
export type MessageRow = Stream["rows"][number];
export type MessageThread = {
  rootId: string;
  root?: MessageRow;
  replies: MessageRow[];
  unreadCount: number;
  count?: number;
};
export function replyRoot(row: MessageRow): string | undefined {
  return row.body.kind === "chat.message"
    ? row.body.payload?.thread_root
    : undefined;
}
/** References are resolved only inside this verified chat; missing history stays visible. */
export function messageThreads(rows: MessageRow[]): Map<string, MessageThread> {
  const byId = new Map(rows.map((row) => [row.id, row]));
  const threads = new Map<string, MessageThread>();
  for (const row of rows) {
    if (!replyRoot(row) && row.reply_count)
      threads.set(row.id, {
        rootId: row.id,
        root: row,
        replies: [],
        unreadCount: 0,
        count: row.reply_count,
      });
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
    root: rows.find((row) => row.id === rootId && !replyRoot(row)),
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
      thread: threads.get(replyRoot(row) ?? row.id),
      placeholder: false,
    }));
  return rows.flatMap<ChatTimelineEntry>((row) => {
    const rootId = replyRoot(row);
    if (!rootId)
      return [{ row, thread: threads.get(row.id), placeholder: false }];
    const thread = threads.get(rootId)!;
    // One reachable summary for an orphan thread; never turn its preview into a read marker.
    return !thread.root && thread.replies[0].id === row.id
      ? [{ row, thread, placeholder: true }]
      : [];
  });
}
