import type { MessageRow } from "./messageThreads";
import type { View, Stream } from "./model";

export type MessageExpiryHours = 1 | 12 | 24;

export function expireMessageRows(
  rows: MessageRow[],
  now: number,
): MessageRow[] {
  let changed = false;
  const result = rows.map((row) => {
    const deadline = row.body.payload?.expires_at_ms;
    if (row.body.kind === "deleted" || deadline == null || deadline > now)
      return row;
    changed = true;
    return {
      ...row,
      unread: false,
      marked_unread: false,
      pinned: false,
      reactions: [],
      body: {
        kind: "deleted",
        expired: true,
        issuer_identity: row.body.issuer_identity,
        issuer_credential: row.body.issuer_credential,
        created_at: row.body.created_at,
        logical_time: row.body.logical_time,
        deleted_record_id: row.body.locator?.message_record_id ?? row.id,
        payload: { thread_root: row.body.payload?.thread_root },
      },
    };
  });
  return changed ? result : rows;
}

export function expireView(view: View | null, now: number): View | null {
  if (!view) return view;
  let changed = false;
  const update = (stream: Stream): Stream => {
    const rows = expireMessageRows(stream.rows, now);
    if (rows === stream.rows) return stream;
    changed = true;
    const removedUnread = stream.rows.filter(
      (row, i) => row.unread && !rows[i].unread,
    ).length;
    return {
      ...stream,
      rows,
      unread_count: Math.max(0, (stream.unread_count ?? 0) - removedUnread),
    };
  };
  const streams = view.streams.map(update);
  const all_streams = view.all_streams?.map(update);
  return changed ? { ...view, streams, all_streams } : view;
}
