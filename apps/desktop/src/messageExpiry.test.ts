import { expect, test } from "vitest";
import { expireMessageRows, expireView } from "./messageExpiry";
import { searchMessages, type View } from "./model";
import type { MessageRow } from "./messageThreads";

const row: MessageRow = {
  id: "signed-record",
  state: "STORED",
  unread: true,
  pinned: true,
  body: {
    kind: "chat.message",
    issuer_identity: "sender",
    created_at: "2026-09-30T10:00:00Z",
    payload: {
      text: "private expiring text",
      thread_root: "thread",
      expires_at_ms: 10_000,
    },
  },
};

test("expiry removes text, pins and unread state at the deadline but preserves timeline and replies", () => {
  const rows = [row];
  expect(expireMessageRows(rows, 9_999)).toBe(rows);
  const result = expireMessageRows(rows, 10_000);
  expect(result[0].body).toEqual({
    kind: "deleted",
    expired: true,
    issuer_identity: "sender",
    issuer_credential: undefined,
    created_at: row.body.created_at,
    logical_time: undefined,
    deleted_record_id: "signed-record",
    payload: { thread_root: "thread" },
  });
  expect(result[0].unread).toBe(false);
  expect(result[0].pinned).toBe(false);
  expect(searchMessages(result, "private")).toEqual([]);
  expect(row.body.payload?.text).toBe("private expiring text");
});

test("ordinary messages keep their content and reconnecting cannot restore expired text", () => {
  const ordinary = {
    ...row,
    body: { ...row.body, payload: { text: "keep this" } },
  };
  expect(expireMessageRows([ordinary], 99_999)[0]).toBe(ordinary);
  const once = expireMessageRows([row], 10_000);
  expect(expireMessageRows(once, 99_999)).toBe(once);
  expect(expireMessageRows([row], 99_999)[0].body.expired).toBe(true);
});

test("Buzz and unread summaries lose expired messages across Spaces", () => {
  const view = {
    streams: [{ rows: [row], unread_count: 3 }],
    all_streams: [{ rows: [row], unread_count: 1 }],
  } as View;
  const result = expireView(view, 10_000)!;
  expect(result.streams[0].unread_count).toBe(2);
  expect(result.all_streams![0].unread_count).toBe(0);
  expect(result.all_streams![0].rows[0].body.payload?.text).toBeUndefined();
  expect(expireView(view, 9_999)).toBe(view);
});
