import { expect, test } from "vitest";
import { expireMessageRows, expireView } from "./messageExpiry";
import { searchMessages, type View } from "./model";
import type { MessageRow } from "./messageThreads";
import { MAX_TIMESTAMP_MS } from "./timestamps";

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

test("invalid cached deadlines neither delete content nor interfere with another message expiring", () => {
  for (const expires of [
    MAX_TIMESTAMP_MS + 1,
    Number.MAX_SAFE_INTEGER,
    Infinity,
    NaN,
    -1,
    0,
    1.5,
  ]) {
    const invalid = {
      ...row,
      body: {
        ...row.body,
        payload: { ...row.body.payload, expires_at_ms: expires },
      },
    };
    const result = expireMessageRows([invalid, row], 10_000);
    expect(result[0]).toBe(invalid);
    expect(result[1].body.expired).toBe(true);
  }
});

test("an expired parent leaves replies readable until each reply's own deadline", () => {
  const root = {
    ...row,
    id: "root",
    body: { ...row.body, payload: { text: "Root", expires_at_ms: 10_000 } },
  };
  const reply = {
    ...row,
    id: "reply",
    body: {
      ...row.body,
      payload: { text: "Reply", thread_root: "root", expires_at_ms: 20_000 },
    },
  };
  const permanent = {
    ...reply,
    id: "permanent",
    body: {
      ...reply.body,
      payload: { text: "Keep this reply", thread_root: "root" },
    },
  };
  const expired = expireMessageRows([root, reply, permanent], 10_000);
  expect(expired[0].body.expired).toBe(true);
  expect(expired[1]).toBe(reply);
  expect(expired[2]).toBe(permanent);
  const later = expireMessageRows(expired, 20_000);
  expect(later[1].body.expired).toBe(true);
  expect(later[2]).toBe(permanent);
  expect(reply.body.payload.text).toBe("Reply");
});

test("changing, cancelling, deleting or missing a parent does not change a reply deadline", () => {
  const reply = {
    ...row,
    body: {
      ...row.body,
      payload: { text: "Reply", thread_root: "root", expires_at_ms: 20_000 },
    },
  };
  const roots: MessageRow[] = [
    {
      ...row,
      id: "root",
      body: { ...row.body, payload: { text: "Root", expires_at_ms: 50_000 } },
    },
    {
      ...row,
      id: "root",
      body: { ...row.body, payload: { text: "Root", expires_at_ms: null } },
    },
    {
      ...row,
      id: "root",
      body: { ...row.body, kind: "deleted", expired: true, payload: undefined },
    },
  ];
  for (const context of [[], ...roots.map((root) => [root])]) {
    const rows = [...context, reply];
    expect(expireMessageRows(rows, 19_999).at(-1)).toBe(reply);
    expect(expireMessageRows(rows, 20_000).at(-1)?.body.expired).toBe(true);
  }
});
