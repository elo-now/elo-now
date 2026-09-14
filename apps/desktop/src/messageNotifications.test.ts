import { expect, test } from "vitest";
import type { Stream, View } from "./model";
import { incomingMessages, newMessageInChat } from "./messageNotifications";

const row = (
  id: string,
  extra: Partial<Stream["rows"][number]> = {},
): Stream["rows"][number] => ({
  id,
  state: "ACCEPTED",
  unread: true,
  body: {
    kind: "chat.message",
    issuer_identity: "other",
    payload: { text: id },
  },
  ...extra,
});
const source = {
  identity: "me",
  streams: [
    {
      stream: "a",
      space: "s",
      rows: [
        row("new"),
        row("old"),
        row("read", { unread: false }),
        row("own", { body: { kind: "chat.message", issuer_identity: "me" } }),
        row("pin", { body: { kind: "chat.action", issuer_identity: "other" } }),
        row("reply", {
          body: {
            kind: "chat.message",
            issuer_identity: "other",
            payload: { text: "reply", thread_root: "old" },
          },
        }),
      ],
    },
  ],
} as View;
test("in-chat arrival hints include muted chats but exclude other scopes, own sends, reactions and unrelated threads", () => {
  const chat = { ...source.streams[0], muted: true, space_context: "company" };
  const view = { ...source, streams: [chat] };
  const ids = ["new", "own", "pin", "reply"];
  expect(newMessageInChat(view, ids, chat)?.id).toBe("new");
  expect(newMessageInChat(view, ids, chat, "old")?.id).toBe("reply");
  expect(newMessageInChat(view, [], chat)).toBeUndefined();
  expect(newMessageInChat(view, ["own", "pin"], chat)).toBeUndefined();
  for (const change of [
    { space_context: "other" },
    { space: "other" },
    { stream: "other" },
  ])
    expect(newMessageInChat(view, ids, { ...chat, ...change })).toBeUndefined();
});
test("only newly admitted unread messages notify; own messages, old history and actions do not", () => {
  expect(
    incomingMessages(
      source,
      ["new", "read", "own", "pin", "missing"],
      null,
    ).map((e) => e.row.id),
  ).toEqual(["new"]);
  expect(incomingMessages(source, [], null)).toEqual([]);
});
test("the open conversation stays quiet while a different thread can notify", () => {
  expect(
    incomingMessages(source, ["new", "reply"], { stream: "a" }).map(
      (e) => e.row.id,
    ),
  ).toEqual(["reply"]);
  expect(
    incomingMessages(source, ["new", "reply"], {
      stream: "a",
      thread: "old",
    }).map((e) => e.row.id),
  ).toEqual(["new"]);
  expect(
    incomingMessages(source, ["new", "reply"], { stream: "b" }).length,
  ).toBe(2);
});
test("late older messages still notify and notification lookup does not mark anything read", () => {
  const snapshot = structuredClone(source);
  expect(incomingMessages(source, ["old"], null)[0].key).toBe("s:a:old");
  expect(source).toEqual(snapshot);
});

test("muted conversations suppress new messages and replies without losing unread state", () => {
  const muted = structuredClone(source);
  muted.streams[0].muted = true;
  muted.streams.push({
    ...source.streams[0],
    stream: "b",
    rows: [row("other-chat")],
  });
  const before = structuredClone(muted);
  expect(
    incomingMessages(muted, ["new", "reply", "other-chat"], null).map(
      (e) => e.row.id,
    ),
  ).toEqual(["other-chat"]);
  expect(muted).toEqual(before);
  muted.streams[0].muted = false;
  // Unmuting alone cannot replay alerts for older unread records.
  expect(incomingMessages(muted, [], null)).toEqual([]);
  expect(
    incomingMessages(muted, ["new", "reply"], null).map((e) => e.row.id),
  ).toEqual(["new", "reply"]);
});
