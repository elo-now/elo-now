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

test("an open chat suppresses only its full scope while identical stream IDs in other Spaces still notify", () => {
  const current = {
    ...source.streams[0],
    space_context: "work",
    rows: [row("current")],
  };
  const otherHost = {
    ...current,
    space_context: "friends",
    rows: [row("other-host")],
  };
  const otherSpace = {
    ...current,
    space: "another-space",
    rows: [row("other-space")],
  };
  const view = {
    ...source,
    active_space: "work",
    streams: [current],
    all_streams: [current, otherHost, otherSpace],
  };
  const location = {
    space: current.space,
    stream: current.stream,
    space_context: "work",
  };
  const ids = ["current", "other-host", "other-space"];
  expect(
    incomingMessages(view, ids, location).map((entry) => entry.row.id),
  ).toEqual(["other-host", "other-space"]);
  // The active Space is the normalized context when its summary omits it.
  expect(
    incomingMessages(view, ids, { ...location, space_context: undefined }).map(
      (entry) => entry.row.id,
    ),
  ).toEqual(["other-host", "other-space"]);
  current.space_context = undefined as never;
  expect(
    incomingMessages(view, ids, location).map((entry) => entry.row.id),
  ).toEqual(["other-host", "other-space"]);
});
