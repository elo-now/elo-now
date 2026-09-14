import { describe, expect, it } from "vitest";
import {
  unreadStreamEntries,
  streamSwipe,
  swipeDirection,
  messageScrollTop,
} from "./streamFeed";
import { markVisibleMessagesRead, type Stream, type View } from "./model";
const row = (
  id: string,
  date?: string,
  extra: Partial<Stream["rows"][number]> = {},
): Stream["rows"][number] => ({
  id,
  unread: true,
  state: "ACCEPTED",
  body: {
    kind: "chat.message",
    issuer_identity: "other",
    created_at: date,
    payload: { text: id },
  },
  ...extra,
});
const chat = (stream: string, rows: Stream["rows"]): Stream => ({
  name: stream,
  space: "space",
  stream,
  head: "head",
  controller: "device",
  recovery: null,
  forked: false,
  can_post: true,
  owners: [],
  members: [],
  rows,
  unread_count: rows.filter((row) => row.unread).length,
});
const view = (streams: Stream[]): View => ({
  identity: "me",
  credential: "device",
  streams,
  replicas: [],
  counts: { pending: 0, held: 0, stored: 0, rejected: 0, repair_pending: 0 },
  inbox: {},
  history_warning: "",
  alpha_ready: false,
});
describe("Messages Stream", () => {
  it("hides muted chats including existing unreads, replies, files and manual markers without marking them read", () => {
    const source = view([
      {
        ...chat("muted", [
          row("old", "2026-09-09T12:00:00Z"),
          row("reply", undefined, {
            body: {
              kind: "chat.message",
              issuer_identity: "other",
              payload: { text: "Reply", thread_root: "old" },
            },
          }),
          row("file", undefined, {
            body: {
              kind: "file.manifest",
              issuer_identity: "other",
              filename: "file.txt",
            },
          }),
          row("own", undefined, {
            marked_unread: true,
            body: { kind: "chat.message", issuer_identity: "me" },
          }),
        ]),
        muted: true,
      },
      chat("visible", [row("visible")]),
    ]);
    const before = structuredClone(source);
    expect(unreadStreamEntries(source).map((e) => e.row.id)).toEqual([
      "visible",
    ]);
    expect(source).toEqual(before);
    expect(source.streams[0].unread_count).toBe(4);
    // New arrivals also stay out of Buzz until the user unmutes the chat.
    source.streams[0].rows.push(row("new", "2026-09-12T12:00:00Z"));
    expect(unreadStreamEntries(source)).toHaveLength(1);
    source.streams[0].muted = false;
    expect(unreadStreamEntries(source)).toHaveLength(6);
    expect(unreadStreamEntries(source)[0].row.id).toBe("new");
  });
  it("combines every chat and DM, ignores own/read records and does not mutate signed chat order", () => {
    const source = view([
      chat("a", [
        row("new", "2026-09-10T12:00:00Z"),
        row("old", "2026-09-09T12:00:00Z"),
        row("seen", undefined, { unread: false }),
      ]),
      {
        ...chat("b", [
          row("dm", "2026-09-10T13:00:00Z"),
          row("own", undefined, {
            body: { kind: "chat.message", issuer_identity: "me" },
          }),
        ]),
        chat_kind: "direct",
      },
    ]);
    const before = structuredClone(source);
    expect(unreadStreamEntries(source).map((entry) => entry.row.id)).toEqual([
      "dm",
      "new",
      "old",
    ]);
    expect(source).toEqual(before);
  });
  it("keeps late older records, deterministic ties, missing dates and file previews", () => {
    const source = view([
      chat("z", [
        row("equal", "2026-09-10T12:00:00Z"),
        row("late", "2026-09-01T12:00:00Z"),
      ]),
      chat("a", [
        row("equal", "2026-09-10T12:00:00Z"),
        row("bad-date", "invalid"),
        row("file", undefined, {
          body: {
            kind: "file.manifest",
            issuer_identity: "other",
            filename: "notes.pdf",
          },
        }),
      ]),
    ]);
    expect(unreadStreamEntries(source).map((entry) => entry.key)).toEqual([
      "space:a:equal",
      "space:z:equal",
      "space:z:late",
      "space:a:bad-date",
      "space:a:file",
    ]);
  });
  it("removes only an explicitly read record; unrelated chats and offscreen records stay unread", () => {
    const source = view([
      chat("a", [row("one"), row("two")]),
      chat("b", [row("one")]),
    ]);
    const selected = unreadStreamEntries(source).find(
      (entry) => entry.key === "space:a:one",
    )!;
    const updated = view(
      source.streams.map((candidate) =>
        candidate.stream === selected.chat.stream
          ? markVisibleMessagesRead(candidate, [selected.row.id])
          : candidate,
      ),
    );
    expect(unreadStreamEntries(updated).map((entry) => entry.key)).toEqual([
      "space:a:two",
      "space:b:one",
    ]);
    expect(updated.streams.map((chat) => chat.unread_count)).toEqual([1, 1]);
    expect(unreadStreamEntries(source)).toHaveLength(3);
  });
  it("does not acquire vertical/diagonal scrolls or taps as a message swipe", () => {
    expect(swipeDirection(4, 2)).toBe("waiting");
    expect(swipeDirection(18, 40)).toBe("vertical");
    expect(swipeDirection(-35, 30)).toBe("vertical");
    expect(swipeDirection(-70, 12)).toBe("horizontal");
    expect(streamSwipe(-15, 360).read).toBe(false);
    expect(streamSwipe(-110, 360).read).toBe(true);
    expect(streamSwipe(-110, 360).expand).toBe(false);
    expect(streamSwipe(190, 360).expand).toBe(false);
    expect(streamSwipe(200, 360).expand).toBe(true);
    expect(streamSwipe(200, 360).read).toBe(false);
  });
  it("positions Open at its record, including records older than the visible history and very long messages", () => {
    expect(messageScrollTop(800, 100, 600, -300, 100)).toBe(150);
    expect(messageScrollTop(0, 100, 600, 1000, 900)).toBe(892);
    expect(messageScrollTop(0, 100, 600, 110, 100)).toBe(0);
  });
});

it("includes an own message only when explicitly marked unread, and Read removes it", () => {
  const own = row("remember", "2026-09-11T12:00:00Z", {
    marked_unread: true,
    body: {
      kind: "chat.message",
      issuer_identity: "me",
      payload: { text: "Remember this" },
    },
  });
  const source = view([chat("a", [own])]);
  expect(unreadStreamEntries(source).map((entry) => entry.row.id)).toEqual([
    "remember",
  ]);
  source.streams[0] = markVisibleMessagesRead(source.streams[0], ["remember"]);
  expect(unreadStreamEntries(source)).toHaveLength(0);
});
