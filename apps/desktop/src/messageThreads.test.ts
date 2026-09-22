import { describe, expect, it } from "vitest";
import {
  chatTimeline,
  findThread,
  messageThreads,
  replyRoot,
  type MessageRow,
} from "./messageThreads";
const row = (
  id: string,
  root?: string,
  unread = false,
  text = id,
): MessageRow => ({
  id,
  state: "ACCEPTED",
  unread,
  body: {
    kind: "chat.message",
    issuer_identity: "other",
    payload: { text, ...(root ? { thread_root: root } : {}) },
  },
});
describe("one-level message threads", () => {
  it("keeps main messages in signed order and groups reply counts without consuming their unread state", () => {
    const rows = [
      row("a"),
      row("b"),
      row("r1", "a", true),
      row("r2", "a"),
      row("r3", "b", true),
    ];
    const before = structuredClone(rows),
      result = chatTimeline(rows, "");
    expect(result.map((e) => e.row.id)).toEqual(["a", "b"]);
    expect(result[0].thread?.replies.map((r) => r.id)).toEqual(["r1", "r2"]);
    expect(result[0].thread?.unreadCount).toBe(1);
    expect(rows).toEqual(before);
  });
  it("keeps one visible placeholder when replies arrive before their root, then attaches without duplicating", () => {
    const replies = [row("r1", "root", true), row("r2", "root", true)];
    const missing = chatTimeline(replies, "");
    expect(missing).toHaveLength(1);
    expect(missing[0].placeholder).toBe(true);
    expect(missing[0].thread?.root).toBeUndefined();
    expect(missing[0].thread?.unreadCount).toBe(2);
    const loaded = chatTimeline([row("root"), ...replies], "");
    expect(loaded).toHaveLength(1);
    expect(loaded[0].placeholder).toBe(false);
    expect(loaded[0].thread?.replies).toEqual(replies);
  });
  it("searches replies without exposing unrelated records and resolves their original thread", () => {
    const rows = [
      row("root"),
      row("reply", "root", true, "found this"),
      row("unrelated"),
    ];
    const hits = chatTimeline(rows, "found");
    expect(hits.map((e) => e.row.id)).toEqual(["reply"]);
    expect(hits[0].thread?.rootId).toBe("root");
    expect(replyRoot(hits[0].row)).toBe("root");
    expect(findThread(rows, "root").replies).toHaveLength(1);
  });
  it("never follows references across chats or recursively treats a reply as another original", () => {
    const rows = [row("reply", "foreign", true), row("nested", "reply", true)];
    expect(messageThreads(rows).get("foreign")?.root).toBeUndefined();
    expect(messageThreads(rows).get("reply")?.root).toBeUndefined();
    expect(chatTimeline(rows, "").every((e) => e.placeholder)).toBe(true);
    expect(findThread([row("different")], "foreign").root).toBeUndefined();
  });
  it("supports attachment roots and a new thread before its first reply", () => {
    const file: MessageRow = {
      id: "file",
      state: "LOCAL",
      body: {
        kind: "file.shared",
        issuer_identity: "me",
        filename: "notes.pdf",
      },
    };
    expect(findThread([file], "file")).toEqual({
      rootId: "file",
      root: file,
      replies: [],
      unreadCount: 0,
    });
    expect(messageThreads([file, row("r", "file")]).get("file")?.root).toBe(
      file,
    );
  });
  it("uses an unavailable locator's original message id to preserve its thread position", () => {
    const unavailable: MessageRow = {
      id: "locator",
      state: "ACCEPTED",
      reply_count: 1,
      body: {
        kind: "unavailable",
        issuer_identity: "other",
        payload: { text: "" },
        locator: {
          message_record_id: "root",
          body_object_id: "body",
          locator_nonce: "nonce",
        },
      },
    };
    const reply = row("reply", "root");
    const timeline = chatTimeline([unavailable, reply], "");
    expect(timeline.map((entry) => entry.row.id)).toEqual(["locator"]);
    expect(timeline[0].thread?.root).toBe(unavailable);
    expect(timeline[0].thread?.rootId).toBe("root");
    expect(timeline[0].thread?.replies).toEqual([reply]);
  });
});
