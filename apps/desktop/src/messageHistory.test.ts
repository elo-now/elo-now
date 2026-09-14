import { expect, test } from "vitest";
import type { Stream, View } from "./model";
import {
  mergeHistory,
  sameHistoryScope,
  type HistoryPage,
} from "./messageHistory";
import { acceptView } from "./liveSync";
import { chatTimeline } from "./messageThreads";
const row = (id: string, time: number): Stream["rows"][number] => ({
  id,
  state: "LOCAL",
  body: {
    kind: "chat.message",
    issuer_identity: "me",
    logical_time: time,
    issuer_credential: "device",
    payload: { text: id },
  },
});
test("overlapping history pages keep canonical order and update the existing record", () => {
  const existing = [row("b", 2), row("c", 3)];
  const merged = mergeHistory(existing, [
    row("a", 1),
    { ...row("b", 2), state: "STORED", pinned: true },
  ]);
  expect(merged.map((row) => row.id)).toEqual(["a", "b", "c"]);
  expect(merged[1].state).toBe("STORED");
  expect(merged[1].pinned).toBe(true);
  expect(existing[0].state).toBe("LOCAL");
});
test("late history responses cannot cross profile, Space, or conversation boundaries", () => {
  const page = {
    identity: "me",
    space_context: "company-a",
    space: "a",
    stream: "chat",
  } as HistoryPage;
  expect(sameHistoryScope(page, "me", "company-a", "a", "chat")).toBe(true);
  expect(sameHistoryScope(page, "other", "company-a", "a", "chat")).toBe(false);
  expect(sameHistoryScope(page, "me", "company-b", "a", "chat")).toBe(false);
  expect(sameHistoryScope(page, "me", "company-a", "b", "chat")).toBe(false);
  expect(sameHistoryScope(page, "me", "company-a", "a", "other")).toBe(false);
});
test("a scoped send updates its chat while retaining other chats and Space activity", () => {
  const a = {
    space_context: "company-a",
    space: "a",
    stream: "one",
    rows: [row("1", 1)],
  } as Stream;
  const b = {
    space_context: "company-a",
    space: "a",
    stream: "two",
    rows: [row("2", 2)],
  } as Stream;
  const c = {
    space_context: "company-b",
    space: "b",
    stream: "three",
    rows: [row("3", 3)],
  } as Stream;
  const current = {
    identity: "me",
    revision: 3,
    active_space: "company-a",
    streams: [a, b],
    all_streams: [a, b, c],
    all_invitations: { actionable: 1, notifications: 2 },
  } as View;
  const updated = { ...a, rows: [row("4", 4)] };
  const patch = {
    ...current,
    partial: true,
    revision: 4,
    streams: [updated],
    all_streams: [updated],
  } as View;
  const result = acceptView(current, patch)!;
  expect(result.streams).toEqual([updated, b]);
  expect(result.all_streams).toEqual([updated, b, c]);
  expect(result.all_invitations).toBe(current.all_invitations);
  expect(acceptView(current, { ...patch, revision: 2 })).toBe(current);
  expect(acceptView(current, { ...patch, active_space: "company-b" })).toBe(
    current,
  );
});
test("a paged root retains its reply link before reply bodies are loaded", () => {
  const root = { ...row("root", 1), reply_count: 4 };
  const timeline = chatTimeline([root], "");
  expect(timeline).toHaveLength(1);
  expect(timeline[0].thread?.count).toBe(4);
  expect(timeline[0].thread?.root?.id).toBe("root");
});
