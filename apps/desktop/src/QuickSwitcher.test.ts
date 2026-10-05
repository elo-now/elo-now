import { expect, test } from "vitest";
import { switchableChats } from "./QuickSwitcher";
import type { Stream, View } from "./model";

const chat = (name: string, context: string, read = true): Stream =>
  ({
    name,
    space_context: context,
    space: "same-space",
    stream: "same-stream",
    forked: false,
    rows: [],
    members: [{ identity_id: "me", capabilities: read ? ["READ"] : ["POST"] }],
  }) as unknown as Stream;
const view = {
  identity: "me",
  active_space: "a",
  streams: [],
  spaces: [
    { id: "a", name: "Studio", status: "joined" },
    { id: "b", name: "Home", status: "joined" },
    { id: "c", name: "Pending", status: "pending" },
  ],
  all_streams: [
    chat("General", "a"),
    chat("General", "a"),
    chat("General", "b"),
    chat("Hidden", "c"),
    chat("Unreadable", "a", false),
    { ...chat("Forked", "a"), forked: true },
  ],
} as unknown as View;

test("switcher keeps full hosting context and includes only readable joined conversations", () => {
  expect(switchableChats(view).map((chat) => chat.space_context)).toEqual([
    "a",
    "b",
  ]);
  expect(
    switchableChats(view, "  GENERAL home ").map((chat) => chat.space_context),
  ).toEqual(["b"]);
  expect(switchableChats(view, "missing")).toEqual([]);
});
test("a different unlocked identity cannot reuse the previous profile's switcher entries", () => {
  expect(switchableChats({ ...view, identity: "other" })).toEqual([]);
});
