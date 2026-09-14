import { describe, expect, it } from "vitest";
import { directName, findPeople, knownPeople } from "./directMessages";
import type { Stream, View } from "./model";

const member = (id: string, type = "HUMAN") => ({
  identity_id: id,
  identity_type: type,
  credential_ids: [id + "-device"],
  capabilities: ["READ", "POST"],
  external: false,
});
const chat = (
  name: string,
  others: string[],
  extra: Partial<Stream> = {},
): Stream => ({
  name,
  space: "space",
  stream: name,
  head: "head",
  controller: "me-device",
  recovery: null,
  forked: false,
  can_post: true,
  owners: [],
  members: [member("me"), ...others.map((id) => member(id))],
  rows: [],
  ...extra,
});
const view = (streams: Stream[]): View => ({
  identity: "me",
  credential: "me-device",
  name: "Alex",
  streams,
  replicas: [],
  counts: { pending: 0, stored: 0, held: 0, rejected: 0, repair_pending: 0 },
  inbox: {},
  history_warning: "",
  alpha_ready: false,
});

describe("DM people", () => {
  it("includes saved contacts without a shared chat and merges memberships by identity", () => {
    const data = {
      ...view([chat("Team", ["maya"], { member_names: { maya: "Maya" } })]),
      contacts: [
        { id: "maya", name: "Maya" },
        { id: "sam", name: "Sam" },
        { id: "me", name: "Me" },
      ],
    };
    const people = knownPeople(data);
    expect(people.map((p) => p.id)).toEqual(["maya", "sam"]);
    expect(people[0].chats).toEqual(["Team"]);
    expect(people[1].chats).toEqual([]);
    expect(findPeople(people, " sAm ").map((p) => p.id)).toEqual(["sam"]);
  });
  it("deduplicates known people by identity while retaining shared chat context", () => {
    const people = knownPeople(
      view([
        chat("Design", ["maya"], { member_names: { maya: "Maya" } }),
        chat("Weekend", ["maya", "sam"], { member_names: { sam: "Sam" } }),
      ]),
    );
    expect(people.map((p) => p.id)).toEqual(["maya", "sam"]);
    expect(people[0].chats).toEqual(["Design", "Weekend"]);
    expect(people[0].name).toBe("Maya");
    expect(findPeople(people, " WEEKEND ")).toHaveLength(2);
    expect(findPeople(people, "aya").map((p) => p.id)).toEqual(["maya"]);
  });
  it("excludes own, nonhuman, removed, inaccessible and conflicting memberships", () => {
    const data = view([
      chat("Good", ["maya"], {
        members: [member("me"), member("maya"), member("bot", "SERVICE")],
      }),
      chat("Forked", ["sam"], { forked: true }),
      chat("Removed", ["removed"], { members: [member("removed")] }),
      chat("Old device", ["old"], {
        members: [
          { ...member("me"), credential_ids: ["retired"] },
          member("old"),
        ],
      }),
    ]);
    expect(knownPeople(data).map((p) => p.id)).toEqual(["maya"]);
  });
  it("keeps two people with the same display name distinct", () => {
    const people = knownPeople(
      view([
        chat("Team", ["one", "two"], {
          member_names: { one: "Sam", two: "Sam" },
        }),
      ]),
    );
    expect(people.map((p) => p.id)).toEqual(["one", "two"]);
  });
  it("uses the other person for a one-to-one title and bounds Unicode names", () => {
    const data = view([]);
    expect(
      directName(data, [
        { id: "maya", name: "Maya", initials: "M", chats: [] },
      ]),
    ).toBe("Maya");
    const text = directName(data, [
      { id: "maya", name: "🌸".repeat(100), initials: "M", chats: [] },
    ]);
    expect(new TextEncoder().encode(text).length).toBeLessThanOrEqual(120);
    expect(text.startsWith("🌸")).toBe(true);
    expect(
      directName(data, [
        { id: "m", name: "Maya", initials: "M", chats: [] },
        { id: "s", name: "Sam", initials: "S", chats: [] },
      ]),
    ).toBe("Alex, Maya, Sam");
    expect(text.endsWith("…")).toBe(true);
    expect(text.includes("�")).toBe(false);
  });
});
