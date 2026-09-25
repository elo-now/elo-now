import { describe, it, expect } from "vitest";
import {
  beginsNewMessageSection,
  isNewMessage,
  markVisibleMessagesRead,
  searchMessages,
  senderName,
  senderInitials,
  statusText,
  recordTimestamp,
  visibleMembers,
  invitationCount,
  notificationCount,
  type Stream,
  type View,
} from "./model";
describe("Signed record timestamps", () => {
  it("omits fractional seconds without rounding into the next day", () => {
    expect(recordTimestamp(new Date("2026-09-11T23:59:59.999Z"))).toBe(
      "2026-09-11T23:59:59Z",
    );
  });
  it("normalizes device timezone offsets to UTC", () => {
    expect(recordTimestamp(new Date("2026-09-11T00:30:00.123+02:00"))).toBe(
      "2026-09-10T22:30:00Z",
    );
  });
});
describe("Sender names", () => {
  it("keeps the locally saved contact name ahead of sender-controlled names", () => {
    const view = { identity: "me", contacts: [{ id: "peer", name: "Trusted contact" }] } as unknown as View;
    const stream = { member_names: { peer: "Administrator" } } as unknown as Stream;
    expect(senderName(view, "peer", stream)).toBe("Trusted contact");
  });
  it("uses your current name and verified names scoped to the current chat", () => {
    const view = {
      identity: "alex",
      name: "Alex River",
      demo_names: { maya: "Old demo name" },
    } as unknown as View;
    const stream = {
      member_names: { maya: "Maya Rose", alex: "Old Alex" },
    } as unknown as Stream;
    expect(senderName(view, "alex", stream)).toBe("Alex River");
    expect(senderInitials(view, "alex", stream)).toBe("AR");
    expect(senderName(view, "maya", stream)).toBe("Maya Rose");
    expect(senderInitials(view, "maya", stream)).toBe("MR");
    expect(senderName(view, "maya")).toBe("Old demo name");
    expect(senderName({ ...view, demo_names: undefined }, "maya")).toBe(
      "maya…",
    );
    expect(senderName({ ...view, name: undefined }, "alex")).toBe("You");
  });
});
describe("claims of delivery", () => {
  it("distinguishes local durability, Replica storage and local verification", () => {
    const labels = ["LOCAL", "STORED", "ACCEPTED"].map(statusText);
    expect(new Set(labels).size).toBe(3);
    for (const l of labels)
      expect(l).not.toMatch(/delivered|read receipt|read by/i);
  });
  it("keeps security holds visible", () => {
    expect(statusText("HELD_STALE_CONFIG")).toMatch(/On hold/);
    expect(statusText("QUARANTINED_STALE")).toMatch(/Quarantined/);
    expect(statusText("WAITING_FOR_PROOF")).toMatch(/proof/);
    expect(statusText("REPAIR_PENDING")).toMatch(/copy missing/);
    expect(statusText("REPAIR_PENDING")).not.toBe(statusText("STORED"));
  });
});

describe("Unread presentation", () => {
  const row = (id: string, unread: boolean): Stream["rows"][number] => ({
    id,
    unread,
    state: "ACCEPTED",
    body: { kind: "chat.message", issuer_identity: "someone" },
  });
  it("starts one marker at the oldest unread message, including a late arrival", () => {
    const rows = [
      row("seen-before", false),
      row("late", true),
      row("seen-after", false),
      row("latest", true),
    ];
    const session = new Set<string>();
    expect(
      rows.map((_, index) => beginsNewMessageSection(rows, index, session)),
    ).toEqual([false, true, false, false]);
    session.add("late");
    expect(isNewMessage(rows, 1, session)).toBe(true);
  });
  it("marks only records reported as visible and keeps offscreen messages unread", () => {
    const stream = {
      rows: [row("above", true), row("visible", true), row("below", true)],
      unread_count: 3,
    } as Stream;
    const updated = markVisibleMessagesRead(stream, ["visible"]);
    expect(updated.rows.map(({ id, unread }) => [id, unread])).toEqual([
      ["above", true],
      ["visible", false],
      ["below", true],
    ]);
    expect(updated.unread_count).toBe(2);
  });
});

describe("Member search", () => {
  const members = ["zoe", "me", "bea"].map((identity_id) => ({
    identity_id,
    external: false,
    capabilities: ["READ"],
    credential_ids: [identity_id + "-phone", identity_id + "-desktop"],
  }));
  const stream: Stream = {
    name: "Team",
    space: "space",
    stream: "team",
    head: "head",
    controller: "device",
    recovery: null,
    forked: false,
    can_post: true,
    owners: [{ identity_id: "me" }],
    members,
    rows: [],
  };
  const view: View = {
    identity: "me",
    credential: "device",
    demo_names: { me: "Ada", zoe: "Zoe", bea: "Bea" },
    streams: [stream],
    replicas: [],
    counts: { pending: 0, stored: 0, held: 0, rejected: 0, repair_pending: 0 },
    inbox: {},
    history_warning: "",
    alpha_ready: false,
  };
  it("lists each identity once, puts the current user first and preserves signed member order", () => {
    const before = structuredClone(stream);
    expect(visibleMembers(view, stream, "").map((m) => m.identity_id)).toEqual([
      "me",
      "bea",
      "zoe",
    ]);
    expect(stream).toEqual(before);
  });
  it("finds names, the current user's name, and full identities without case or whitespace surprises", () => {
    expect(
      visibleMembers(view, stream, " aDA ").map((m) => m.identity_id),
    ).toEqual(["me"]);
    expect(
      visibleMembers(view, stream, "BEA").map((m) => m.identity_id),
    ).toEqual(["bea"]);
    expect(
      visibleMembers({ ...view, demo_names: undefined }, stream, "zoe").map(
        (m) => m.identity_id,
      ),
    ).toEqual(["zoe"]);
    expect(visibleMembers(view, stream, "nobody")).toEqual([]);
  });
});

describe("Message search", () => {
  it("filters local text without changing canonical order, record identity or unread state", () => {
    const rows: Stream["rows"] = [
      {
        id: "late",
        state: "ACCEPTED",
        unread: true,
        body: {
          kind: "chat.message",
          issuer_identity: "maya",
          created_at: "2026-09-08T10:00:00Z",
          payload: { text: "Music for tomorrow" },
        },
      },
      {
        id: "other",
        state: "LOCAL",
        unread: true,
        body: {
          kind: "chat.message",
          issuer_identity: "alex",
          payload: { text: "Dinner at seven" },
        },
      },
      {
        id: "file",
        state: "STORED",
        unread: true,
        body: {
          kind: "file.manifest",
          issuer_identity: "maya",
          filename: "Music.pdf",
        },
      },
      {
        id: "last",
        state: "LOCAL",
        body: {
          kind: "chat.message",
          issuer_identity: "alex",
          payload: { text: "More MUSIC" },
        },
      },
    ];
    const before = structuredClone(rows);
    const matches = searchMessages(rows, "  mUsIc  ");
    expect(matches.map((row) => row.id)).toEqual(["late", "last"]);
    expect(matches[0]).toBe(rows[0]);
    expect(searchMessages(rows, " ")).toBe(rows);
    expect(searchMessages(rows, "no matches")).toEqual([]);
    expect(rows).toEqual(before);
    const updated = markVisibleMessagesRead(
      { rows, unread_count: 3 } as Stream,
      [matches[0].id],
    );
    expect(
      updated.rows.filter((row) => row.unread).map((row) => row.id),
    ).toEqual(["other", "file"]);
  });
});

describe("More indicators", () => {
  it("keeps pending invitations separate from unread notifications", () => {
    const view = {
      invitations: {
        enabled: true,
        pending: 2,
        responses: 4,
        actionable: 3,
        notifications: 1,
      },
    } as View;
    expect(invitationCount(view)).toBe(3);
    expect(notificationCount(view)).toBe(1);
    view.invitations!.notifications = 0;
    expect(invitationCount(view)).toBe(3);
    expect(notificationCount(view)).toBe(0);
  });
});

describe("Space activity", () => {
  it("counts every connected Space once and includes owner join requests", () => {
    const view = {
      invitations: { actionable: 2, notifications: 1 },
      all_invitations: { actionable: 5, notifications: 3 },
      space_requests: 4,
    } as View;
    expect(invitationCount(view)).toBe(9);
    expect(notificationCount(view)).toBe(3);
  });
});
