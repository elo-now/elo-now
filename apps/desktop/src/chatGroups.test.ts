import { describe, expect, it } from "vitest";
import {
  chatActivity,
  chatSections,
  isDirectChat,
  chatIconName,
} from "./chatGroups";
import type { Stream, View } from "./model";

function chat(id: number, group: string | null = null): Stream {
  return {
    name: `Chat ${id}`,
    stream: String(id),
    space: "space",
    head: "head",
    controller: "device",
    recovery: null,
    forked: false,
    can_post: true,
    group,
    created_at: id * 1000,
    owners: [{ identity_id: "me" }],
    members: [
      {
        identity_id: "me",
        identity_type: "HUMAN",
        external: false,
        capabilities: ["READ", "POST"],
        credential_ids: ["phone", "desktop"],
      },
    ],
    rows: [],
  };
}
function view(streams: Stream[]): View {
  return {
    identity: "me",
    credential: "phone",
    groups: [{ id: "work", name: "Work" }],
    streams,
    replicas: [],
    counts: { pending: 0, stored: 0, held: 0, rejected: 0, repair_pending: 0 },
    inbox: {},
    history_warning: "",
    alpha_ready: false,
  };
}
const person = (identity: string) => ({
  identity_id: identity,
  identity_type: "HUMAN",
  external: true,
  capabilities: ["READ", "POST"],
  credential_ids: [`${identity}-phone`],
});

describe("Personal chat groups", () => {
  it("keeps the verified General above five recent chats, without pinning a same-named ordinary chat", () => {
    const general = { ...chat(1, "work"), name: "General", is_general: true };
    const namesake = { ...chat(9), name: "General" };
    const streams = [
      general,
      namesake,
      ...Array.from({ length: 7 }, (_, i) => chat(i + 2)),
    ];
    const sections = chatSections(view(streams), "overview");
    expect(
      sections.map((section) => [
        section.id,
        section.chats.map((row) => row.stream),
      ]),
    ).toEqual([
      ["general", ["1"]],
      ["recent", ["9", "8", "7", "6", "5"]],
      ["ungrouped", ["4", "3", "2"]],
    ]);
    expect(sections[0].title).toBeUndefined();
    expect(chatSections(view(streams), "overview", "missing")[0].chats).toEqual(
      [],
    );
    expect(chatSections(view(streams), "dms")[0].chats).not.toContain(general);
    expect(chatSections(view(streams), "work")[0].chats).toEqual([general]);
  });
  it("keeps explicit DMs in their tab as people join and changes only the icon", () => {
    const direct = chat(1, "work");
    direct.chat_kind = "direct";
    expect(isDirectChat(direct, "me")).toBe(true);
    expect(chatIconName(direct, "me")).toBe("person");
    direct.members.push(person("alex"));
    direct.members[1].credential_ids.push("alex-desktop");
    expect(chatIconName(direct, "me")).toBe("person");
    direct.members.push(person("maya"));
    expect(chatIconName(direct, "me")).toBe("people");
    expect(chatSections(view([direct]), "dms")[0].chats).toEqual([direct]);
    direct.members.pop();
    expect(chatIconName(direct, "me")).toBe("person");
    expect(chatSections(view([direct]), "dms")[0].chats).toEqual([direct]);
    expect(isDirectChat(direct, "outsider")).toBe(false);
  });
  it("does not turn a named chat into a DM when it has only two members", () => {
    const named = chat(1);
    named.chat_kind = "chat";
    named.members.push(person("alex"));
    expect(isDirectChat(named, "me")).toBe(false);
    expect(chatIconName(named, "me")).toBe("hash");
    expect(chatSections(view([named]), "dms")[0].chats).toEqual([]);
  });
  it("keeps the five latest first and avoids duplicate ungrouped rows", () => {
    const streams = Array.from({ length: 7 }, (_, i) =>
      chat(i + 1, [1, 5].includes(i + 1) ? "work" : null),
    );
    const before = structuredClone(streams);
    const sections = chatSections(view(streams), "overview");
    expect(sections.map((s) => [s.id, s.chats.map((c) => c.stream)])).toEqual([
      ["recent", ["7", "6", "5", "4", "3"]],
      ["ungrouped", ["2"]],
    ]);
    const visible = sections.flatMap((section) =>
      section.chats.map((c) => c.stream),
    );
    expect(new Set(visible).size).toBe(visible.length);
    expect(streams).toEqual(before);
    expect(
      chatSections(view(streams), "work")[0].chats.map((c) => c.stream),
    ).toEqual(["5", "1"]);
  });
  it("uses message activity and local creation time, ignoring invalid timestamps", () => {
    const stream = chat(1);
    stream.rows = [
      {
        id: "old",
        state: "LOCAL",
        body: {
          kind: "chat.message",
          issuer_identity: "me",
          created_at: "1970-01-01T00:00:09Z",
        },
      },
      {
        id: "unknown",
        state: "LOCAL",
        body: {
          kind: "chat.message",
          issuer_identity: "me",
          created_at: "unknown",
        },
      },
    ];
    expect(chatActivity(stream)).toBe(9000);
    expect(
      chatSections(view([chat(7), stream]), "overview")[0].chats[0].stream,
    ).toBe("1");
    delete stream.created_at;
    stream.rows = [];
    expect(chatActivity(stream)).toBe(0);
  });
  it("legacy views infer one other human, not devices, services or a solo chat", () => {
    const direct = chat(1, "work");
    expect(isDirectChat(direct, "me")).toBe(false);
    direct.members.push(person("alex"));
    expect(isDirectChat(direct, "me")).toBe(true);
    expect(
      chatSections(view([chat(2), direct]), "dms")[0].chats.map(
        (c) => c.stream,
      ),
    ).toEqual(["1"]);
    direct.members.push(person("maya"));
    expect(isDirectChat(direct, "me")).toBe(false);
    direct.members = [person("alex"), person("maya")];
    expect(isDirectChat(direct, "me")).toBe(false);
    direct.members = [
      person("me"),
      { ...person("bot"), identity_type: "SERVICE" },
    ];
    expect(isDirectChat(direct, "me")).toBe(false);
  });
  it("supports empty views and groups without inventing memberships", () => {
    expect(chatSections(view([]), "overview")).toEqual([]);
    expect(chatSections(view([chat(1)]), "missing")[0].chats).toEqual([]);
    expect(chatSections(view([chat(1)]), "dms")[0].chats).toEqual([]);
  });
  it("searches every group by chat name, latest message and group name", () => {
    const named = chat(1, "work");
    named.name = "Launch room";
    named.rows = [
      {
        id: "message",
        state: "LOCAL",
        body: {
          kind: "chat.message",
          issuer_identity: "me",
          payload: { text: "Bring the telescope" },
        },
      },
    ];
    const other = chat(2);
    expect(
      chatSections(view([other, named]), "dms", " launch ")[0].chats,
    ).toEqual([named]);
    expect(
      chatSections(view([other, named]), "overview", "TELESCOPE")[0].chats,
    ).toEqual([named]);
    expect(
      chatSections(view([other, named]), "overview", "work")[0].chats,
    ).toEqual([named]);
    expect(
      chatSections(view([other, named]), "overview", "missing")[0].chats,
    ).toEqual([]);
  });
});
