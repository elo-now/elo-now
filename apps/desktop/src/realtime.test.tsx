import { expect, test } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import type { Stream, View } from "./model";
import {
  onlineInScope,
  pendingRemoteUploads,
  realtimeScopes,
  realtimeStateKey,
  typingPeople,
  visibleRealtimeEvents,
  type RealtimeEvent,
  type RealtimeScope,
} from "./realtime";
import {
  OnlineIndicator,
  RealtimeProvider,
  RemoteUploads,
  TypingIndicator,
} from "./useRealtime";

const scope: RealtimeScope = {
  space_context: "work",
  space: "space",
  stream: "general",
};
const now = 10_000;
const event = (
  payload: RealtimeEvent["payload"],
  overrides: Partial<RealtimeEvent> = {},
): RealtimeEvent => ({
  ...scope,
  issuer_identity: "bob",
  issuer_credential: "phone",
  created_at_ms: 5_000,
  expires_at_ms: 20_000,
  nonce: "event",
  payload,
  ...overrides,
});
const chat = (rows: Stream["rows"] = []): Stream => ({
  ...scope,
  name: "General",
  head: "head",
  controller: "alice",
  recovery: null,
  forked: false,
  can_post: true,
  owners: [],
  rows,
  members: ["alice", "bob"].map((identity_id) => ({
    identity_id,
    external: false,
    capabilities: ["READ", "POST"],
    credential_ids: [],
  })),
});
const view = (): View => ({
  identity: "alice",
  credential: "this-device",
  active_space: "work",
  streams: [chat()],
  replicas: [],
  counts: { pending: 0, stored: 0, held: 0, rejected: 0, repair_pending: 0 },
  contacts: [{ id: "bob", name: "Bob" }],
  inbox: {},
  history_warning: "",
  alpha_ready: false,
});
const upload = (
  status: "uploading" | "interrupted" | "cancelled" | "ready" = "uploading",
) =>
  event({
    kind: "upload",
    attachment_id: "file-id",
    name: "notes.pdf",
    size: 1234,
    status,
  });

test("presence remains online when any verified device is active and expires per shared scope", () => {
  const events = [
    event({ kind: "presence", active: false }),
    event({ kind: "presence", active: true }, { issuer_credential: "desktop" }),
  ];
  expect(onlineInScope(events, "bob", scope, now)).toBe(true);
  expect(onlineInScope(events, "bob", scope, 20_000)).toBe(false);
  expect(
    onlineInScope(events, "bob", { ...scope, space_context: "private" }, now),
  ).toBe(false);
  expect(onlineInScope(events, "bob", { ...scope, stream: "other" }, now)).toBe(
    false,
  );
});

test("repeated native snapshots coalesce without hiding lease renewal or disconnection", () => {
  const events = [event({ kind: "presence", active: true }), upload()];
  const previous = realtimeStateKey(["work"], events);
  expect(realtimeStateKey(["work"], structuredClone(events))).toBe(previous);
  expect(realtimeStateKey([], events)).not.toBe(previous);
  expect(
    realtimeStateKey(
      ["work"],
      [{ ...events[0], expires_at_ms: 40_000 }, events[1]],
    ),
  ).not.toBe(previous);
  expect(
    realtimeStateKey(["work"], [events[0], upload("interrupted")]),
  ).not.toBe(previous);
});

test("typing deduplicates devices, omits the local identity, and expires without another event", () => {
  const events = [
    event({ kind: "typing", active: true }),
    event({ kind: "typing", active: true }, { issuer_credential: "desktop" }),
    event({ kind: "typing", active: true }, { issuer_identity: "alice" }),
  ];
  expect(typingPeople(events, scope, "alice", now)).toEqual(["bob"]);
  expect(typingPeople(events, scope, "alice", 20_000)).toEqual([]);
});

test("only authenticated shared scopes are requested, with bounded and deduplicated subscriptions", () => {
  const profile = view();
  profile.all_streams = [
    chat(),
    { ...chat(), space_context: "other-space", stream: "other" },
    { ...chat(), stream: "removed", members: [] },
  ];
  expect(realtimeScopes(profile)).toEqual([
    scope,
    { ...scope, space_context: "other-space", stream: "other" },
  ]);
  profile.all_streams = Array.from({ length: 300 }, (_, index) => ({
    ...chat(),
    stream: String(index),
  }));
  expect(realtimeScopes(profile)).toHaveLength(256);
  const selected = { ...chat(), stream: "selected-late" };
  expect(realtimeScopes(profile, selected)[0].stream).toBe("selected-late");
});

test("blocking, removed membership and lost read access hide live events before a new native snapshot", () => {
  const profile = view();
  const events = [event({ kind: "presence", active: true }), upload()];
  expect(visibleRealtimeEvents(profile, events)).toHaveLength(2);
  profile.blocked_users = [{ identity: "bob", name: "Bob" }];
  expect(visibleRealtimeEvents(profile, events)).toEqual([]);
  profile.blocked_users = [];
  profile.streams[0].members = profile.streams[0].members.filter(
    (member) => member.identity_id === "alice",
  );
  expect(visibleRealtimeEvents(profile, events)).toEqual([]);
  profile.streams = [chat()];
  profile.streams[0].members[0].capabilities = [];
  expect(visibleRealtimeEvents(profile, events)).toEqual([]);
});

test("a committed or deleted record suppresses late ready events even if the loaded page has no descriptor", () => {
  const ready = event({
    kind: "upload",
    attachment_id: "file-id",
    name: "notes.pdf",
    size: 1234,
    status: "ready",
    record: "committed-file",
  });
  const profile = view();
  profile.streams[0].rows = [
    {
      id: "delete-event",
      state: "STORED",
      body: {
        kind: "deleted",
        issuer_identity: "bob",
        deleted_record_id: "committed-file",
      },
    },
  ];
  expect(pendingRemoteUploads([ready], profile, chat(), now)).toEqual([]);
});

test("ready retains the upload tile until the matching signed attachment is available", () => {
  expect(
    pendingRemoteUploads([upload("ready")], view(), chat(), now),
  ).toHaveLength(1);
  const row: Stream["rows"][number] = {
    id: "signed-record",
    state: "STORED",
    body: {
      kind: "file.manifest",
      issuer_identity: "bob",
      attachment: {
        id: "file-id",
        name: "notes.pdf",
        mime: "application/pdf",
        plaintext_size: 1234,
        encrypted_size: 1248,
        created_at_ms: now,
        object_id: "object",
      },
    },
  };
  expect(pendingRemoteUploads([upload()], view(), chat([row]), now)).toEqual(
    [],
  );
  expect(
    pendingRemoteUploads([upload("ready")], view(), chat([row]), now),
  ).toEqual([]);
});

test("upload cancellation, local transfers and other scopes cannot produce remote tiles", () => {
  expect(
    pendingRemoteUploads(
      [upload(), { ...upload("cancelled"), created_at_ms: 6_000 }],
      view(),
      chat(),
      now,
    ),
  ).toEqual([]);
  expect(
    pendingRemoteUploads(
      [{ ...upload(), issuer_credential: "this-device" }],
      view(),
      chat(),
      now,
    ),
  ).toEqual([]);
  expect(
    pendingRemoteUploads(
      [{ ...upload(), space_context: "private" }],
      view(),
      chat(),
      now,
    ),
  ).toEqual([]);
});

test("an expired upload becomes interrupted for a bounded interval instead of spinning forever", () => {
  expect(
    pendingRemoteUploads([upload()], view(), chat(), 20_001)[0].payload.status,
  ).toBe("interrupted");
  expect(pendingRemoteUploads([upload()], view(), chat(), 80_001)).toEqual([]);
});

test("remote upload presentation has no progress percentage, read target, download action or notification", () => {
  const html = renderToStaticMarkup(
    <RealtimeProvider
      value={{ view: view(), events: [upload()], now, typing: () => {} }}
    >
      <RemoteUploads view={view()} chat={chat()} hideAvatars={false} />
    </RealtimeProvider>,
  );
  expect(html).toContain("notes.pdf");
  expect(html).toContain("Uploading…");
  expect(html).not.toMatch(/<progress|<button|data-unread-id|data-record-id|%/);
});

test("typing and online labels use shared display names and expire accessibly", () => {
  const profile = view();
  const html = renderToStaticMarkup(
    <RealtimeProvider
      value={{
        view: profile,
        events: [
          event({ kind: "typing", active: true }),
          event({ kind: "presence", active: true }),
        ],
        now,
        typing: () => {},
      }}
    >
      <TypingIndicator chat={chat()} />
      <OnlineIndicator identity="bob" chat={chat()} />
    </RealtimeProvider>,
  );
  expect(html).toContain("Bob is typing…");
  expect(html).toContain('aria-label="Online"');
  profile.blocked_users = [{ identity: "bob", name: "Bob" }];
  expect(
    renderToStaticMarkup(
      <RealtimeProvider
        value={{
          view: profile,
          events: [event({ kind: "presence", active: true })],
          now,
          typing: () => {},
        }}
      >
        <OnlineIndicator identity="bob" chat={chat()} />
      </RealtimeProvider>,
    ),
  ).toBe("");
});
