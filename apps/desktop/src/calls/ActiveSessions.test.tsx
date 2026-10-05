import { expect, it, vi } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import type { Stream, View } from "../model";
import type { Calls } from "./controller";
import { activeSessions } from "./sessionPresence";
import { ActiveSessionJoin, ActiveSessions } from "./ActiveSessions";
import { callKey, muted, type ActiveCall, type Snapshot } from "./types";

vi.mock("react", async (importOriginal) => ({
  ...(await importOriginal<typeof import("react")>()),
  useSyncExternalStore: (_subscribe: unknown, getSnapshot: () => unknown) =>
    getSnapshot(),
}));

function fixture() {
  const chat = {
    name: "Planning",
    space_context: "other",
    space: "space",
    stream: "chat",
    head: "head",
    can_post: true,
    member_names: { peer: "Alex", joining: "Morgan" },
  } as unknown as Stream;
  const call: ActiveCall = {
    call_id: "call",
    scope: {
      hosting_space_id: "other",
      conversation: { space_id: "space", stream_id: "chat" },
    },
    config_id: "head",
    key_epoch: 1,
    kind: "group",
    initial_media: "audio",
    started_by: "peer",
    started_at: 1,
    ready: true,
    participants: {
      peer: {
        identity_id: "peer",
        credential_id: "device",
        media: muted,
        ready: true,
      },
      joining: {
        identity_id: "joining",
        credential_id: "joining-device",
        media: muted,
        ready: false,
      },
    },
  };
  const view = {
    identity: "me",
    name: "My name",
    active_space: "current",
    streams: [],
    all_streams: [chat],
    spaces: [
      { id: "current", name: "Home", managed: true, status: "joined" },
      { id: "other", name: "Team", managed: true, status: "joined" },
    ],
  } as unknown as View;
  const state: Snapshot = {
    phase: "idle",
    media: muted,
    tiles: [],
    available: { [callKey(call)]: call },
  };
  const calls = {
    subscribe: () => () => {},
    getSnapshot: () => state,
    start: vi.fn(),
  } as unknown as Calls;
  return { chat, call, view, state, calls };
}

it("shows ready participants and Space names from outside the selected Space without starting media", () => {
  const f = fixture();
  const sessions = activeSessions(f.view, f.state.available);
  expect(sessions).toHaveLength(1);
  expect(sessions[0]).toMatchObject({
    spaceName: "Team",
    participantNames: ["Alex"],
  });
  const onOpen = vi.fn();
  const list = renderToStaticMarkup(
    <ActiveSessions calls={f.calls} view={f.view} onOpen={onOpen} />,
  );
  expect(list).toContain("Planning");
  expect(list).toContain("in Team space");
  expect(list).toContain("Alex");
  expect(list).not.toContain("Morgan");
  expect(list).not.toContain(">Join<");
  const join = renderToStaticMarkup(
    <ActiveSessionJoin calls={f.calls} view={f.view} chat={f.chat} />,
  );
  expect(join).toContain(">Join</button>");
  expect(f.calls.start).not.toHaveBeenCalled();
  expect(onOpen).not.toHaveBeenCalled();
});

it("hides unavailable, empty, stale, or inaccessible sessions", () => {
  const f = fixture();
  for (const call of [
    { ...f.call, ready: false },
    { ...f.call, ready: undefined },
    { ...f.call, participants: {} },
    { ...f.call, participants: { joining: f.call.participants.joining } },
    { ...f.call, config_id: "old-head" },
  ])
    expect(activeSessions(f.view, { [callKey(call)]: call })).toEqual([]);
  f.chat.can_post = false;
  expect(activeSessions(f.view, f.state.available)).toEqual([]);
  f.chat.can_post = true;
  f.view.spaces![1].status = "offline" as never;
  expect(activeSessions(f.view, f.state.available)).toEqual([]);
});

it("keeps Join disabled while another session is active", () => {
  const f = fixture();
  f.state.active = { ...f.call, call_id: "other-call" };
  const markup = renderToStaticMarkup(
    <ActiveSessionJoin calls={f.calls} view={f.view} chat={f.chat} />,
  );
  expect(markup).toContain('disabled=""');
  expect(f.calls.start).not.toHaveBeenCalled();
});

it("opens a session's chat on list click and joins only through the explicit Join action", () => {
  const f = fixture();
  const onOpen = vi.fn();
  const list = ActiveSessions({ calls: f.calls, view: f.view, onOpen })!;
  const row = list.props.children[1][0];
  row.props.onClick();
  expect(onOpen).toHaveBeenCalledExactlyOnceWith(
    expect.objectContaining({
      space_context: "other",
      stream: "chat",
    }),
  );
  expect(f.calls.start).not.toHaveBeenCalled();
  const banner = ActiveSessionJoin({
    calls: f.calls,
    view: f.view,
    chat: f.chat,
  })!;
  banner.props.children.at(-1).props.onClick();
  expect(f.calls.start).toHaveBeenCalledExactlyOnceWith(
    expect.objectContaining({
      space_context: "other",
      stream: "chat",
    }),
    f.call,
  );
});
