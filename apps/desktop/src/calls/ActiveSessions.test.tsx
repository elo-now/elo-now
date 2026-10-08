import { expect, it, vi } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import type { Stream, View } from "../model";
import type { Calls } from "./controller";
import { activeSessions } from "./sessionPresence";
import { CallList } from "./ActiveSessions";
import { CallButton } from "./CallUI";
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
    requestStart: vi.fn(),
    reveal: vi.fn(),
    expand: vi.fn(),
  } as unknown as Calls;
  return { chat, call, view, state, calls };
}

it("lists verified ready calls across Spaces without acquiring media", () => {
  const f = fixture();
  const sessions = activeSessions(f.view, f.state.available);
  expect(sessions).toHaveLength(1);
  expect(sessions[0]).toMatchObject({
    spaceName: "Team",
    participantNames: ["Alex"],
  });
  const markup = renderToStaticMarkup(
    <CallList calls={f.calls} view={f.view} onOpen={vi.fn()} />,
  );
  expect(markup).toContain("Planning");
  expect(markup).toContain("in Team space");
  expect(markup).toContain("Alex");
  expect(markup).not.toContain("Morgan");
  expect(f.calls.start).not.toHaveBeenCalled();
});

it("omits the redundant Space name for a call in the selected Space", () => {
  const f = fixture();
  f.view.active_space = "other";
  const markup = renderToStaticMarkup(
    <CallList calls={f.calls} view={f.view} onOpen={vi.fn()} />,
  );
  expect(markup).toContain("Planning");
  expect(markup).toContain("Alex");
  expect(markup).not.toContain("in Team space");
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

it("keeps dismissed groups in Calls and opens their chat without joining", () => {
  const f = fixture();
  f.state.dismissed = [`${callKey(f.call)}:${f.call.call_id}`];
  const onOpen = vi.fn();
  const list = CallList({ calls: f.calls, view: f.view, onOpen });
  const row = list.props.children[0];
  row.props.children[0].props.onClick();
  expect(f.calls.reveal).toHaveBeenCalledExactlyOnceWith(
    expect.objectContaining({ space_context: "other", stream: "chat" }),
  );
  expect(onOpen).toHaveBeenCalledOnce();
  expect(f.calls.requestStart).not.toHaveBeenCalled();
  const join = row.props.children[1];
  expect(join.props["aria-label"]).toBe("Join");
  expect(join.props.className).toBe("call-list-open");
  expect(renderToStaticMarkup(join)).toContain("<svg");
  expect(renderToStaticMarkup(join)).not.toContain(">Join</button>");
  join.props.onClick();
  expect(f.calls.requestStart).toHaveBeenCalledExactlyOnceWith(
    expect.objectContaining({ space_context: "other", stream: "chat" }),
    f.call,
  );
});

it("opens this device's call instead of offering a redundant Join", () => {
  const f = fixture();
  f.state.active = f.call;
  const list = CallList({ calls: f.calls, view: f.view, onOpen: vi.fn() });
  const markup = renderToStaticMarkup(list);
  expect(markup).toContain('aria-label="Open call"');
  expect(markup).toContain('class="call-list-open"');
  expect(markup).not.toContain(">Open call</button>");
  list.props.children[0].props.children[1].props.onClick();
  expect(f.calls.requestStart).toHaveBeenCalledExactlyOnceWith(f.chat, f.call);
  expect(f.calls.expand).not.toHaveBeenCalled();
});

it("does not confuse identical call IDs from separate hostings", () => {
  const f = fixture();
  f.state.active = {
    ...f.call,
    scope: { ...f.call.scope, hosting_space_id: "current" },
  };
  const list = CallList({ calls: f.calls, view: f.view, onOpen: vi.fn() });
  list.props.children[0].props.children[1].props.onClick();
  expect(f.calls.expand).not.toHaveBeenCalled();
  expect(f.calls.requestStart).toHaveBeenCalledOnce();
});

it("reveals a dismissed group from the phone action and waits for an explicit Join", () => {
  const f = fixture();
  f.state.dismissed = [`${callKey(f.call)}:${f.call.call_id}`];
  const phone = CallButton({ calls: f.calls, chat: f.chat });
  expect(phone.props["aria-label"]).toBe("Open call");
  phone.props.onClick();
  expect(f.calls.reveal).toHaveBeenCalledExactlyOnceWith(f.chat);
  expect(f.calls.requestStart).not.toHaveBeenCalled();
  // The distinct Join control remains the admission action.
  const list = CallList({ calls: f.calls, view: f.view, onOpen: vi.fn() });
  list.props.children[0].props.children[1].props.onClick();
  expect(f.calls.requestStart).toHaveBeenCalledExactlyOnceWith(f.chat, f.call);
});

it("keeps the phone admission action for direct calls and new sessions", () => {
  const f = fixture();
  f.call.kind = "direct";
  CallButton({ calls: f.calls, chat: f.chat }).props.onClick();
  expect(f.calls.requestStart).toHaveBeenLastCalledWith(f.chat, f.call);
  expect(f.calls.reveal).not.toHaveBeenCalled();
  f.state.available = {};
  CallButton({ calls: f.calls, chat: f.chat }).props.onClick();
  expect(f.calls.requestStart).toHaveBeenLastCalledWith(f.chat, undefined);
});

it("opens an already joined group but never confuses its ID with another hosting", () => {
  const f = fixture();
  f.state.active = f.call;
  CallButton({ calls: f.calls, chat: f.chat }).props.onClick();
  expect(f.calls.requestStart).toHaveBeenCalledExactlyOnceWith(f.chat, f.call);
  vi.mocked(f.calls.requestStart).mockClear();
  f.state.active = {
    ...f.call,
    scope: { ...f.call.scope, hosting_space_id: "different-hosting" },
  };
  CallButton({ calls: f.calls, chat: f.chat }).props.onClick();
  expect(f.calls.reveal).toHaveBeenCalledExactlyOnceWith(f.chat);
  expect(f.calls.requestStart).not.toHaveBeenCalled();
});

it.each(["direct", "group"] as const)(
  "restores a minimized %s from the drawer without joining or expanding",
  (kind) => {
    const f = fixture();
    f.call.kind = kind;
    f.state.minimized = `${callKey(f.call)}:${f.call.call_id}`;
    const phone = CallButton({ calls: f.calls, chat: f.chat });
    expect(phone.props["aria-label"]).toBe("Open call");
    phone.props.onClick();
    expect(f.calls.reveal).toHaveBeenCalledExactlyOnceWith(f.chat);
    expect(f.calls.requestStart).not.toHaveBeenCalled();
    expect(f.calls.expand).not.toHaveBeenCalled();
    f.state.active = f.call;
    CallButton({ calls: f.calls, chat: f.chat }).props.onClick();
    expect(f.calls.reveal).toHaveBeenCalledTimes(2);
    expect(f.calls.requestStart).not.toHaveBeenCalled();
  },
);

it("restores a pending or newly admitted call before available presence arrives", () => {
  const f = fixture();
  f.state.available = {};
  f.state.phase = "connecting";
  f.state.chat = f.chat;
  f.state.minimized = "pending:other:space:chat";
  CallButton({ calls: f.calls, chat: f.chat }).props.onClick();
  expect(f.calls.reveal).toHaveBeenCalledExactlyOnceWith(f.chat);
  expect(f.calls.requestStart).not.toHaveBeenCalled();
  f.state.active = f.call;
  f.state.minimized = `${callKey(f.call)}:${f.call.call_id}`;
  CallButton({ calls: f.calls, chat: f.chat }).props.onClick();
  expect(f.calls.reveal).toHaveBeenCalledTimes(2);
  expect(f.calls.requestStart).not.toHaveBeenCalled();
});
