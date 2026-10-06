import { expect, it, vi } from "vitest";
import type { Stream, View } from "../model";
import type { Calls } from "./controller";
import { SessionDialogs } from "./SessionDialogs";
import { muted, type ActiveCall, type Snapshot } from "./types";

vi.mock("react", async (original) => ({
  ...(await original<typeof import("react")>()),
  useSyncExternalStore: (_subscribe: unknown, getSnapshot: () => unknown) =>
    getSnapshot(),
}));
function setup() {
  const chat = {
    name: "Planning",
    space_context: "host",
    space: "space",
    stream: "chat",
    head: "head",
    can_post: true,
    member_names: { peer: "Alex" },
  } as unknown as Stream;
  const call: ActiveCall = {
    call_id: "call",
    scope: {
      hosting_space_id: "host",
      conversation: { space_id: "space", stream_id: "chat" },
    },
    config_id: "head",
    key_epoch: 1,
    kind: "direct",
    initial_media: "audio",
    started_by: "peer",
    started_at: 1,
    phase: "ringing",
    ready: true,
    participants: {
      peer: {
        identity_id: "peer",
        credential_id: "device",
        media: muted,
        ready: true,
      },
    },
    invitations: {
      me: {
        invitation_id: "attempt",
        invited_by: "peer",
        expires_at: Math.floor(Date.now() / 1000) + 60,
      },
    },
  };
  const state: Snapshot = {
    phase: "idle",
    media: muted,
    tiles: [],
    available: {},
    incoming: [call],
  };
  const view = {
    identity: "me",
    streams: [chat],
    spaces: [{ id: "host", name: "Team", managed: true, status: "joined" }],
  } as unknown as View;
  const calls = {
    subscribe: () => () => {},
    getSnapshot: () => state,
    answer: vi.fn(),
    decline: vi.fn(),
    cancelJoin: vi.fn(),
  } as unknown as Calls;
  return { calls, view, state, call, chat };
}
it("requires explicit End & answer and carries the exact invitation attempt", () => {
  const f = setup();
  f.state.active = { ...f.call, call_id: "current" };
  f.state.chat = { ...f.chat, name: "Current chat" };
  const dialog = SessionDialogs(f)!;
  const actions = dialog.props.children[2].props.children;
  expect(actions[0].props.children).toBe("End & answer");
  expect(f.calls.answer).not.toHaveBeenCalled();
  actions[0].props.onClick();
  expect(f.calls.answer).toHaveBeenCalledExactlyOnceWith(
    f.chat,
    f.call,
    true,
    "attempt",
  );
  dialog.props.onClose();
  expect(f.calls.decline).toHaveBeenCalledExactlyOnceWith(f.call);
});
it("suppresses only the exact incoming invitation already presented by native UI", () => {
  const f = setup();
  f.state.nativePresented = [
    { call_id: f.call.call_id, invitation_id: "attempt" },
  ];
  expect(SessionDialogs(f)).toBeNull();
  f.state.nativePresented = [{ call_id: f.call.call_id, invitation_id: "old" }];
  expect(SessionDialogs(f)).not.toBeNull();
});
it("does not dismiss a call while Answer is pending", () => {
  const f = setup();
  f.state.answering = true;
  const dialog = SessionDialogs(f)!;
  expect(
    dialog.props.children[2].props.children.every(
      (button: any) => button.props.disabled,
    ),
  ).toBe(true);
  dialog.props.onClose();
  expect(f.calls.decline).not.toHaveBeenCalled();
});
it("lets a user cancel switching without touching the existing call", () => {
  const f = setup();
  f.state.incoming = [];
  f.state.joinRequest = { chat: f.chat, call: f.call };
  const dialog = SessionDialogs(f)!;
  dialog.props.children[1].props.children[1].props.onClick();
  expect(f.calls.cancelJoin).toHaveBeenCalledOnce();
  expect(f.calls.answer).not.toHaveBeenCalled();
  expect(f.calls.decline).not.toHaveBeenCalled();
});
