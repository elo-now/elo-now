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
it("does not open an automatic incoming dialog, even during another call", () => {
  const f = setup();
  expect(SessionDialogs(f)).toBeNull();
  f.state.active = { ...f.call, call_id: "current" };
  expect(SessionDialogs(f)).toBeNull();
  f.state.nativePresented = [{ call_id: f.call.call_id, invitation_id: "old" }];
  expect(SessionDialogs(f)).toBeNull();
});
it("requires explicit End & answer and carries the exact invitation attempt", () => {
  const f = setup();
  f.state.active = { ...f.call, call_id: "current" };
  f.state.chat = { ...f.chat, name: "Current chat" };
  f.state.joinRequest = {
    chat: f.chat,
    call: f.call,
    invitation_id: "attempt",
  };
  const dialog = SessionDialogs(f)!;
  const actions = dialog.props.children[1].props.children;
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
  expect(f.calls.cancelJoin).toHaveBeenCalledOnce();
  expect(f.calls.decline).not.toHaveBeenCalled();
});
it("does not cancel the explicit switch while Answer is pending", () => {
  const f = setup();
  f.state.answering = true;
  f.state.joinRequest = {
    chat: f.chat,
    call: f.call,
    invitation_id: "attempt",
  };
  const dialog = SessionDialogs(f)!;
  expect(
    dialog.props.children[1].props.children.every(
      (button: any) => button.props.disabled,
    ),
  ).toBe(true);
  dialog.props.onClose();
  expect(f.calls.cancelJoin).not.toHaveBeenCalled();
});
it("lets a user cancel switching without touching the existing call", () => {
  const f = setup();
  f.state.incoming = [];
  f.state.joinRequest = {
    chat: f.chat,
    call: f.call,
    invitation_id: "attempt",
  };
  const dialog = SessionDialogs(f)!;
  dialog.props.children[1].props.children[1].props.onClick();
  expect(f.calls.cancelJoin).toHaveBeenCalledOnce();
  expect(f.calls.answer).not.toHaveBeenCalled();
  expect(f.calls.decline).not.toHaveBeenCalled();
});
it("preserves an old attempt ID until the controller revalidates it", () => {
  const f = setup();
  f.state.joinRequest = {
    chat: f.chat,
    call: f.call,
    invitation_id: "attempt",
  };
  f.state.incoming = [
    {
      ...f.call,
      invitations: {
        me: { ...f.call.invitations!.me, invitation_id: "new-attempt" },
      },
    },
  ];
  const dialog = SessionDialogs(f)!;
  dialog.props.children[1].props.children[0].props.onClick();
  expect(f.calls.answer).toHaveBeenCalledExactlyOnceWith(
    f.chat,
    f.call,
    true,
    "attempt",
  );
});

it("does not reuse an old invitation when confirming an ordinary group Join", () => {
  const f = setup();
  f.call.kind = "group";
  f.call.invitations!.me.expires_at = 1;
  f.state.joinRequest = { chat: f.chat, call: f.call };
  const dialog = SessionDialogs(f)!;
  const confirm = dialog.props.children[1].props.children[0];
  expect(confirm.props.children).toBe("End & join");
  confirm.props.onClick();
  expect(f.calls.answer).toHaveBeenCalledExactlyOnceWith(
    f.chat,
    f.call,
    true,
    undefined,
  );
});
