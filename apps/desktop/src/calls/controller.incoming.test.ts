import { afterEach, expect, it, vi } from "vitest";
import type { View, Stream } from "../model";
import type { ActiveCall } from "./types";
const peers = vi.hoisted(() => ({
  ids: [] as string[],
  stops: [] as string[],
  action: vi.fn(async () => true),
}));
vi.mock("./nativePeer", () => ({
  usesNativePeer: () => true,
  nativeMediaPermission: vi.fn(),
  takeIncomingControl: vi.fn(async () => {}),
  nativeIncomingAction: peers.action,
  NativePeer: class {
    id: string;
    constructor(...args: unknown[]) {
      this.id = args[10] as string;
      peers.ids.push(this.id);
    }
    stop() {
      peers.stops.push(this.id);
      return Promise.resolve();
    }
    update() {
      return Promise.resolve();
    }
  },
}));
vi.mock("./control", async (importOriginal) => ({
  ...(await importOriginal<typeof import("./control")>()),
  Control: class {},
  requestContext: () => ({}),
  operate: vi.fn(),
}));
import { Calls } from "./controller";
function fixture() {
  vi.stubGlobal(
    "MediaStream",
    class {
      getTracks() {
        return [];
      }
    },
  );
  const chat = {
    space_context: "host",
    space: "space",
    stream: "chat",
    head: "head",
    can_post: true,
    members: [
      { identity_id: "me", credential_ids: ["a"], capabilities: ["POST"] },
      { identity_id: "them", credential_ids: ["b"], capabilities: ["POST"] },
    ],
  } as unknown as Stream;
  const call: ActiveCall = {
    call_id: "call",
    kind: "direct",
    initial_media: "audio",
    config_id: "head",
    key_epoch: 2,
    ringing: false,
    started_by: "them",
    started_at: 1,
    scope: {
      hosting_space_id: "host",
      conversation: { space_id: "space", stream_id: "chat" },
    },
    participants: Object.fromEntries(
      [
        ["me", "a"],
        ["them", "b"],
      ].map(([identity_id, credential_id]) => [
        identity_id,
        {
          identity_id,
          credential_id,
          media: {
            audio_muted: false,
            video_published: false,
            screen_published: false,
          },
        },
      ]),
    ),
  };
  const calls = new Calls();
  const command = vi.fn(
    async (
      _chat: Stream,
      _operation: Record<string, unknown>,
    ): Promise<{ call?: ActiveCall }> => ({}),
  );
  Object.assign(calls, {
    view: {
      identity: "me",
      credential: "a",
      streams: [chat],
      spaces: [{ id: "host", managed: true, status: "joined" }],
    } as unknown as View,
    command,
  });
  return { calls, call, command };
}
afterEach(() => {
  peers.ids = [];
  peers.stops = [];
  peers.action.mockReset();
  peers.action.mockResolvedValue(true);
  vi.unstubAllGlobals();
});
it("answers a system-reported call through CallKit without a second foreground join", async () => {
  const { calls, call } = fixture();
  const chat = (calls as any).view.streams[0];
  const start = vi.spyOn(calls, "start").mockResolvedValue();
  Object.assign(calls.snapshot, { incoming: { call, chat } });
  await Promise.all([calls.answer(), calls.answer()]);
  expect(peers.action).toHaveBeenCalledExactlyOnceWith("me", "call", "answer");
  expect(start).not.toHaveBeenCalled();
  expect(calls.snapshot.nativeAnswer?.id).toBe("call");
  await calls.decline();
  expect(peers.action).toHaveBeenLastCalledWith("me", "call", "decline");
  expect(calls.snapshot.nativeAnswer).toBeUndefined();
});
it("keeps foreground-only calls working when CallKit has no matching incoming call", async () => {
  const { calls, call } = fixture();
  const chat = (calls as any).view.streams[0];
  peers.action.mockResolvedValue(false);
  const start = vi.spyOn(calls, "start").mockResolvedValue();
  Object.assign(calls.snapshot, { incoming: { call, chat } });
  await calls.answer();
  expect(start).toHaveBeenCalledExactlyOnceWith(chat, false, call);
  expect(calls.snapshot.nativeAnswer).toBeUndefined();
});
it("does not start a call when native Answer rejects authorization", async () => {
  const { calls, call } = fixture();
  const chat = (calls as any).view.streams[0];
  peers.action.mockRejectedValue(new Error("unauthorized"));
  const start = vi.spyOn(calls, "start").mockResolvedValue();
  Object.assign(calls.snapshot, { incoming: { call, chat } });
  await calls.answer();
  expect(start).not.toHaveBeenCalled();
  expect(calls.snapshot.nativeAnswer).toBeUndefined();
  expect(calls.snapshot.error).toBeDefined();
});
it("adopts a background call once without joining or restarting its native peer", async () => {
  const { calls, call, command } = fixture();
  const value = {
    id: "native",
    call_id: "call",
    phase: "connecting" as const,
    call,
  };
  await calls.adoptIncoming(value, vi.fn());
  await calls.adoptIncoming(value, vi.fn());
  expect(peers.ids).toEqual(["native"]);
  expect(peers.stops).toEqual([]);
  expect(command).not.toHaveBeenCalled();
  expect(calls.snapshot.phase).toBe("connecting");
  expect(calls.snapshot.active).toEqual(call);
  await calls.finishManagedIncoming();
  expect(peers.stops).toEqual(["native"]);
  expect(calls.snapshot.phase).toBe("idle");
  expect(calls.snapshot.error).toBeUndefined();
});
it("hands an established call to an authenticated foreground socket without restarting audio", async () => {
  const { calls, call, command } = fixture();
  command.mockResolvedValue({ call });
  const { takeIncomingControl } = await import("./nativePeer");
  await calls.adoptIncoming(
    { id: "native", call_id: "call", phase: "connected", call },
    vi.fn(),
  );
  expect(command.mock.calls[0][1]).toEqual({
    type: "heartbeat",
    call_id: "call",
  });
  expect(takeIncomingControl).toHaveBeenCalledWith("me", "native");
  await calls.finishManagedIncoming();
  expect(calls.snapshot.phase).toBe("connected");
  expect(peers.stops).toEqual([]);
  await calls.leave();
  expect(peers.stops).toEqual(["native"]);
});
it("shows pending native admission without creating media and rejects another credential", async () => {
  const { calls, call } = fixture();
  await calls.adoptIncoming(
    { id: "native", call_id: "call", phase: "connecting" },
    vi.fn(),
  );
  expect(calls.snapshot.nativeAnswer?.id).toBe("call");
  expect(peers.ids).toEqual([]);
  call.participants.me.credential_id = "other";
  await calls.adoptIncoming(
    { id: "native", call_id: "call", phase: "connected", call },
    vi.fn(),
  );
  expect(peers.ids).toEqual([]);
  await calls.finishManagedIncoming();
  expect(calls.snapshot.nativeAnswer).toBeUndefined();
});
