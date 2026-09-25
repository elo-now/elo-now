import { afterEach, describe, expect, it, vi } from "vitest";
import type { Stream, View } from "../model";
import type { ActiveCall, MediaState } from "./types";
const controls = vi.hoisted(() => ({
  events: [] as ((event: Record<string, unknown>) => void)[],
}));
vi.mock("livekit-client", () => ({ isE2EESupported: () => true }));
vi.mock("./control", async (importOriginal) => ({
  ...(await importOriginal<typeof import("./control")>()),
  operate: async () => ({ url: "https://private.example/calls/v1" }),
  requestContext: () => ({}),
  Control: class {
    constructor(
      _endpoint: string,
      _identity: string,
      event: (event: Record<string, unknown>) => void,
      public networkClosed: () => void,
    ) {
      controls.events.push(event);
    }
    command = vi.fn(async () => ({ type: "result" }));
    close() {}
  },
}));
import { Calls } from "./controller";
import { setUpdateRequired } from "../releasePolicy";
import { callErrorCopy } from "./errors";
const chat = {
  space_context: "host",
  space: "space",
  stream: "chat",
  can_post: true,
  head: "head",
  members: [],
  chat_kind: "group",
} as unknown as Stream;
const view = {
  identity: "me",
  credential: "device",
  active_space: "host",
  spaces: [{ id: "host", managed: true, status: "joined" }],
  streams: [chat],
} as unknown as View;
function pendingCapture() {
  let resolve!: (stream: MediaStream) => void;
  const promise = new Promise<MediaStream>((r) => {
    resolve = r;
  });
  const stop = vi.fn();
  const stream = { getTracks: () => [{ stop }] } as unknown as MediaStream;
  vi.stubGlobal("navigator", {
    mediaDevices: {
      getUserMedia: () => promise,
      getDisplayMedia: () => promise,
    },
  });
  return { resolve: () => resolve(stream), stop };
}
afterEach(() => {
  controls.events = [];
  setUpdateRequired(false);
  vi.unstubAllGlobals();
  vi.useRealTimers();
});
describe("call subscriptions", () => {
  it("subscribes beyond 32 chats in bounded batches and cancels queued work on logout", async () => {
    vi.useFakeTimers();
    const calls = new Calls();
    const command = vi.fn(async () => ({ type: "result" }));
    Object.assign(calls, { command });
    const streams = Array.from({ length: 70 }, (_, i) => ({
      ...chat,
      stream: `chat-${i}`,
    }));
    calls.update({ ...view, streams });
    await vi.advanceTimersByTimeAsync(0);
    expect(command).toHaveBeenCalledTimes(16);
    await vi.advanceTimersByTimeAsync(3000);
    expect(command).toHaveBeenCalledTimes(32);
    await vi.advanceTimersByTimeAsync(9000);
    expect(command).toHaveBeenCalledTimes(70);
    expect(
      new Set(
        command.mock.calls.map(
          (entry) => (entry as unknown as [Stream])[0].stream,
        ),
      ).size,
    ).toBe(70);
    calls.update({
      ...view,
      streams: [
        ...streams,
        ...Array.from({ length: 30 }, (_, i) => ({
          ...chat,
          stream: `extra-${i}`,
        })),
      ],
    });
    await vi.advanceTimersByTimeAsync(0);
    expect(command).toHaveBeenCalledTimes(86);
    calls.update(null);
    await vi.advanceTimersByTimeAsync(15000);
    expect(command).toHaveBeenCalledTimes(86);
    calls.dispose();
  });
  it("resubscribes after server eviction without clearing a different incoming call", async () => {
    const calls = new Calls();
    const other = { ...chat, stream: "other" };
    const command = vi.fn(async () => ({ type: "result" }));
    Object.assign(calls, { command });
    calls.update({ ...view, streams: [chat, other] });
    await vi.waitFor(() => expect(command).toHaveBeenCalledTimes(2));
    const incoming = {
      chat: other,
      call: {
        call_id: "other-call",
        scope: {
          hosting_space_id: "host",
          conversation: { space_id: "space", stream_id: "other" },
        },
      } as ActiveCall,
    };
    calls.snapshot = { ...calls.snapshot, incoming };
    const runtime = calls as unknown as {
      event(event: Record<string, unknown>): Promise<void>;
      subscribeChats(): Promise<void>;
    };
    // Wire object property order must not affect scope matching.
    await runtime.event({
      type: "access_revoked",
      scope: {
        conversation: { stream_id: "chat", space_id: "space" },
        hosting_space_id: "host",
      },
    });
    expect(calls.snapshot.incoming).toBe(incoming);
    await runtime.subscribeChats();
    expect(command).toHaveBeenCalledTimes(3);
    expect(command).toHaveBeenLastCalledWith(chat, { type: "subscribe" });
    await runtime.event({ type: "ended", call_id: "other-call" });
    expect(calls.snapshot.incoming).toBeUndefined();
    calls.dispose();
  });

  for (const error of ["unauthorized", "invalid"])
    it(`still subscribes to another chat after a ${error} refusal`, async () => {
      const calls = new Calls();
      const direct = { ...chat, stream: "direct", chat_kind: "direct" };
      const command = vi.fn(async (target: Stream) => {
        if (target.stream === chat.stream) throw new Error(error);
        return { type: "result" };
      });
      Object.assign(calls, { command });
      calls.update({ ...view, streams: [chat, direct] } as View);
      await vi.waitFor(() => expect(command).toHaveBeenCalledTimes(2));
      expect(command).toHaveBeenLastCalledWith(direct, { type: "subscribe" });
      calls.dispose();
    });

  it("stops a subscription pass after a transport failure", async () => {
    const calls = new Calls();
    const command = vi.fn(async () => {
      throw new Error("unavailable");
    });
    Object.assign(calls, { command });
    calls.update({ ...view, streams: [chat, { ...chat, stream: "other" }] });
    await vi.waitFor(() => expect(command).toHaveBeenCalledOnce());
    await Promise.resolve();
    expect(command).toHaveBeenCalledOnce();
    calls.dispose();
  });
});
describe("capture ownership", () => {
  it("does not open capture or join twice while a start is still pending", async () => {
    const calls = new Calls();
    calls.update(view);
    const capture = pendingCapture();
    const getUserMedia = vi.spyOn(navigator.mediaDevices, "getUserMedia");
    const first = calls.start(chat);
    await vi.waitFor(() => expect(getUserMedia).toHaveBeenCalledOnce());
    await calls.start(chat);
    expect(getUserMedia).toHaveBeenCalledOnce();
    calls.dispose();
    capture.resolve();
    await first;
    expect(capture.stop).toHaveBeenCalledOnce();
  });
  it("explains an already joined profile before asking for microphone permission", async () => {
    const calls = new Calls();
    calls.update(view);
    pendingCapture();
    const capture = vi.spyOn(navigator.mediaDevices, "getUserMedia");
    await calls.start(chat, false, {
      participants: { me: { credential_id: "another-device" } },
    } as unknown as ActiveCall);
    expect(capture).not.toHaveBeenCalled();
    expect(calls.snapshot.phase).toBe("idle");
    expect(calls.snapshot.error).toBe("already_joined");
    expect(callErrorCopy(calls.snapshot.error!)).toEqual({
      title: "calls.alreadyJoinedTitle",
      message: "calls.alreadyJoined",
    });
    calls.dispose();
  });
  it("retains a server refusal reason and releases capture without leaving someone else's call", async () => {
    const calls = new Calls();
    calls.update(view);
    const capture = pendingCapture();
    const command = vi.fn(async () => {
      throw new Error("already_joined");
    });
    Object.assign(calls, { command });
    const started = calls.start(chat);
    capture.resolve();
    await started;
    expect(calls.snapshot.error).toBe("already_joined");
    expect(calls.snapshot.phase).toBe("idle");
    expect(calls.localCapture()).toBeUndefined();
    expect(capture.stop).toHaveBeenCalled();
    expect(command).toHaveBeenCalledOnce();
    calls.dispose();
  });
  it("releases a permission result that arrives after logout", async () => {
    const calls = new Calls();
    calls.update(view);
    const capture = pendingCapture();
    const starting = calls.start(chat, true);
    await vi.waitFor(() => expect(calls.snapshot.phase).toBe("connecting"));
    calls.update(null);
    capture.resolve();
    await starting;
    expect(capture.stop).toHaveBeenCalledOnce();
    expect(calls.localCapture()).toBeUndefined();
    expect(calls.snapshot.phase).toBe("idle");
    expect(calls.snapshot.error).toBeUndefined();
    calls.dispose();
  });
  for (const kind of ["video", "screen"] as const)
    it(`releases late ${kind} permission after leaving`, async () => {
      const calls = new Calls();
      calls.update(view);
      const pending = pendingCapture();
      const originalStop = vi.fn();
      const capture = {
        getTracks: () => [{ stop: originalStop }],
        getVideoTracks: () => [],
        getAudioTracks: () => [],
        addTrack: vi.fn(),
      };
      Object.assign(calls, { capture });
      calls.snapshot = {
        ...calls.snapshot,
        active: { call_id: "test" } as ActiveCall,
        chat,
        phase: "connected",
      };
      const toggling = calls.toggle(kind);
      await calls.leave();
      pending.resolve();
      await toggling;
      expect(originalStop).toHaveBeenCalledOnce();
      expect(pending.stop).toHaveBeenCalledOnce();
      expect(capture.addTrack).not.toHaveBeenCalled();
      expect(calls.snapshot.error).toBeUndefined();
      calls.dispose();
    });
});

it("removes an empty group call from the available-call indicator immediately", async () => {
  const calls = new Calls();
  calls.update(view);
  const call: ActiveCall = {
    call_id: "empty-call",
    scope: {
      hosting_space_id: "host",
      conversation: { space_id: "space", stream_id: "chat" },
    },
    kind: "group",
    initial_media: "audio",
    config_id: "head",
    participants: {},
    key_epoch: 2,
    ringing: false,
    started_by: "me",
    started_at: 1,
  };
  calls.snapshot = {
    ...calls.snapshot,
    available: { "host:space:chat": call },
  };
  const events = calls as unknown as {
    event(event: { type: string; call: ActiveCall }): Promise<void>;
  };

  await events.event({ type: "presence", call });

  expect(calls.snapshot.available).toEqual({});
  calls.dispose();
});

function screenCall() {
  const calls = new Calls();
  calls.update(view);
  const capture = {
    getTracks: () => [],
    getVideoTracks: () => [],
    getAudioTracks: () => [],
  };
  const update = vi.fn(
    async (_state: MediaState, _capture: unknown, _screen?: unknown) => {},
  );
  const command = vi.fn(
    async (_chat: Stream, _operation: Record<string, unknown>) => ({}),
  );
  Object.assign(calls, {
    capture,
    adapter: { update, stop: vi.fn(async () => {}) },
    command,
  });
  calls.snapshot = {
    ...calls.snapshot,
    active: { call_id: "test" } as ActiveCall,
    chat,
    phase: "connected",
  };
  return { calls, update, command, capture };
}

it("processes remote hangup before pending signaling and ignores its late failure", async () => {
  const { calls } = screenCall();
  let reject!: (error: Error) => void;
  const signal = vi.fn(
    () =>
      new Promise<void>((_resolve, fail) => {
        reject = fail;
      }),
  );
  Object.assign(calls, { signal });
  await (calls as any).connection(chat);
  const event = controls.events.at(-1)!;
  event({ type: "signal", call_id: "test" });
  await vi.waitFor(() => expect(signal).toHaveBeenCalledOnce());
  const signaling = (calls as any).events;
  event({ type: "ended", call_id: "test" });
  await vi.waitFor(() => expect(calls.snapshot.phase).toBe("idle"));
  reject(new Error("ended"));
  await signaling;
  expect(calls.snapshot.error).toBeUndefined();
  calls.dispose();
});

it("does not let an old hangup end a new call in the same chat", async () => {
  const { calls } = screenCall();
  const scope = {
    hosting_space_id: "host",
    conversation: { space_id: "space", stream_id: "chat" },
  };
  calls.snapshot.active = { ...calls.snapshot.active!, scope };
  await (calls as any).event({ type: "ended", call_id: "old-call", scope });
  expect(calls.snapshot.active?.call_id).toBe("test");
  expect(calls.snapshot.phase).toBe("connected");
  calls.dispose();
});

it("treats an ended heartbeat as a normal hangup without an error dialog", async () => {
  const { calls, command } = screenCall();
  command.mockRejectedValueOnce(new Error("ended"));
  await (calls as any).tick();
  expect(calls.snapshot.phase).toBe("idle");
  expect(calls.snapshot.error).toBeUndefined();
  calls.dispose();
});

it("sends hangup without waiting for media teardown", async () => {
  const { calls, command } = screenCall();
  let stopped!: () => void;
  Object.assign(calls, {
    adapter: {
      stop: () =>
        new Promise<void>((resolve) => {
          stopped = resolve;
        }),
    },
  });
  const leaving = calls.leave();
  expect(calls.snapshot.phase).toBe("idle");
  expect(command).toHaveBeenCalledWith(chat, {
    type: "leave",
    call_id: "test",
  });
  stopped();
  await leaving;
  calls.dispose();
});

it("keeps a transient control outage recoverable but releases capture at the deadline", async () => {
  vi.useFakeTimers();
  const { calls, command } = screenCall();
  const stop = vi.fn();
  Object.assign(calls, { capture: { getTracks: () => [{ stop }] } });
  command.mockRejectedValue(new Error("unavailable"));
  const runtime = calls as unknown as { tick(): Promise<void> };
  await runtime.tick();
  expect(calls.snapshot.phase).toBe("reconnecting");
  expect(calls.snapshot.active).toBeDefined();
  expect(stop).not.toHaveBeenCalled();
  await vi.advanceTimersByTimeAsync(1500);
  expect(
    command.mock.calls.filter(
      ([, operation]) => operation.type === "heartbeat",
    ),
  ).toHaveLength(2);
  await vi.advanceTimersByTimeAsync(23500);
  expect(calls.snapshot.active).toBeUndefined();
  expect(calls.snapshot.error).toBe("unavailable");
  expect(stop).toHaveBeenCalledOnce();
  calls.dispose();
});
it("does not retry revoked admission or let an old heartbeat fail a later session", async () => {
  const { calls, command } = screenCall();
  command.mockRejectedValueOnce(new Error("unauthorized"));
  const runtime = calls as unknown as { tick(): Promise<void> };
  await runtime.tick();
  expect(calls.snapshot.phase).toBe("idle");
  expect(calls.snapshot.error).toBe("unauthorized");
  calls.dispose();

  const next = screenCall();
  let reject!: (error: Error) => void;
  next.command.mockImplementationOnce(
    () =>
      new Promise((_resolve, fail) => {
        reject = fail;
      }),
  );
  const ticking = (next.calls as unknown as { tick(): Promise<void> }).tick();
  await next.calls.leave();
  reject(new Error("unavailable"));
  await ticking;
  expect(next.calls.snapshot.error).toBeUndefined();
  expect(next.calls.snapshot.phase).toBe("idle");
  next.calls.dispose();
});
it("cancelling the system screen picker keeps the call and microphone connected", async () => {
  const { calls, update, command } = screenCall();
  vi.stubGlobal("navigator", {
    mediaDevices: {
      getDisplayMedia: vi
        .fn()
        .mockRejectedValue(new DOMException("Cancelled", "NotAllowedError")),
    },
  });
  await calls.toggle("screen");
  expect(calls.snapshot.phase).toBe("connected");
  expect(calls.snapshot.error).toBeUndefined();
  expect(calls.localCapture()).toBeDefined();
  expect(update).not.toHaveBeenCalled();
  expect(command).not.toHaveBeenCalled();
  calls.dispose();
});
it("shares a separate screen track and immediately releases it on stop despite control failure", async () => {
  const { calls, update, command, capture } = screenCall();
  const stop = vi.fn();
  const track = {
    stop,
    readyState: "live",
    contentHint: "",
    onended: undefined,
  };
  const stream = { getTracks: () => [track], getVideoTracks: () => [track] };
  vi.stubGlobal("navigator", {
    mediaDevices: { getDisplayMedia: vi.fn().mockResolvedValue(stream) },
  });
  await calls.toggle("screen");
  expect(calls.snapshot.media.screen_published).toBe(true);
  expect(track.contentHint).toBe("detail");
  expect(update).toHaveBeenLastCalledWith(
    calls.snapshot.media,
    capture,
    stream,
  );
  command.mockRejectedValueOnce(new Error("network"));
  await calls.toggle("screen");
  expect(stop).toHaveBeenCalled();
  expect(calls.localScreen()).toBeUndefined();
  expect(calls.snapshot.media.screen_published).toBe(false);
  expect(calls.snapshot.phase).toBe("connected");
  expect(update).toHaveBeenLastCalledWith(calls.snapshot.media, capture);
  calls.dispose();
});
it("failed screen publication releases capture without ending the call", async () => {
  const { calls, update, command } = screenCall();
  const stop = vi.fn();
  const track = { stop, readyState: "live" };
  vi.stubGlobal("navigator", {
    mediaDevices: {
      getDisplayMedia: vi.fn().mockResolvedValue({
        getTracks: () => [track],
        getVideoTracks: () => [track],
      }),
    },
  });
  update.mockRejectedValueOnce(new Error("media"));
  await calls.toggle("screen");
  expect(stop).toHaveBeenCalled();
  expect(calls.localScreen()).toBeUndefined();
  expect(calls.snapshot.media.screen_published).toBe(false);
  expect(calls.snapshot.phase).toBe("connected");
  expect(calls.snapshot.error).toBe("screen_unavailable");
  expect(command).toHaveBeenLastCalledWith(chat, {
    type: "media",
    call_id: "test",
    state: calls.snapshot.media,
  });
  calls.dispose();
});

it("obtains the screen publishing grant before sending a screen track to the SFU", async () => {
  const { calls, update, command } = screenCall();
  const track = { stop: vi.fn(), readyState: "live" };
  vi.stubGlobal("navigator", {
    mediaDevices: {
      getDisplayMedia: vi.fn().mockResolvedValue({
        getTracks: () => [track],
        getVideoTracks: () => [track],
      }),
    },
  });
  let permitted = false;
  command.mockImplementation(async (_chat, operation) => {
    permitted = (operation.state as MediaState).screen_published;
    return {};
  });
  update.mockImplementation(async (state) => {
    if (state.screen_published && !permitted) throw new Error("not permitted");
  });
  await calls.toggle("screen");
  expect(calls.snapshot.media.screen_published).toBe(true);
  expect(calls.snapshot.error).toBeUndefined();
  calls.dispose();
});

it("silences muted chats and immediately dismisses a ringing call when muted or blocked", async () => {
  const calls = new Calls();
  const direct = {
    ...chat,
    chat_kind: "direct",
    members: [
      {
        identity_id: "peer",
        credential_ids: ["peer-device"],
        capabilities: ["POST"],
      },
    ],
  } as Stream;
  const directView = { ...view, streams: [direct] };
  calls.update(directView);
  const call: ActiveCall = {
    call_id: "incoming",
    scope: {
      hosting_space_id: "host",
      conversation: { space_id: "space", stream_id: "chat" },
    },
    kind: "direct",
    initial_media: "audio",
    config_id: "head",
    key_epoch: 1,
    ringing: true,
    started_by: "peer",
    started_at: 1,
    participants: {
      peer: {
        identity_id: "peer",
        credential_id: "peer-device",
        media: {
          audio_muted: false,
          video_published: false,
          screen_published: false,
        },
      },
    },
  };
  const events = calls as unknown as {
    event(event: { type: string; call: ActiveCall }): Promise<void>;
  };
  await events.event({ type: "presence", call });
  expect(calls.snapshot.incoming?.call.call_id).toBe("incoming");
  const controls = (
    calls as unknown as { connections: Map<string, { networkClosed(): void }> }
  ).connections;
  await vi.waitFor(() => expect(controls.size).toBe(1));
  controls.values().next().value!.networkClosed();
  expect(calls.snapshot.incoming).toBeUndefined();
  await events.event({ type: "presence", call });
  expect(calls.snapshot.incoming).toBeDefined();
  calls.update({ ...directView, streams: [{ ...direct, muted: true }] });
  expect(calls.snapshot.incoming).toBeUndefined();
  await events.event({ type: "presence", call });
  expect(calls.snapshot.incoming).toBeUndefined();
  expect(calls.snapshot.available["host:space:chat"]).toBeDefined();
  calls.update(directView);
  await events.event({ type: "presence", call });
  expect(calls.snapshot.incoming).toBeDefined();
  calls.update({
    ...directView,
    blocked_users: [{ identity: "peer", name: "Peer" }],
  });
  expect(calls.snapshot.incoming).toBeUndefined();
  calls.dispose();
});

it("required updates stop subscriptions and new calls without stopping active media", async () => {
  vi.useFakeTimers();
  setUpdateRequired(true);
  const calls = new Calls();
  const command = vi.fn(async () => ({ type: "result" }));
  Object.assign(calls, { command });
  calls.activate();
  calls.update(view);
  await calls.start(chat);
  expect(calls.snapshot.error).toBe("updateRequired");
  await vi.advanceTimersByTimeAsync(20000);
  expect(command).not.toHaveBeenCalled();
  calls.dispose();

  setUpdateRequired(false);
  const connected = new Calls();
  connected.activate();
  const close = vi.fn();
  const unrelatedClose = vi.fn();
  const active = { call_id: "ongoing" } as ActiveCall;
  connected.snapshot = {
    ...connected.snapshot,
    active,
    chat,
    phase: "connected",
  };
  Object.assign(connected, {
    endpoints: new Map([["host", "https://active.example"]]),
    connections: new Map([
      ["https://active.example", { close }],
      ["https://other.example", { close: unrelatedClose }],
    ]),
  });
  setUpdateRequired(true);
  expect(close).not.toHaveBeenCalled();
  expect(unrelatedClose).toHaveBeenCalledOnce();
  expect(connected.snapshot.active).toBe(active);
  connected.dispose();
});
