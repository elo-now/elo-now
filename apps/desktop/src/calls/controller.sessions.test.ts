import { afterEach, expect, it, vi } from "vitest";
import type { Stream, View } from "../model";
import type { ActiveCall, MediaState } from "./types";

const runtime = vi.hoisted(() => ({
  native: false,
  peers: [] as any[],
  groups: [] as any[],
  permission: vi.fn(async () => {}),
  activity: vi.fn(async (_state: Record<string, unknown>) => {}),
  operate: vi.fn(async (_request: Record<string, unknown>): Promise<any> => ({
    ciphertext: "sealed",
  })),
}));
vi.mock("livekit-client", () => ({ isE2EESupported: () => true }));
vi.mock("./livekit", () => ({
  GroupMedia: class {
    connect = vi.fn(async () => {});
    update = vi.fn(async () => {});
    stop = vi.fn(async () => {});
    constructor() {
      runtime.groups.push(this);
    }
  },
}));
vi.mock("./sessionActivity", () => ({ nativeCallState: runtime.activity }));
vi.mock("./control", () => ({
  operate: runtime.operate,
  requestContext: (chat: Stream, identity: string) => ({
    expected_identity: identity,
    target_space: chat.space_context,
    hosting_space_id: chat.space_context,
    space: chat.space,
    stream: chat.stream,
  }),
  Control: class {},
  callErrorCode: (error: unknown) =>
    error instanceof Error ? error.message : "unavailable",
}));
vi.mock("./nativePeer", () => ({
  usesNativePeer: () => runtime.native,
  nativeMediaPermission: runtime.permission,
  NativePeer: class {
    update = vi.fn(async () => {});
    stop = vi.fn(async () => {});
    offer = vi.fn(async () => {});
    signal = vi.fn(async () => {});
    setSpeakerMuted = vi.fn(async () => {});
    constructor(...args: unknown[]) {
      runtime.peers.push({ ...this, args, native: true });
      queueMicrotask(() => (args[4] as () => void)());
    }
  },
}));
vi.mock("./peer", () => ({
  PeerMedia: class {
    update = vi.fn(async () => {});
    stop = vi.fn(async () => {});
    offer = vi.fn(async () => {});
    signal = vi.fn(async () => {});
    constructor(...args: unknown[]) {
      runtime.peers.push({ ...this, args, native: false });
    }
  },
}));
import { Calls } from "./controller";
import { leaveBeforeLock } from "./leaveBeforeLock";

const media: MediaState = {
  audio_muted: false,
  video_published: false,
  screen_published: false,
};
const participant = (identity: string, credential: string) => ({
  identity_id: identity,
  credential_id: credential,
  media: { ...media },
});
function setup() {
  const audio = {
    stop: vi.fn(),
    enabled: true,
    kind: "audio",
    readyState: "live",
  };
  const video = {
    stop: vi.fn(),
    enabled: true,
    kind: "video",
    readyState: "live",
  };
  class Capture {
    tracks: any[] = [];
    getTracks() {
      return this.tracks;
    }
    getAudioTracks() {
      return this.tracks.filter((track) => track.kind === "audio");
    }
    getVideoTracks() {
      return this.tracks.filter((track) => track.kind === "video");
    }
    addTrack(track: any) {
      this.tracks.push(track);
    }
    removeTrack(track: any) {
      this.tracks = this.tracks.filter((item) => item !== track);
    }
  }
  const capture = new Capture();
  capture.addTrack(audio);
  const camera = new Capture();
  camera.addTrack(video);
  const getUserMedia = vi.fn(async (constraints: { audio?: unknown }) =>
    constraints.audio ? capture : camera,
  );
  vi.stubGlobal("navigator", { mediaDevices: { getUserMedia } });
  vi.stubGlobal("MediaStream", Capture);
  const chat = {
    space_context: "host",
    space: "space",
    stream: "chat",
    head: "head",
    can_post: true,
    chat_kind: "direct",
    members: [
      { identity_id: "me", credential_ids: ["a"], capabilities: ["POST"] },
      { identity_id: "peer", credential_ids: ["b"], capabilities: ["POST"] },
    ],
  } as unknown as Stream;
  let current: ActiveCall = {
    call_id: "c".repeat(32),
    kind: "direct",
    initial_media: "audio",
    config_id: "head",
    key_epoch: 1,
    started_by: "me",
    started_at: 1,
    scope: {
      hosting_space_id: "host",
      conversation: { space_id: "space", stream_id: "chat" },
    },
    participants: { me: participant("me", "a") },
  };
  const command = vi.fn(
    async (_chat: Stream, operation: Record<string, any>): Promise<any> => {
      if (operation.type === "connect_media")
        return {
          media: {
            provider: "p2p",
            ice_servers: [],
            epoch: current.key_epoch,
            url: "",
            token: "",
          },
        };
      if (operation.type === "signal") return {};
      if (operation.type === "subscribe")
        return {
          call: Object.keys(current.participants).length ? current : null,
        };
      if (operation.type === "start")
        current = { ...current, participants: { me: participant("me", "a") } };
      if (operation.type === "join")
        current = {
          ...current,
          key_epoch: current.key_epoch + 1,
          participants: { ...current.participants, me: participant("me", "a") },
        };
      if (operation.type === "media")
        current = {
          ...current,
          participants: {
            ...current.participants,
            me: { ...current.participants.me, media: operation.state },
          },
        };
      if (operation.type === "leave") {
        const { me: _me, ...participants } = current.participants;
        current = {
          ...current,
          key_epoch: current.key_epoch + 1,
          participants,
        };
        return { call: Object.keys(participants).length ? current : null };
      }
      return { call: current };
    },
  );
  const calls = new Calls();
  const view = {
    identity: "me",
    credential: "a",
    streams: [chat],
    spaces: [{ id: "host", managed: true, status: "joined" }],
  } as unknown as View;
  Object.assign(calls, { view, command });
  const controller = calls as any;
  return {
    calls,
    chat,
    command,
    capture,
    audio,
    video,
    getUserMedia,
    controller,
    current: () => current,
    presence: async (participants: ActiveCall["participants"]) => {
      current = { ...current, key_epoch: current.key_epoch + 1, participants };
      await controller.presence(current);
    },
  };
}
afterEach(() => {
  runtime.native = false;
  runtime.peers = [];
  runtime.groups = [];
  runtime.permission.mockClear();
  runtime.activity.mockReset();
  runtime.activity.mockResolvedValue();
  runtime.operate.mockReset();
  runtime.operate.mockResolvedValue({ ciphertext: "sealed" });
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

it("releases capture immediately and locks within 400ms when signed Leave cannot reach the network", async () => {
  const f = setup();
  await f.calls.start(f.chat);
  await vi.waitFor(() => expect(f.calls.snapshot.phase).toBe("connected"));
  vi.useFakeTimers();
  let respond!: (result: unknown) => void;
  f.command.mockImplementationOnce(
    () =>
      new Promise((resolve) => {
        respond = resolve;
      }),
  );
  const lock = vi.fn(async () => {
    f.calls.update(null);
  });
  const locking = leaveBeforeLock(f.calls, lock);
  expect(f.audio.stop).toHaveBeenCalledOnce();
  expect(f.calls.snapshot.active).toBeUndefined();
  expect(f.command).toHaveBeenLastCalledWith(f.chat, {
    type: "leave",
    call_id: f.current().call_id,
  });
  await vi.advanceTimersByTimeAsync(399);
  expect(lock).not.toHaveBeenCalled();
  await vi.advanceTimersByTimeAsync(1);
  await locking;
  expect(lock).toHaveBeenCalledOnce();
  respond({ call: f.current() });
  await vi.advanceTimersByTimeAsync(0);
  expect(f.calls.snapshot.active).toBeUndefined();
  expect(f.calls.snapshot.available).toEqual({});
  f.calls.dispose();
});

it("discovers a session in its chat without joining or acquiring media", async () => {
  const f = setup();
  await f.presence({ peer: participant("peer", "b") });
  expect(f.calls.snapshot.available["host:space:chat"]).toBe(f.current());
  expect(f.calls.snapshot.active).toBeUndefined();
  expect(f.calls.snapshot.phase).toBe("idle");
  expect(f.getUserMedia).not.toHaveBeenCalled();
  expect(runtime.activity).not.toHaveBeenCalled();
  expect(f.command).not.toHaveBeenCalled();
  f.calls.dispose();
});

it("starts audio only and remains connected alone until explicitly leaving", async () => {
  const f = setup();
  await f.calls.start(f.chat);
  await vi.waitFor(() => expect(f.calls.snapshot.phase).toBe("connected"));
  expect(f.getUserMedia).toHaveBeenCalledExactlyOnceWith({
    audio: { echoCancellation: true, noiseSuppression: true },
    video: false,
  });
  expect(f.command).toHaveBeenCalledWith(f.chat, {
    type: "start",
    kind: "direct",
    initial_media: "audio",
  });
  expect(f.calls.localCapture()).toBe(f.capture);
  expect(runtime.peers).toHaveLength(0);
  await f.controller.tick();
  expect(f.calls.snapshot.phase).toBe("connected");
  expect(f.audio.stop).not.toHaveBeenCalled();
  await f.calls.leave();
  expect(f.calls.snapshot.available["host:space:chat"]).toBeUndefined();
  expect(f.audio.stop).toHaveBeenCalledOnce();
  expect(runtime.activity.mock.calls.map(([state]) => state.active)).toEqual([
    true,
    false,
  ]);
  expect(runtime.activity.mock.calls[0][0]).toMatchObject({
    identity: "me",
    sessionId: f.current().call_id,
    camera: false,
    context: {
      expected_identity: "me",
      target_space: "host",
      space: "space",
      stream: "chat",
    },
  });
  f.calls.dispose();
});

it("joins explicitly, keeps camera and capture when the peer leaves, and negotiates again on rejoin", async () => {
  const f = setup();
  await f.presence({ peer: participant("peer", "b") });
  await f.calls.start(f.chat, f.current());
  await vi.waitFor(() => expect(runtime.peers).toHaveLength(1));
  expect(f.command).toHaveBeenCalledWith(f.chat, {
    type: "join",
    call_id: f.current().call_id,
  });
  expect(f.calls.snapshot.media.video_published).toBe(false);
  await f.calls.toggle("video");
  expect(f.calls.snapshot.media.video_published).toBe(true);
  await f.presence({ me: f.current().participants.me });
  await vi.waitFor(() => expect(f.calls.snapshot.phase).toBe("connected"));
  expect(runtime.peers[0].stop).toHaveBeenCalledOnce();
  expect(f.calls.localCapture()).toBe(f.capture);
  expect(f.audio.stop).not.toHaveBeenCalled();
  expect(f.video.stop).not.toHaveBeenCalled();
  expect(f.calls.snapshot.media.video_published).toBe(true);
  await f.presence({
    me: f.current().participants.me,
    peer: participant("peer", "b"),
  });
  await vi.waitFor(() => expect(runtime.peers).toHaveLength(2));
  expect(runtime.peers[1].update).toHaveBeenCalledWith(
    f.calls.snapshot.media,
    f.capture,
    undefined,
  );
  await f.calls.leave();
  expect(f.calls.snapshot.available["host:space:chat"]?.participants).toEqual({
    peer: participant("peer", "b"),
  });
  f.calls.dispose();
});

it("keeps native capture and signaling ownership across solo and joined epochs", async () => {
  runtime.native = true;
  const f = setup();
  await f.calls.start(f.chat);
  await vi.waitFor(() => expect(f.calls.snapshot.phase).toBe("connected"));
  expect(runtime.permission).toHaveBeenCalledExactlyOnceWith("me", false);
  expect(f.getUserMedia).not.toHaveBeenCalled();
  expect(runtime.peers[0].args[0]).toBe("a");
  expect(runtime.peers[0].args[7]).toMatchObject({
    call_id: f.current().call_id,
  });
  expect(runtime.peers[0].offer).not.toHaveBeenCalled();
  await f.calls.toggle("video");
  expect(runtime.peers[0].update).toHaveBeenLastCalledWith(
    { ...media, video_published: true },
    f.calls.localCapture(),
    undefined,
  );
  await f.presence({
    me: f.current().participants.me,
    peer: participant("peer", "b"),
  });
  await f.presence({ me: f.current().participants.me });
  expect(runtime.peers).toHaveLength(1);
  expect(runtime.peers[0].stop).not.toHaveBeenCalled();
  expect(
    f.command.mock.calls.some(
      ([, command]) =>
        command.type === "connect_media" || command.type === "signal",
    ),
  ).toBe(false);
  runtime.operate.mockClear();
  await f.controller.signal({
    call_id: f.current().call_id,
    from: "b",
    epoch: f.current().key_epoch,
  });
  expect(runtime.operate).not.toHaveBeenCalled();
  await f.calls.leave();
  f.calls.dispose();
});

it("serializes a pending native activation before its cancellation", async () => {
  const f = setup();
  let resolve!: () => void;
  runtime.activity.mockImplementationOnce(
    () => new Promise<void>((done) => (resolve = done)),
  );
  const starting = f.calls.start(f.chat);
  await vi.waitFor(() => expect(runtime.activity).toHaveBeenCalledOnce());
  const leaving = f.calls.leave();
  expect(f.calls.snapshot.phase).toBe("idle");
  resolve();
  await Promise.all([starting, leaving]);
  expect(runtime.activity.mock.calls.map(([state]) => state.active)).toEqual([
    true,
    false,
  ]);
  expect(f.calls.snapshot.active).toBeUndefined();
  expect(runtime.peers).toHaveLength(0);
  f.calls.dispose();
});

it("waits for initial microphone admission before opening media from an early presence", async () => {
  const f = setup();
  f.chat.chat_kind = "chat";
  f.current().kind = "group";
  const original = f.command.getMockImplementation()!;
  const admission: boolean[] = [];
  f.command.mockImplementation(async (chat, operation) => {
    const result = await original(chat, operation);
    if (operation.type === "start")
      result.call.participants.me.media.audio_muted = true;
    if (operation.type === "connect_media")
      admission.push(!f.current().participants.me.media.audio_muted);
    return result;
  });
  let activate!: () => void;
  runtime.activity.mockImplementationOnce(
    () => new Promise<void>((resolve) => (activate = resolve)),
  );
  const starting = f.calls.start(f.chat);
  await vi.waitFor(() => expect(runtime.activity).toHaveBeenCalledOnce());
  // The server echoes Start while iOS is still activating its audio session.
  await f.controller.presence(f.current());
  await new Promise<void>((resolve) => setTimeout(resolve, 0));
  const beforeActivation = f.command.mock.calls.map(([, op]) => op.type);
  activate();
  await starting;
  await vi.waitFor(() => expect(f.calls.snapshot.phase).toBe("connected"));
  const operations = f.command.mock.calls.map(([, op]) => op.type);
  f.calls.dispose();
  expect(beforeActivation).toEqual(["start"]);
  expect(operations).toEqual(["start", "media", "connect_media"]);
  expect(admission).toEqual([true]);
});

it("uses the latest membership when initial media admission returns an older epoch", async () => {
  const f = setup();
  f.chat.chat_kind = "chat";
  f.current().kind = "group";
  const original = f.command.getMockImplementation()!;
  f.command.mockImplementation(async (chat, operation) => {
    const result = await original(chat, operation);
    if (operation.type === "media")
      await f.presence({
        me: f.current().participants.me,
        peer: participant("peer", "b"),
      });
    return result;
  });
  await f.calls.start(f.chat);
  await vi.waitFor(() => expect(f.calls.snapshot.phase).toBe("connected"));
  expect(runtime.groups).toHaveLength(1);
  expect(runtime.groups[0].connect.mock.calls[0][0].epoch).toBe(2);
  expect(f.calls.snapshot.active?.key_epoch).toBe(2);
  f.calls.dispose();
});

it("does not open media when the initial microphone admission is rejected", async () => {
  const f = setup();
  f.chat.chat_kind = "chat";
  f.current().kind = "group";
  const original = f.command.getMockImplementation()!;
  f.command.mockImplementation(async (chat, operation) => {
    if (operation.type === "media") {
      await f.controller.presence(f.current());
      throw new Error("unauthorized");
    }
    return original(chat, operation);
  });
  await f.calls.start(f.chat);
  expect(runtime.groups).toHaveLength(0);
  expect(f.command.mock.calls.map(([, op]) => op.type)).toEqual([
    "start",
    "media",
    "leave",
  ]);
  expect(f.calls.snapshot.phase).toBe("idle");
  expect(f.calls.snapshot.error).toBe("unauthorized");
  expect(f.calls.localCapture()).toBeUndefined();
  expect(f.audio.stop).toHaveBeenCalled();
  f.calls.dispose();
});

it("rejects old membership signals before decryption and validates the signed epoch", async () => {
  const f = setup();
  await f.presence({ peer: participant("peer", "b") });
  await f.calls.start(f.chat, f.current());
  await vi.waitFor(() => expect(runtime.peers).toHaveLength(1));
  runtime.operate.mockClear();
  const epoch = f.current().key_epoch;
  const event = {
    type: "signal",
    call_id: f.current().call_id,
    from: "b",
    epoch,
    ciphertext: "sealed",
  };
  await f.controller.signal({ ...event, epoch: epoch - 1 });
  expect(runtime.operate).not.toHaveBeenCalled();
  const signal = {
    from: "b",
    to: "a",
    config_id: "head",
    epoch: epoch - 1,
    nonce: "nonce",
    payload: { type: "answer", sdp: "session" },
  };
  runtime.operate.mockResolvedValue({ signal });
  await f.controller.signal(event);
  expect(runtime.peers[0].signal).not.toHaveBeenCalled();
  runtime.operate.mockResolvedValue({ signal: { ...signal, epoch } });
  await f.controller.signal(event);
  expect(runtime.operate).toHaveBeenLastCalledWith(
    expect.objectContaining({ op: "call_open_signal", epoch }),
  );
  expect(runtime.peers[0].signal).toHaveBeenCalledExactlyOnceWith(
    signal.payload,
  );
  runtime.operate.mockResolvedValue({ ciphertext: "sealed" });
  await f.controller.sendSignal("b", { type: "request_offer" });
  expect(runtime.operate).toHaveBeenLastCalledWith(
    expect.objectContaining({ op: "call_encrypt_signal", epoch }),
  );
  expect(f.command).toHaveBeenLastCalledWith(
    f.chat,
    expect.objectContaining({ type: "signal", epoch }),
  );
  f.calls.dispose();
});

it("ignores an old native end event after rejoining the same ongoing session", async () => {
  const f = setup();
  await f.calls.start(f.chat);
  const first = runtime.activity.mock.calls[0][0];
  await f.presence({
    me: f.current().participants.me,
    peer: participant("peer", "b"),
  });
  await f.calls.leave();
  await f.calls.start(f.chat, f.current());
  const second = runtime.activity.mock.calls
    .filter(([state]) => state.active)
    .at(-1)![0];
  expect(first.sessionId).toBe(second.sessionId);
  expect(first.activation).not.toBe(second.activation);
  await f.calls.nativeSessionEnded(
    first.sessionId as string,
    first.activation as string,
  );
  expect(f.calls.snapshot.active?.call_id).toBe(second.sessionId);
  expect(
    runtime.activity.mock.calls.filter(([state]) => !state.active),
  ).toHaveLength(1);
  await f.calls.nativeSessionEnded(
    second.sessionId as string,
    second.activation as string,
  );
  expect(f.calls.snapshot.active).toBeUndefined();
  expect(runtime.activity.mock.lastCall?.[0]).toMatchObject({
    active: false,
    activation: second.activation,
  });
  f.calls.dispose();
});

it("waits for pending Leave before refreshing and rejoining the same session", async () => {
  const f = setup();
  await f.calls.start(f.chat);
  await f.presence({
    me: f.current().participants.me,
    peer: participant("peer", "b"),
  });
  const original = f.command.getMockImplementation()!;
  let release!: () => void;
  f.command.mockImplementationOnce(async (chat, operation) => {
    await new Promise<void>((resolve) => {
      release = resolve;
    });
    return original(chat, operation);
  });
  f.command.mockClear();
  const leaving = f.calls.leave();
  const joining = f.calls.start(f.chat, f.current());
  await Promise.resolve();
  expect(f.audio.stop).toHaveBeenCalled();
  expect(f.command.mock.calls.map(([, operation]) => operation.type)).toEqual([
    "leave",
  ]);
  release();
  await Promise.all([leaving, joining]);
  expect(
    f.command.mock.calls.slice(0, 4).map(([, operation]) => operation.type),
  ).toEqual(["leave", "subscribe", "join", "media"]);
  expect(f.calls.snapshot.active?.participants.me).toBeDefined();
  f.calls.dispose();
});

it("rejoins after reporting a media teardown failure without retaining capture", async () => {
  const f = setup();
  await f.presence({ peer: participant("peer", "b") });
  await f.calls.start(f.chat, f.current());
  await vi.waitFor(() => expect(runtime.peers).toHaveLength(1));
  runtime.peers[0].args[5]();
  expect(f.calls.snapshot.phase).toBe("connected");
  const failure = new Error("media teardown failed");
  runtime.peers[0].stop.mockRejectedValueOnce(failure);

  await expect(f.calls.leave()).rejects.toBe(failure);
  expect(f.audio.stop).toHaveBeenCalled();
  expect(f.calls.localCapture()).toBeUndefined();
  expect(f.calls.snapshot.active).toBeUndefined();
  expect(f.calls.snapshot.phase).toBe("idle");

  f.command.mockClear();
  await f.calls.start(f.chat, f.current());
  await vi.waitFor(() => expect(runtime.peers).toHaveLength(2));
  runtime.peers[1].args[5]();
  expect(f.calls.snapshot.phase).toBe("connected");
  expect(f.calls.snapshot.error).toBeUndefined();
  expect(
    f.command.mock.calls.slice(0, 3).map(([, operation]) => operation.type),
  ).toEqual(["subscribe", "join", "media"]);
  f.calls.dispose();
});

it("waits for earlier teardown before reporting a later teardown failure", async () => {
  const f = setup();
  let finish!: () => void;
  f.controller.adapter = {
    stop: () => new Promise<void>((resolve) => (finish = resolve)),
  };
  const first = f.controller.stopMedia();
  const failure = new Error("later media teardown failed");
  f.controller.adapter = {
    stop: async () => {
      throw failure;
    },
  };
  const second = f.controller.stopMedia();
  const rejected = expect(second).rejects.toBe(failure);
  const settled = vi.fn();
  void second.then(settled, settled);
  const recovered = f.controller.stopMedia();
  const recoveredResult = expect(recovered).resolves.toBeUndefined();
  void recovered.then(settled, settled);
  for (let turn = 0; turn < 10; turn++) await Promise.resolve();
  expect(settled).not.toHaveBeenCalled();

  finish();
  await first;
  await rejected;
  await recoveredResult;
  f.calls.dispose();
});

it("finishes cleanup of a cancelled server Start before starting again", async () => {
  const f = setup();
  const original = f.command.getMockImplementation()!;
  let release!: () => void;
  f.command.mockImplementationOnce(async (chat, operation) => {
    await new Promise<void>((resolve) => {
      release = resolve;
    });
    return original(chat, operation);
  });
  const first = f.calls.start(f.chat);
  await vi.waitFor(() => expect(f.command).toHaveBeenCalledOnce());
  await f.calls.leave();
  const second = f.calls.start(f.chat);
  await Promise.resolve();
  expect(f.command).toHaveBeenCalledOnce();
  release();
  await Promise.all([first, second]);
  expect(f.command.mock.calls.map(([, operation]) => operation.type)).toEqual([
    "start",
    "leave",
    "subscribe",
    "start",
    "media",
  ]);
  expect(f.calls.snapshot.active?.participants.me).toBeDefined();
  f.calls.dispose();
});
