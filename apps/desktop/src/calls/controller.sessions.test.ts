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
    detach = vi.fn();
    setParticipantMuted = vi.fn(async () => {});
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
  ready: true,
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
    name: "General",
    member_names: { peer: "Alex" },
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
    ready: true,
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
        current = {
          ...current,
          ready: false,
          participants: { me: { ...participant("me", "a"), ready: false } },
        };
      if (operation.type === "join")
        current = {
          ...current,
          key_epoch: current.key_epoch + 1,
          participants: { ...current.participants, me: participant("me", "a") },
        };
      if (operation.type === "media")
        current = {
          ...current,
          ready: true,
          participants: {
            ...current.participants,
            me: {
              ...current.participants.me,
              ready: true,
              media: operation.state,
            },
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
    spaces: [{ id: "host", name: "Friends", managed: true, status: "joined" }],
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
  await vi.waitFor(() => expect(f.calls.snapshot.phase).toBe("connecting"));
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

it("starts audio only and waits for the recipient without claiming a connection", async () => {
  const f = setup();
  await f.calls.start(f.chat);
  await vi.waitFor(() => expect(f.calls.snapshot.phase).toBe("connecting"));
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
  expect(f.calls.snapshot.phase).toBe("connecting");
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

it("marks a direct call connected only after the remote media transport connects", async () => {
  const f = setup();
  await f.calls.start(f.chat);
  expect(f.current().ready).toBe(true);
  expect(f.calls.snapshot.phase).toBe("connecting");
  await f.presence({
    me: f.current().participants.me,
    peer: participant("peer", "b"),
  });
  await vi.waitFor(() => expect(runtime.peers).toHaveLength(1));
  expect(f.calls.snapshot.phase).toBe("connecting");
  runtime.peers[0].args[5]();
  expect(f.calls.snapshot.phase).toBe("connected");
  await f.calls.leave();
  f.calls.dispose();
});

it("releases a waiting direct call when the control service reports it unanswered", async () => {
  const f = setup();
  await f.calls.start(f.chat);
  expect(f.calls.snapshot.phase).toBe("connecting");
  await f.controller.event({
    type: "ended",
    call_id: f.current().call_id,
    scope: f.current().scope,
    reason: "unanswered",
  });
  await vi.waitFor(() => expect(f.calls.snapshot.phase).toBe("idle"));
  expect(f.calls.snapshot.active).toBeUndefined();
  expect(f.audio.stop).toHaveBeenCalled();
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
  await vi.waitFor(() => expect(f.calls.snapshot.phase).toBe("connecting"));
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
  expect(
    runtime.operate.mock.calls.some(
      ([request]) => request.op === "call_notify_ready",
    ),
  ).toBe(false);
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

it("keeps a successor session active when an old mute command fails late", async () => {
  const f = setup();
  await f.calls.start(f.chat);
  let rejectMute!: (reason: Error) => void;
  f.controller.adapter = {
    stop: async () => {},
    setSpeakerMuted: () =>
      new Promise<void>((_, reject) => {
        rejectMute = reject;
      }),
  };
  const muting = f.calls.setSpeakerMuted(true);
  await f.calls.leave();
  await f.calls.start(f.chat);
  const active = f.calls.snapshot.active;
  rejectMute(new Error("ended"));
  await muting;
  expect(f.calls.snapshot.active).toBe(active);
  expect(f.calls.snapshot.error).toBeUndefined();
  expect(f.controller.speakerMuted).toBe(false);
  f.calls.dispose();
});

it("reports local playback failure without changing microphone state or ending the session", async () => {
  const f = setup();
  await f.calls.start(f.chat);
  const active = f.calls.snapshot.active;
  f.controller.adapter = {
    stop: async () => {},
    setSpeakerMuted: async () => {
      throw new Error("route changed");
    },
  };
  expect(await f.calls.setSpeakerMuted(true)).toBe(false);
  expect(f.calls.snapshot.active).toBe(active);
  expect(f.calls.snapshot.media.audio_muted).toBe(false);
  expect(f.calls.snapshot.error).toBe("audio_unavailable");
  expect(f.controller.speakerMuted).toBe(false);
  f.calls.dispose();
});

it("announces only a newly ready session once without acquiring media", async () => {
  const f = setup();
  const listener = vi.fn();
  f.calls.subscribeSessionStarted(listener);
  f.controller.subscribed.set("host:space:chat", "head");
  const call = {
    ...f.current(),
    started_by: "peer",
    participants: { peer: participant("peer", "b") },
  };
  await f.controller.event({
    type: "presence",
    call: {
      ...call,
      ready: false,
      participants: { peer: { ...call.participants.peer, ready: false } },
    },
  });
  expect(f.calls.snapshot.available).toEqual({});
  expect(listener).not.toHaveBeenCalled();
  await f.controller.event({ type: "presence", call });
  await f.controller.event({ type: "presence", call });
  expect(listener).toHaveBeenCalledExactlyOnceWith(
    expect.objectContaining({
      call,
      spaceName: "Friends",
      starterName: "Alex",
      participantNames: ["Alex"],
    }),
  );
  expect(f.getUserMedia).not.toHaveBeenCalled();
  expect(runtime.activity).not.toHaveBeenCalled();
  f.calls.dispose();
});

it("suppresses old snapshots, own starts, and muted sessions even after repeats", async () => {
  const f = setup();
  const listener = vi.fn();
  f.calls.subscribeSessionStarted(listener);
  f.current().started_by = "peer";
  await f.controller.subscribeChats();
  await f.controller.event({ type: "presence", call: f.current() });
  const own = { ...f.current(), call_id: "own", started_by: "me" };
  await f.controller.event({ type: "presence", call: own });
  f.chat.muted = true;
  const mutedCall = { ...f.current(), call_id: "muted" };
  await f.controller.event({ type: "presence", call: mutedCall });
  f.chat.muted = false;
  await f.controller.event({ type: "presence", call: mutedCall });
  expect(listener).not.toHaveBeenCalled();
  expect(Object.values(f.calls.snapshot.available)).toEqual([mutedCall]);
  f.calls.dispose();
});

it("announces a recent session when a new empty DM is discovered during this unlock", async () => {
  const f = setup();
  const listener = vi.fn();
  f.calls.subscribeSessionStarted(listener);
  f.chat.created_at = Date.now();
  f.current().ready_at = Math.floor(Date.now() / 1000);
  f.current().started_by = "peer";
  const original = f.command.getMockImplementation()!;
  f.command.mockImplementation(async (chat, operation) => {
    if (operation.type === "subscribe")
      await f.controller.event({ type: "presence", call: f.current() });
    return original(chat, operation);
  });
  await f.controller.subscribeChats();
  await f.controller.event({ type: "presence", call: f.current() });
  expect(listener).toHaveBeenCalledOnce();
  expect(f.getUserMedia).not.toHaveBeenCalled();
  expect(runtime.activity).not.toHaveBeenCalled();
  expect(f.calls.snapshot.phase).toBe("idle");
  f.calls.dispose();
});

it("keeps pre-existing DMs and stale session discoveries silent at first subscription", async () => {
  for (const [created, ready] of [
    [-1000, 0],
    [0, -61_000],
    [0, 1000],
  ]) {
    const f = setup();
    const listener = vi.fn();
    f.calls.subscribeSessionStarted(listener);
    f.chat.created_at = f.controller.sessionDiscoverySince + created;
    f.current().ready_at = Math.floor((Date.now() + ready) / 1000);
    f.current().started_by = "peer";
    await f.controller.subscribeChats();
    await f.controller.event({ type: "presence", call: f.current() });
    expect(listener).not.toHaveBeenCalled();
    expect(Object.values(f.calls.snapshot.available)).toEqual([f.current()]);
    f.calls.dispose();
  }
});

it("cannot revive an ended or revoked session with a queued presence", async () => {
  const f = setup();
  f.controller.subscribed.set("host:space:chat", "head");
  const listener = vi.fn();
  f.calls.subscribeSessionStarted(listener);
  const call = { ...f.current(), started_by: "peer" };
  await f.controller.event({
    type: "ended",
    call_id: call.call_id,
    scope: call.scope,
  });
  await f.controller.event({ type: "presence", call });
  expect(f.calls.snapshot.available).toEqual({});
  const next = { ...call, call_id: "next" };
  await f.controller.event({ type: "presence", call: next });
  expect(listener).toHaveBeenCalledOnce();
  await f.controller.event({ type: "access_revoked", scope: call.scope });
  await f.controller.event({ type: "presence", call: next });
  expect(f.calls.snapshot.available).toEqual({});
  expect(listener).toHaveBeenCalledOnce();
  f.calls.dispose();
});

it("notifies after microphone admission and keeps a session when push delivery fails", async () => {
  const f = setup();
  const diagnostic = vi.spyOn(console, "warn").mockImplementation(() => {});
  const original = f.command.getMockImplementation()!;
  f.command.mockImplementation(async (chat, operation) => {
    if (operation.type === "media")
      expect(runtime.operate).not.toHaveBeenCalled();
    return original(chat, operation);
  });
  runtime.operate.mockRejectedValue(new Error("unavailable"));
  await f.calls.start(f.chat);
  await vi.waitFor(() => expect(f.calls.snapshot.phase).toBe("connecting"));
  expect(runtime.operate).toHaveBeenCalledExactlyOnceWith({
    expected_identity: "me",
    target_space: "host",
    hosting_space_id: "host",
    space: "space",
    stream: "chat",
    op: "call_notify_ready",
    call_id: f.current().call_id,
  });
  expect(f.calls.snapshot.error).toBeUndefined();
  expect(f.audio.stop).not.toHaveBeenCalled();
  expect(diagnostic).toHaveBeenCalledWith(
    "Session notification handoff failed.",
    "unavailable",
  );
  await f.calls.leave();
  diagnostic.mockRestore();
  f.calls.dispose();
});

it("retries a failed session notification without changing media and stops after success", async () => {
  vi.useFakeTimers();
  const f = setup();
  const diagnostic = vi.spyOn(console, "warn").mockImplementation(() => {});
  runtime.operate
    .mockRejectedValueOnce(new Error("unavailable"))
    .mockResolvedValueOnce({ notified: true });
  await f.calls.start(f.chat);
  await vi.advanceTimersByTimeAsync(7999);
  expect(runtime.operate).toHaveBeenCalledTimes(1);
  await vi.advanceTimersByTimeAsync(1);
  expect(runtime.operate).toHaveBeenCalledTimes(2);
  await vi.advanceTimersByTimeAsync(60_000);
  expect(runtime.operate).toHaveBeenCalledTimes(2);
  expect(f.calls.snapshot.phase).toBe("connecting");
  expect(f.audio.stop).not.toHaveBeenCalled();
  await f.calls.leave();
  diagnostic.mockRestore();
  f.calls.dispose();
});

it("retries opaque acknowledgements long enough for a newly discovered DM scope", async () => {
  vi.useFakeTimers();
  const f = setup();
  runtime.operate.mockResolvedValue({ notified: true, retry: true });
  await f.calls.start(f.chat);
  await vi.advanceTimersByTimeAsync(35_000);
  expect(runtime.operate).toHaveBeenCalledTimes(5);
  expect(
    runtime.operate.mock.calls.every(
      ([request]) =>
        request.call_id === f.current().call_id &&
        request.target_space === "host",
    ),
  ).toBe(true);
  await vi.advanceTimersByTimeAsync(25_000);
  expect(runtime.operate).toHaveBeenCalledTimes(8);
  await vi.advanceTimersByTimeAsync(60_000);
  expect(runtime.operate).toHaveBeenCalledTimes(8);
  expect(f.calls.snapshot.phase).toBe("connecting");
  await f.calls.leave();
  f.calls.dispose();
});

it("bounds notification retries and cancels them when leaving or locking", async () => {
  vi.useFakeTimers();
  const f = setup();
  const diagnostic = vi.spyOn(console, "warn").mockImplementation(() => {});
  runtime.operate.mockRejectedValue(new Error("unavailable"));
  await f.calls.start(f.chat);
  await vi.advanceTimersByTimeAsync(60_000);
  expect(runtime.operate).toHaveBeenCalledTimes(8);
  expect(f.calls.snapshot.phase).toBe("connecting");
  await f.calls.leave();
  runtime.operate.mockClear();
  await f.calls.start(f.chat);
  expect(runtime.operate).toHaveBeenCalledTimes(1);
  f.calls.update(null);
  await vi.advanceTimersByTimeAsync(60_000);
  expect(runtime.operate).toHaveBeenCalledTimes(1);
  expect(f.calls.snapshot.active).toBeUndefined();
  diagnostic.mockRestore();
  f.calls.dispose();
});

it("does not send a session start notification for an explicit Join", async () => {
  const f = setup();
  await f.calls.start(f.chat, f.current());
  await vi.waitFor(() => expect(f.calls.snapshot.phase).toBe("connecting"));
  expect(
    runtime.operate.mock.calls.some(
      ([request]) => request.op === "call_notify_ready",
    ),
  ).toBe(false);
  f.calls.dispose();
});

function invited(f: ReturnType<typeof setup>, id = "attempt") {
  return {
    ...f.current(),
    phase: "ringing" as const,
    started_by: "peer",
    participants: { peer: participant("peer", "b") },
    invitations: {
      me: {
        invitation_id: id,
        invited_by: "peer",
        expires_at: Math.floor(Date.now() / 1000) + 60,
      },
    },
  };
}

it("rings only a fresh targeted invitation and expires it without acquiring media", async () => {
  vi.useFakeTimers();
  const f = setup();
  f.controller.subscribed.set("host:space:chat", "head");
  const old = invited(f, "old");
  await f.controller.presence(old, false);
  expect(f.calls.snapshot.incoming).toEqual([]);
  await f.controller.event({ type: "presence", call: old });
  expect(f.calls.snapshot.incoming).toEqual([]);
  const fresh = { ...invited(f, "fresh"), call_id: "new-call" };
  await f.controller.event({ type: "presence", call: fresh });
  expect(f.calls.snapshot.incoming).toEqual([fresh]);
  expect(f.getUserMedia).not.toHaveBeenCalled();
  await vi.advanceTimersByTimeAsync(60_001);
  expect(f.calls.snapshot.incoming).toEqual([]);
  f.calls.dispose();
});

it("does not ring a group start and accepts a new explicit invitation after dismissal", async () => {
  const f = setup();
  f.chat.chat_kind = "chat";
  f.controller.subscribed.set("host:space:chat", "head");
  const group = {
    ...invited(f),
    kind: "group" as const,
    phase: "active" as const,
    invitations: {},
  };
  await f.controller.event({ type: "presence", call: group });
  expect(f.calls.snapshot.incoming).toEqual([]);
  const ring = { ...group, invitations: invited(f).invitations };
  await f.controller.event({ type: "presence", call: ring });
  expect(f.calls.snapshot.incoming).toEqual([ring]);
  await f.calls.decline(ring);
  expect(f.command).toHaveBeenCalledWith(f.chat, {
    type: "decline",
    call_id: ring.call_id,
    invitation_id: "attempt",
  });
  expect(f.calls.snapshot.dismissed).toContain(
    `host:space:chat:${ring.call_id}`,
  );
  await f.controller.event({ type: "presence", call: ring });
  expect(f.calls.snapshot.incoming).toEqual([]);
  const again = { ...ring, invitations: invited(f, "attempt-2").invitations };
  await f.controller.event({ type: "presence", call: again });
  expect(f.calls.snapshot.incoming).toEqual([again]);
  expect(f.getUserMedia).not.toHaveBeenCalled();
  f.calls.dispose();
});

it("rejects a stale Answer before leaving the current session", async () => {
  const f = setup();
  await f.calls.start(f.chat);
  const original = f.calls.snapshot.active;
  const next = { ...invited(f, "first"), call_id: "another-call" };
  f.command.mockResolvedValueOnce({
    call: { ...next, invitations: invited(f, "second").invitations },
  });
  f.command.mockClear();
  await f.calls.answer(f.chat, next, true, "first");
  expect(f.calls.snapshot.active).toBe(original);
  expect(f.audio.stop).not.toHaveBeenCalled();
  expect(f.command.mock.calls.map(([, operation]) => operation.type)).toEqual([
    "subscribe",
  ]);
  f.calls.dispose();
});

it("requires explicit switching and validates a session before ending the current one", async () => {
  const f = setup();
  await f.calls.start(f.chat);
  const original = f.calls.snapshot.active!;
  const next = { ...invited(f), call_id: "another-call" };
  f.calls.requestStart(f.chat, next);
  expect(f.calls.snapshot.joinRequest?.call).toBe(next);
  expect(f.calls.snapshot.active).toBe(original);
  expect(f.audio.stop).not.toHaveBeenCalled();
  f.calls.cancelJoin();
  f.calls.requestStart(f.chat, original);
  expect(f.calls.snapshot.expanded).toBe(true);
  const start = vi.spyOn(f.calls, "start").mockResolvedValueOnce();
  f.command.mockResolvedValueOnce({ call: next });
  await f.calls.answer(f.chat, next, true, "attempt");
  expect(f.audio.stop).toHaveBeenCalled();
  expect(start).toHaveBeenCalledWith(f.chat, next, "attempt");
  f.calls.dispose();
});

it("declining an incoming call does not stop an unrelated active session", async () => {
  const f = setup();
  await f.calls.start(f.chat);
  const original = f.calls.snapshot.active!;
  const ring = { ...invited(f), call_id: "another-call" };
  f.command.mockResolvedValueOnce({});
  await f.calls.decline(ring);
  expect(f.calls.snapshot.active).toBe(original);
  expect(f.audio.stop).not.toHaveBeenCalled();
  expect(f.command).toHaveBeenLastCalledWith(f.chat, {
    type: "decline",
    call_id: ring.call_id,
    invitation_id: "attempt",
  });
  f.calls.dispose();
});

it("adopts only a current native call for this profile without duplicate media admission", async () => {
  const f = setup();
  runtime.native = true;
  const native = {
    identity: "me",
    call: f.current(),
    session_id: "12345678-1234-1234-1234-123456789abc",
    activation: "12345678-1234-1234-1234-123456789def",
    media,
  };
  expect(await f.calls.adoptNative({ ...native, identity: "other" })).toBe(
    false,
  );
  expect(
    await f.calls.adoptNative({
      ...native,
      call: { ...native.call, config_id: "old-head" },
    }),
  ).toBe(false);
  expect(await f.calls.adoptNative(native)).toBe(true);
  expect(runtime.peers).toHaveLength(1);
  expect(runtime.peers[0].args[8]).toEqual({ sessionId: native.session_id });
  expect(f.calls.snapshot.active?.call_id).toBe(native.call.call_id);
  expect(f.command).not.toHaveBeenCalled();
  expect(runtime.permission).not.toHaveBeenCalled();
  expect(f.getUserMedia).not.toHaveBeenCalled();
  expect(
    await f.calls.adoptNative({
      ...native,
      session_id: "12345678-1234-1234-1234-123456789aaa",
    }),
  ).toBe(false);
  const stop = runtime.peers[0].stop;
  const detach = runtime.peers[0].detach;
  f.calls.update(null);
  expect(detach).toHaveBeenCalledOnce();
  expect(stop).not.toHaveBeenCalled();
  expect(f.command).not.toHaveBeenCalled();
  expect(f.calls.snapshot.active).toBeUndefined();
  f.calls.dispose();
});

it("ignores native actions from an old invitation attempt or activation", async () => {
  const f = setup();
  await f.calls.start(f.chat);
  const original = f.calls.snapshot.active;
  const event = {
    action: "answer" as const,
    call_id: "another-call",
    hosting_space_id: "host",
    space: "space",
    stream: "chat",
    invitation_id: "old",
  };
  f.command.mockResolvedValueOnce({
    call: { ...invited(f, "new"), call_id: event.call_id },
  });
  await f.calls.handleNativeAction(event);
  expect(f.calls.snapshot.incoming ?? []).toEqual([]);
  expect(f.calls.snapshot.active).toBe(original);
  await f.calls.handleNativeAction({
    ...event,
    action: "end",
    call_id: original!.call_id,
    activation: "stale",
  });
  expect(f.audio.stop).not.toHaveBeenCalled();
  f.calls.dispose();
});

it("adopts a group on the native owner and routes participant mute without acquiring WebView media", async () => {
  const f = setup();
  runtime.native = true;
  f.chat.chat_kind = "chat";
  const call = {
    ...f.current(),
    kind: "group" as const,
    participants: {
      ...f.current().participants,
      peer: participant("peer", "b"),
    },
  };
  expect(
    await f.calls.adoptNative({
      identity: "me",
      call,
      session_id: "12345678-1234-1234-1234-123456789abc",
      activation: "12345678-1234-1234-1234-123456789def",
      media,
    }),
  ).toBe(true);
  expect(await f.calls.setParticipantMuted("b", true)).toBe(true);
  expect(runtime.peers[0].setParticipantMuted).toHaveBeenCalledExactlyOnceWith(
    "b",
    true,
  );
  expect(await f.calls.setParticipantMuted("removed-device", true)).toBe(false);
  expect(runtime.groups).toHaveLength(0);
  expect(f.getUserMedia).not.toHaveBeenCalled();
  f.calls.dispose();
});

it("starts mobile groups on the native worker without WebView capture or a second LiveKit room", async () => {
  runtime.native = true;
  const f = setup();
  f.chat.chat_kind = "chat";
  f.current().kind = "group";
  await f.calls.start(f.chat);
  await new Promise((resolve) => setTimeout(resolve, 0));
  expect(f.calls.getSnapshot().active?.kind).toBe("group");
  expect(runtime.permission).toHaveBeenCalledWith("me", false);
  expect(f.getUserMedia).not.toHaveBeenCalled();
  expect(runtime.groups).toHaveLength(0);
  expect(runtime.peers).toHaveLength(1);
  expect(runtime.peers[0].native).toBe(true);
  expect(runtime.peers[0].args[7]).toMatchObject({
    call_id: f.current().call_id,
  });
  expect(
    f.command.mock.calls.some(
      ([, operation]) => operation.type === "connect_media",
    ),
  ).toBe(false);
  await f.presence({
    me: participant("me", "a"),
    peer: participant("peer", "b"),
  });
  expect(runtime.peers).toHaveLength(1);
  await f.calls.leave();
});

it.each(["user", "native_end"])(
  "dismisses a group after %s leave while keeping it available for explicit rejoin",
  async (reason) => {
    runtime.native = true;
    const f = setup();
    f.chat.chat_kind = "chat";
    f.current().kind = "group";
    await f.calls.start(f.chat);
    await f.presence({
      me: participant("me", "a"),
      peer: participant("peer", "b"),
    });
    const id = f.current().call_id;
    await f.calls.leave(reason);
    expect(f.calls.snapshot.active).toBeUndefined();
    expect(f.calls.snapshot.dismissed).toContain(`host:space:chat:${id}`);
    expect(f.calls.snapshot.available["host:space:chat"].participants).toEqual({
      peer: participant("peer", "b"),
    });
    // Later presence does not undo the local dismissal.
    await f.presence({ peer: participant("peer", "b") });
    expect(f.calls.snapshot.dismissed).toContain(`host:space:chat:${id}`);
    f.command.mockClear();
    f.calls.reveal(f.chat);
    expect(f.calls.snapshot.dismissed).not.toContain(`host:space:chat:${id}`);
    expect(f.calls.snapshot.active).toBeUndefined();
    expect(f.command).not.toHaveBeenCalled();
    const start = vi.spyOn(f.calls, "start").mockResolvedValueOnce();
    f.calls.requestStart(f.chat);
    await vi.waitFor(() =>
      expect(start).toHaveBeenCalledExactlyOnceWith(
        f.chat,
        f.current(),
        undefined,
      ),
    );
    f.calls.dispose();
  },
);

it("does not record a group dismissal for direct calls or transport failures", async () => {
  const f = setup();
  await f.calls.start(f.chat);
  await f.calls.leave();
  expect(f.calls.snapshot.dismissed ?? []).toEqual([]);
  f.calls.dispose();
  runtime.native = true;
  const group = setup();
  group.chat.chat_kind = "chat";
  group.current().kind = "group";
  await group.calls.start(group.chat);
  await group.calls.leave("failure");
  expect(group.calls.snapshot.dismissed ?? []).toEqual([]);
  group.calls.dispose();
});
