import { beforeEach, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  setKey: vi.fn(async () => {}),
  setE2EEEnabled: vi.fn(async () => {}),
  connect: vi.fn(async () => {}),
  disconnect: vi.fn(async () => {}),
  terminate: vi.fn(),
  startAudio: vi.fn(async () => {}),
  publishTrack: vi.fn(async () => {}),
  unpublishTrack: vi.fn(async () => {}),
  events: new Map<string, () => void>(),
  participants: new Map(),
  permissions: { canPublish: true, canPublishSources: [] as number[] },
}));

vi.mock("livekit-client/e2ee-worker?worker", () => ({
  default: class {
    terminate = mocks.terminate;
  },
}));

vi.mock("livekit-client", () => ({
  ExternalE2EEKeyProvider: class {
    setKey = mocks.setKey;
  },
  Room: class {
    remoteParticipants = mocks.participants;
    localParticipant = {
      permissions: mocks.permissions,
      publishTrack: mocks.publishTrack,
      unpublishTrack: mocks.unpublishTrack,
    };
    on(event: string, callback: () => void) {
      mocks.events.set(event, callback);
      return this;
    }
    setE2EEEnabled = mocks.setE2EEEnabled;
    connect = mocks.connect;
    disconnect = mocks.disconnect;
    startAudio = mocks.startAudio;
  },
  RoomEvent: {
    TrackSubscribed: "trackSubscribed",
    TrackUnsubscribed: "trackUnsubscribed",
    TrackUnpublished: "trackUnpublished",
    TrackMuted: "trackMuted",
    TrackUnmuted: "trackUnmuted",
    ActiveSpeakersChanged: "activeSpeakersChanged",
    ParticipantDisconnected: "participantDisconnected",
    ParticipantPermissionsChanged: "participantPermissionsChanged",
    EncryptionError: "encryptionError",
    Disconnected: "disconnected",
  },
  Track: {
    sourceToProto: (source: string) =>
      ({ camera: 1, microphone: 2, screenShare: 3 })[
        source as "camera" | "microphone" | "screenShare"
      ],
    Source: {
      Microphone: "microphone",
      Camera: "camera",
      ScreenShare: "screenShare",
    },
  },
  isE2EESupported: () => true,
}));

import { GroupMedia } from "./livekit";
import { Calls } from "./controller";
import type { Stream, View } from "../model";
import type { ActiveCall, MediaTile } from "./types";

beforeEach(() => {
  vi.clearAllMocks();
  mocks.events.clear();
  mocks.participants.clear();
  mocks.permissions.canPublish = true;
  mocks.permissions.canPublishSources = [];
});

it("keeps playback attached while speakers change and replaces only changed tracks", () => {
  vi.stubGlobal(
    "MediaStream",
    class {
      constructor(public tracks: unknown[]) {}
    },
  );
  try {
    const tiles = vi.fn<(tiles: MediaTile[]) => void>();
    new GroupMedia(tiles, vi.fn());
    const track = { mediaStreamTrack: {}, attach: vi.fn(), detach: vi.fn() };
    const camera = { trackSid: "camera", source: "camera", track };
    const participant = {
      identity: "peer",
      isSpeaking: false,
      trackPublications: new Map([["camera", camera]]),
    };
    mocks.participants.set("peer", participant);
    const latest = () => tiles.mock.lastCall![0][0];
    mocks.events.get("trackSubscribed")!();
    const initial = latest();
    for (const speaking of [true, false, true, false]) {
      participant.isSpeaking = speaking;
      mocks.events.get("activeSpeakersChanged")!();
      expect(latest().speaking).toBe(speaking);
      expect(latest().stream).toBe(initial.stream);
      expect(latest().attach).toBe(initial.attach);
      expect(latest().detach).toBe(initial.detach);
      expect(initial.speaking).toBe(false);
    }

    // A provider can replace a wrapper under the same publication SID, or
    // restart its native track while keeping that wrapper. Both need reattach.
    camera.track = { ...track, attach: vi.fn(), detach: vi.fn() };
    mocks.events.get("trackSubscribed")!();
    const replacement = latest();
    expect(replacement.stream).not.toBe(initial.stream);
    const element = {} as HTMLMediaElement;
    replacement.attach!(element);
    expect(camera.track.attach).toHaveBeenCalledWith(element);
    expect(track.attach).not.toHaveBeenCalled();
    camera.track.mediaStreamTrack = {};
    mocks.events.get("trackSubscribed")!();
    expect(latest().stream).not.toBe(replacement.stream);

    const beforeDisconnect = latest();
    mocks.participants.clear();
    mocks.events.get("participantDisconnected")!();
    expect(tiles.mock.lastCall![0]).toEqual([]);
    mocks.participants.set("peer", participant);
    mocks.events.get("trackSubscribed")!();
    expect(latest().stream).not.toBe(beforeDisconnect.stream);
  } finally {
    vi.unstubAllGlobals();
  }
});

it("removes an unsubscribed screen after the provider clears its track", async () => {
  vi.stubGlobal(
    "MediaStream",
    class {
      constructor(public tracks: unknown[]) {}
    },
  );
  try {
    const tiles = vi.fn();
    new GroupMedia(tiles, vi.fn());
    const camera = {
      trackSid: "camera",
      source: "camera",
      track: { mediaStreamTrack: {} },
    };
    const screen: {
      trackSid: string;
      source: string;
      track?: { mediaStreamTrack: object };
    } = {
      trackSid: "screen",
      source: "screenShare",
      track: { mediaStreamTrack: {} },
    };
    mocks.participants.set("peer", {
      identity: "peer",
      isSpeaking: false,
      trackPublications: new Map([
        ["camera", camera],
        ["screen", screen],
      ]),
    });
    mocks.events.get("trackSubscribed")!();
    expect(
      tiles.mock.lastCall?.[0].map((tile: { id: string }) => tile.id),
    ).toEqual(["camera", "screen"]);

    // This is the SDK's event ordering. An unsubscribe can also occur without
    // unpublishing (e.g. permissions change), so neither speakers nor another
    // track event should be required to remove the stale tile.
    mocks.events.get("trackUnsubscribed")!();
    screen.track = undefined;
    await Promise.resolve();
    expect(
      tiles.mock.lastCall?.[0].map((tile: { id: string }) => tile.id),
    ).toEqual(["camera"]);
  } finally {
    vi.unstubAllGlobals();
  }
});

it("keeps an encrypted group call connected when iOS defers audio playback", async () => {
  mocks.startAudio.mockRejectedValueOnce(
    new DOMException("The operation was aborted.", "AbortError"),
  );
  const failure = vi.fn();
  const media = new GroupMedia(vi.fn(), failure);

  await expect(
    media.connect(
      {
        provider: "livekit",
        url: "wss://media.example.test",
        token: "token",
        epoch: 6,
        ice_servers: [],
      },
      "00".repeat(32),
    ),
  ).resolves.toBeUndefined();

  expect(failure).not.toHaveBeenCalled();
});

it("stops the screen clone before waiting for provider unpublication", async () => {
  const stop = vi.fn();
  const clone = { stop };
  const original = { clone: () => clone };
  const capture = {
    getAudioTracks: () => [],
    getVideoTracks: () => [],
  } as unknown as MediaStream;
  const screen = { getVideoTracks: () => [original] } as unknown as MediaStream;
  const media = new GroupMedia(vi.fn(), vi.fn());
  await media.update(
    { audio_muted: true, video_published: false, screen_published: true },
    capture,
    screen,
  );
  expect(mocks.publishTrack).toHaveBeenCalledWith(clone, {
    source: "screenShare",
  });
  mocks.unpublishTrack.mockImplementationOnce(async () => {
    expect(stop).toHaveBeenCalled();
    throw new Error("network");
  });
  await expect(
    media.update(
      { audio_muted: true, video_published: false, screen_published: false },
      capture,
    ),
  ).rejects.toThrow("network");
  expect(stop).toHaveBeenCalledOnce();
});

it.each([
  ["microphone", 2],
  ["camera", 1],
  ["screenShare", 3],
] as const)(
  "waits for the provider's delayed %s grant before publishing",
  async (source, grantedSource) => {
    mocks.permissions.canPublishSources = [4];
    const clone = { stop: vi.fn() };
    const original = { clone: vi.fn(() => clone) };
    const capture = {
      getAudioTracks: () => (source === "microphone" ? [original] : []),
      getVideoTracks: () => (source === "camera" ? [original] : []),
    } as unknown as MediaStream;
    const screen = {
      getVideoTracks: () => (source === "screenShare" ? [original] : []),
    } as unknown as MediaStream;
    const media = new GroupMedia(vi.fn(), vi.fn());
    const publishing = media.update(
      {
        audio_muted: source !== "microphone",
        video_published: source === "camera",
        screen_published: source === "screenShare",
      },
      capture,
      screen,
    );
    await Promise.resolve();
    expect(original.clone).not.toHaveBeenCalled();
    expect(mocks.publishTrack).not.toHaveBeenCalled();

    mocks.events.get("participantPermissionsChanged")!();
    await Promise.resolve();
    expect(mocks.publishTrack).not.toHaveBeenCalled();

    mocks.permissions.canPublishSources = [grantedSource];
    mocks.events.get("participantPermissionsChanged")!();
    await publishing;
    expect(mocks.publishTrack).toHaveBeenCalledExactlyOnceWith(clone, {
      source,
    });
    await media.stop();
  },
);

it("does not publish if the provider never grants screen permission", async () => {
  vi.useFakeTimers();
  try {
    mocks.permissions.canPublish = false;
    const original = { clone: vi.fn() };
    const media = new GroupMedia(vi.fn(), vi.fn());
    const publishing = media.update(
      { audio_muted: true, video_published: false, screen_published: true },
      {
        getAudioTracks: () => [],
        getVideoTracks: () => [],
      } as unknown as MediaStream,
      { getVideoTracks: () => [original] } as unknown as MediaStream,
    );
    const failed = expect(publishing).rejects.toThrow(
      "media_permission_timeout",
    );
    await vi.advanceTimersByTimeAsync(5000);
    await failed;
    expect(original.clone).not.toHaveBeenCalled();
    expect(mocks.publishTrack).not.toHaveBeenCalled();
    expect(vi.getTimerCount()).toBe(0);
    await media.stop();
  } finally {
    vi.useRealTimers();
  }
});

it.each(["leave", "disconnect"])(
  "cancels a pending screen grant on %s without publishing later",
  async (ending) => {
    vi.useFakeTimers();
    try {
      mocks.permissions.canPublishSources = [2];
      const original = { clone: vi.fn() };
      const media = new GroupMedia(vi.fn(), vi.fn());
      const publishing = media.update(
        { audio_muted: true, video_published: false, screen_published: true },
        {
          getAudioTracks: () => [],
          getVideoTracks: () => [],
        } as unknown as MediaStream,
        { getVideoTracks: () => [original] } as unknown as MediaStream,
      );
      if (ending === "leave") {
        await media.stop();
        await publishing;
      } else {
        const failed = expect(publishing).rejects.toThrow("disconnected");
        mocks.events.get("disconnected")!();
        await failed;
      }
      mocks.permissions.canPublishSources = [3];
      mocks.events.get("participantPermissionsChanged")!();
      await Promise.resolve();
      expect(original.clone).not.toHaveBeenCalled();
      expect(mocks.publishTrack).not.toHaveBeenCalled();
      expect(vi.getTimerCount()).toBe(0);
      await media.stop();
    } finally {
      vi.useRealTimers();
    }
  },
);

it.each([false, true])(
  "shares the pending teardown and its result with repeated stops (reject=%s)",
  async (reject) => {
    const tiles = vi.fn();
    const media = new GroupMedia(tiles, vi.fn());
    const failure = new Error("disconnect failed");
    let finish!: () => void;
    mocks.disconnect.mockImplementationOnce(
      () =>
        new Promise<void>((resolve, rejectStop) => {
          finish = () => (reject ? rejectStop(failure) : resolve());
        }),
    );
    const first = media.stop();
    const second = media.stop();
    const results = Promise.allSettled([first, second]);
    expect(mocks.disconnect).toHaveBeenCalledOnce();
    expect(mocks.terminate).not.toHaveBeenCalled();
    finish();
    const expected = reject
      ? { status: "rejected", reason: failure }
      : { status: "fulfilled", value: undefined };
    expect(await results).toEqual([expected, expected]);
    expect(second).toBe(first);
    expect(media.stop()).toBe(first);
    expect(mocks.terminate).toHaveBeenCalledOnce();
    expect(tiles).toHaveBeenCalledExactlyOnceWith([]);
  },
);

it("waits for failed connection cleanup before connecting a later admission", async () => {
  const calls = new Calls();
  const chat = {
    space_context: "host",
    space: "space",
    stream: "chat",
    head: "head",
    can_post: true,
    members: [
      { identity_id: "me", credential_ids: ["a"], capabilities: ["POST"] },
    ],
  } as unknown as Stream;
  const call = (epoch: number): ActiveCall => ({
    call_id: `call-${epoch}`,
    scope: {
      hosting_space_id: "host",
      conversation: { space_id: "space", stream_id: "chat" },
    },
    config_id: "head",
    key_epoch: epoch,
    kind: "group",
    initial_media: "audio",
    started_by: "me",
    started_at: 1,
    participants: {
      me: {
        identity_id: "me",
        credential_id: "a",
        media: {
          audio_muted: false,
          video_published: false,
          screen_published: false,
        },
      },
    },
  });
  const capture = {
    getTracks: () => [],
    getAudioTracks: () => [],
    getVideoTracks: () => [],
  } as unknown as MediaStream;
  Object.assign(calls, {
    view: {
      identity: "me",
      credential: "a",
      streams: [chat],
      spaces: [{ id: "host", managed: true, status: "joined" }],
    } as unknown as View,
    capture,
    command: async () => ({
      media: { epoch: calls.snapshot.active?.key_epoch },
    }),
  });
  const controller = calls as unknown as {
    presence(call: ActiveCall): Promise<void>;
  };
  let finish!: () => void;
  mocks.disconnect.mockImplementationOnce(
    () => new Promise<void>((resolve) => (finish = resolve)),
  );
  mocks.connect.mockRejectedValueOnce(new Error("connection failed"));
  calls.snapshot = { ...calls.snapshot, active: call(1), chat };
  await controller.presence(call(1));
  await vi.waitFor(() => expect(mocks.disconnect).toHaveBeenCalledOnce());
  const leaving = calls.leave();
  let left = false;
  void leaving.then(() => {
    left = true;
  });
  // A later admission can finish while the failed room is still disconnecting.
  Object.assign(calls, { capture });
  calls.snapshot = { ...calls.snapshot, active: call(2), chat };
  await controller.presence(call(2));
  for (let turn = 0; turn < 100; turn++) await Promise.resolve();
  const leftBeforeCleanup = left;
  const connectionsBeforeCleanup = mocks.connect.mock.calls.length;
  finish();
  await leaving;
  await vi.waitFor(() => expect(calls.snapshot.phase).toBe("connected"));
  expect(mocks.connect).toHaveBeenCalledTimes(2);
  expect(calls.snapshot.active?.call_id).toBe("call-2");
  expect(calls.snapshot.error).toBeUndefined();
  calls.dispose();
  expect(leftBeforeCleanup).toBe(false);
  expect(connectionsBeforeCleanup).toBe(1);
});
