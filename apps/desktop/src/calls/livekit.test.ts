import { beforeEach, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  setKey: vi.fn(async () => {}),
  setE2EEEnabled: vi.fn(async () => {}),
  connect: vi.fn(async () => {}),
  startAudio: vi.fn(async () => {}),
  publishTrack: vi.fn(async () => {}),
  unpublishTrack: vi.fn(async () => {}),
  events: new Map<string, () => void>(),
  participants: new Map(),
}));

vi.mock("livekit-client/e2ee-worker?worker", () => ({
  default: class {
    terminate() {}
  },
}));

vi.mock("livekit-client", () => ({
  ExternalE2EEKeyProvider: class {
    setKey = mocks.setKey;
  },
  Room: class {
    remoteParticipants = mocks.participants;
    localParticipant = {
      publishTrack: mocks.publishTrack,
      unpublishTrack: mocks.unpublishTrack,
    };
    on(event: string, callback: () => void) {
      mocks.events.set(event, callback);
      return this;
    }
    setE2EEEnabled = mocks.setE2EEEnabled;
    connect = mocks.connect;
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
    EncryptionError: "encryptionError",
    Disconnected: "disconnected",
  },
  Track: {
    Source: {
      Microphone: "microphone",
      Camera: "camera",
      ScreenShare: "screenShare",
    },
  },
  isE2EESupported: () => true,
}));

import { GroupMedia } from "./livekit";
import type { MediaTile } from "./types";

beforeEach(() => {
  vi.clearAllMocks();
  mocks.events.clear();
  mocks.participants.clear();
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
