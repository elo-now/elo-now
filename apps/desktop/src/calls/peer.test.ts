import { afterEach, expect, it, vi } from "vitest";
import { PeerMedia } from "./peer";
import type { MediaAccess, SignalPayload } from "./types";

function setup() {
  const transceiver = (kind: string, mid: string | null = null) => ({
    mid,
    direction: "sendrecv",
    sender: { replaceTrack: vi.fn(async (_track: unknown) => {}) },
    receiver: { track: { kind, readyState: "ended" } },
  });
  const channels: ReturnType<typeof transceiver>[] = [];
  const pc = {
    signalingState: "stable",
    connectionState: "connected",
    localDescription: undefined as RTCSessionDescriptionInit | undefined,
    remoteDescription: undefined as RTCSessionDescriptionInit | undefined,
    onconnectionstatechange: () => {},
    addTransceiver: vi.fn((kind: string) => {
      const channel = transceiver(kind);
      channels.push(channel);
      return channel;
    }),
    getTransceivers: () => channels,
    createOffer: vi.fn(async (_options: RTCOfferOptions) => ({
      type: "offer" as const,
      sdp: "authenticated-sdp",
    })),
    setLocalDescription: vi.fn(async (offer: RTCSessionDescriptionInit) => {
      pc.localDescription = offer;
      pc.signalingState =
        offer.type === "answer" ? "stable" : "have-local-offer";
    }),
    setRemoteDescription: vi.fn(
      async (description: RTCSessionDescriptionInit) => {
        if (
          description.type === "answer" &&
          pc.signalingState !== "have-local-offer"
        )
          throw new DOMException("Unexpected answer", "InvalidStateError");
        // Native WebRTC may normalize line endings or rewrite SDP attributes.
        pc.remoteDescription = {
          ...description,
          sdp: description.sdp + "\r\n",
        };
        pc.signalingState =
          description.type === "offer" ? "have-remote-offer" : "stable";
        if (description.type === "offer" && !channels.length)
          channels.push(
            ...["audio", "video", "video"].map((kind, i) => ({
              ...transceiver(kind, String(i)),
              direction: "recvonly",
            })),
          );
      },
    ),
    createAnswer: vi.fn(async () => ({
      type: "answer" as const,
      sdp: "authenticated-answer",
    })),
    addIceCandidate: vi.fn(),
    close: vi.fn(),
  };
  vi.stubGlobal(
    "RTCPeerConnection",
    class {
      constructor() {
        return pc;
      }
    },
  );
  const send = vi.fn(async (_payload: SignalPayload) => {});
  const failure = vi.fn();
  const connected = vi.fn();
  const peer = new PeerMedia(
    { ice_servers: [] } as unknown as MediaAccess,
    "peer",
    send,
    vi.fn(),
    failure,
    connected,
  );
  return { peer, pc, send, failure, connected };
}
afterEach(() => {
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

it("restarts ICE when the other device asks to recover its peer connection", async () => {
  const { peer, pc, send } = setup();
  await peer.signal({ type: "request_offer" });
  expect(pc.createOffer).toHaveBeenCalledWith({ iceRestart: true });
  expect(send).toHaveBeenCalledWith({
    type: "offer",
    sdp: "authenticated-sdp",
  });
  // A retry before the answer resends the pending offer without SDP glare.
  await peer.signal({ type: "request_offer" });
  expect(pc.createOffer).toHaveBeenCalledOnce();
  expect(send).toHaveBeenCalledTimes(2);
  await peer.stop();
});

it("coalesces simultaneous initial and recovery offers and discards late capture work", async () => {
  const { peer, pc, send } = setup();
  let resolve!: (offer: { type: "offer"; sdp: string }) => void;
  pc.createOffer.mockImplementationOnce(
    () =>
      new Promise((done) => {
        resolve = done;
      }),
  );
  const starting = peer.offer();
  const recovering = peer.signal({ type: "request_offer" });
  await vi.waitFor(() => expect(pc.createOffer).toHaveBeenCalledOnce());
  expect(pc.createOffer).toHaveBeenCalledOnce();
  await peer.stop();
  resolve({ type: "offer", sdp: "obsolete" });
  await Promise.all([starting, recovering]);
  expect(pc.setLocalDescription).not.toHaveBeenCalled();
  expect(send).not.toHaveBeenCalled();
});

it("publishes the answerer's microphone on the offered channel, including later mute and camera changes", async () => {
  const { peer, pc } = setup();
  const audio = { kind: "audio" } as MediaStreamTrack;
  const video = { kind: "video" } as MediaStreamTrack;
  const capture = {
    getAudioTracks: () => [audio],
    getVideoTracks: () => [video],
  } as unknown as MediaStream;
  await peer.update(
    { audio_muted: false, video_published: false, screen_published: false },
    capture,
  );
  expect(pc.addTransceiver).not.toHaveBeenCalled();
  await peer.signal({ type: "offer", sdp: "authenticated-offer" });
  const channels = pc.getTransceivers();
  expect(channels).toHaveLength(3);
  expect(channels.map((t) => t.direction)).toEqual([
    "sendrecv",
    "sendrecv",
    "sendrecv",
  ]);
  expect(channels[0].sender.replaceTrack).toHaveBeenLastCalledWith(audio);
  expect(channels[1].sender.replaceTrack).toHaveBeenLastCalledWith(null);
  await peer.update(
    { audio_muted: true, video_published: true, screen_published: false },
    capture,
  );
  expect(channels[0].sender.replaceTrack).toHaveBeenLastCalledWith(null);
  expect(channels[1].sender.replaceTrack).toHaveBeenLastCalledWith(video);
  await peer.stop();
});

it("tolerates a short network interruption and requests recovery for a sustained outage", async () => {
  vi.useFakeTimers();
  const { peer, pc, failure, connected } = setup();
  pc.connectionState = "disconnected";
  pc.onconnectionstatechange();
  await vi.advanceTimersByTimeAsync(3000);
  pc.connectionState = "connected";
  pc.onconnectionstatechange();
  await vi.advanceTimersByTimeAsync(2000);
  expect(connected).toHaveBeenCalledOnce();
  expect(failure).not.toHaveBeenCalled();
  pc.connectionState = "disconnected";
  pc.onconnectionstatechange();
  await vi.advanceTimersByTimeAsync(4000);
  expect(failure).toHaveBeenCalledOnce();
  pc.onconnectionstatechange();
  await peer.stop();
  await vi.advanceTimersByTimeAsync(5000);
  expect(failure).toHaveBeenCalledOnce();
});

it("ignores a repeated answer after negotiation and accepts a new recovery answer", async () => {
  const { peer, pc } = setup();
  await peer.offer();
  const answer = { type: "answer" as const, sdp: "authenticated-answer" };
  await Promise.all([peer.signal(answer), peer.signal(answer)]);
  expect(pc.setRemoteDescription).toHaveBeenCalledOnce();
  expect(pc.signalingState).toBe("stable");
  await peer.signal({
    type: "answer",
    sdp: "authenticated-answer-with-gathered-candidates",
  });
  expect(pc.setRemoteDescription).toHaveBeenCalledOnce();
  await peer.offer(true);
  await peer.signal({ type: "answer", sdp: "new-ice-credentials" });
  expect(pc.setRemoteDescription).toHaveBeenCalledTimes(2);
  expect(pc.signalingState).toBe("stable");
  await peer.stop();
});

it("resends the existing answer to a repeated offer without renegotiating tracks", async () => {
  const { peer, pc, send } = setup();
  const offer = { type: "offer" as const, sdp: "authenticated-offer" };
  await Promise.all([peer.signal(offer), peer.signal(offer)]);
  expect(pc.setRemoteDescription).toHaveBeenCalledOnce();
  expect(pc.createAnswer).toHaveBeenCalledOnce();
  expect(send).toHaveBeenCalledTimes(2);
  await peer.signal({ type: "offer", sdp: "new-ice-credentials" });
  expect(pc.createAnswer).toHaveBeenCalledTimes(2);
  await peer.stop();
});
