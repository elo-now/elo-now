import {
  ExternalE2EEKeyProvider,
  Room,
  RoomEvent,
  Track,
  isE2EESupported,
  type RemoteTrack,
} from "livekit-client";
import EncryptionWorker from "livekit-client/e2ee-worker?worker";
import type { MediaAccess, MediaAdapter, MediaState, MediaTile } from "./types";
type RemoteTile = {
  track: RemoteTrack;
  mediaTrack: MediaStreamTrack;
  tile: MediaTile;
};
export class GroupMedia implements MediaAdapter {
  private room: Room;
  private worker: Worker;
  private key = new ExternalE2EEKeyProvider();
  private published = new Map<
    string,
    { source: MediaStreamTrack; clone: MediaStreamTrack }
  >();
  private stopped = false;
  private stopping?: Promise<void>;
  private remoteTiles = new Map<string, RemoteTile>();
  private permissionWaiters = new Set<(error?: Error) => void>();
  constructor(
    private tiles: (value: MediaTile[]) => void,
    private failure: (reason: string) => void,
  ) {
    if (!isE2EESupported()) throw new Error("encryption_unavailable");
    this.worker = new EncryptionWorker();
    this.room = new Room({
      adaptiveStream: true,
      dynacast: true,
      encryption: { keyProvider: this.key, worker: this.worker },
      publishDefaults: { simulcast: true, videoCodec: "vp8" },
    });
    this.room.on(RoomEvent.TrackSubscribed, () => this.refresh());
    // LiveKit emits unsubscribe before clearing publication.track. Read the
    // settled publication state so an ended screen cannot remain in the UI.
    this.room.on(RoomEvent.TrackUnsubscribed, () =>
      queueMicrotask(() => this.refresh()),
    );
    this.room.on(RoomEvent.TrackUnpublished, () => this.refresh());
    this.room.on(RoomEvent.TrackMuted, () => this.refresh());
    this.room.on(RoomEvent.TrackUnmuted, () => this.refresh());
    this.room.on(RoomEvent.ActiveSpeakersChanged, () => this.refresh());
    this.room.on(RoomEvent.ParticipantDisconnected, () => this.refresh());
    this.room.on(RoomEvent.ParticipantPermissionsChanged, () => {
      for (const check of this.permissionWaiters) check();
    });
    this.room.on(RoomEvent.EncryptionError, () =>
      this.failure("encryption_error"),
    );
    this.room.on(RoomEvent.Disconnected, () => {
      for (const check of this.permissionWaiters)
        check(new Error("disconnected"));
      if (!this.stopped) this.failure("disconnected");
    });
  }
  async connect(access: MediaAccess, secret: string) {
    const bytes = Uint8Array.from(secret.match(/../g)!, (x) => parseInt(x, 16));
    await this.key.setKey(bytes.buffer);
    bytes.fill(0);
    if (this.stopped) return;
    await this.room.setE2EEEnabled(true);
    if (this.stopped) return;
    await this.room.connect(access.url, access.token, { autoSubscribe: true });
    if (this.stopped) return;
    try {
      await this.room.startAudio();
    } catch (error) {}
  }
  private refresh() {
    if (this.stopped) return;
    const tiles: MediaTile[] = [];
    const current = new Map<string, RemoteTile>();
    for (const participant of this.room.remoteParticipants.values())
      for (const publication of participant.trackPublications.values()) {
        const track = publication.track;
        if (track) {
          let cached = this.remoteTiles.get(publication.trackSid);
          // Speaker events update only metadata. Replacing the stream would
          // detach/restart playback on every voice activity change.
          if (
            cached?.track !== track ||
            cached.mediaTrack !== track.mediaStreamTrack
          ) {
            cached = {
              track,
              mediaTrack: track.mediaStreamTrack,
              tile: {
                id: publication.trackSid,
                credential: participant.identity,
                stream: new MediaStream([track.mediaStreamTrack]),
                local: false,
                source:
                  publication.source === Track.Source.ScreenShare
                    ? "screen"
                    : publication.source === Track.Source.Camera
                      ? "camera"
                      : "audio",
                attach: (element) => {
                  track.attach(element);
                },
                detach: (element) => {
                  track.detach(element);
                },
              },
            };
          }
          current.set(publication.trackSid, cached);
          tiles.push({ ...cached.tile, speaking: participant.isSpeaking });
        }
      }
    this.remoteTiles = current;
    this.tiles(tiles);
  }
  private waitForPublicationPermission(source: Track.Source) {
    const allowed = () => {
      const permissions = this.room.localParticipant.permissions;
      return (
        permissions?.canPublish &&
        (permissions.canPublishSources.length === 0 ||
          permissions.canPublishSources.includes(Track.sourceToProto(source)))
      );
    };
    if (this.stopped || allowed()) return Promise.resolve();
    // Call control and LiveKit use separate connections. Its grant can arrive
    // before the SDK receives the corresponding participant permission update.
    return new Promise<void>((resolve, reject) => {
      const check = (error?: Error) => {
        if (!error && !this.stopped && !allowed()) return;
        clearTimeout(timer);
        this.permissionWaiters.delete(check);
        if (error) reject(error);
        else resolve();
      };
      const timer = setTimeout(
        () => check(new Error("media_permission_timeout")),
        5000,
      );
      this.permissionWaiters.add(check);
      check();
    });
  }
  async update(state: MediaState, capture: MediaStream, screen?: MediaStream) {
    const desired: [Track.Source, MediaStreamTrack | undefined][] = [
      [
        Track.Source.Microphone,
        state.audio_muted ? undefined : capture.getAudioTracks()[0],
      ],
      [
        Track.Source.Camera,
        state.video_published ? capture.getVideoTracks()[0] : undefined,
      ],
      [
        Track.Source.ScreenShare,
        state.screen_published ? screen?.getVideoTracks()[0] : undefined,
      ],
    ];
    for (const [source, track] of desired) {
      if (this.stopped) return;
      const old = this.published.get(source);
      if (old?.source === track) continue;
      if (old) {
        old.clone.stop();
        try {
          await this.room.localParticipant.unpublishTrack(old.clone, true);
        } finally {
          this.published.delete(source);
        }
      }
      if (this.stopped) return;
      if (track) {
        await this.waitForPublicationPermission(source);
        if (this.stopped) return;
        // The provider may stop its tracks when an epoch's room is revoked.
        // Keep ownership of the original capture in the call controller.
        const clone = track.clone();
        try {
          await this.room.localParticipant.publishTrack(clone, { source });
          if (this.stopped) {
            clone.stop();
            return;
          }
          this.published.set(source, { source: track, clone });
        } catch (error) {
          clone.stop();
          throw error;
        }
      }
    }
  }
  stop() {
    // Leave can race with cleanup started by a failed connection. Every caller
    // must await that same cleanup, including its rejection, before replacing it.
    this.stopping ??= this.stopOnce();
    return this.stopping;
  }
  private async stopOnce() {
    this.stopped = true;
    for (const check of this.permissionWaiters) check();
    for (const track of this.published.values()) track.clone.stop();
    try {
      await this.room.disconnect();
    } finally {
      for (const track of this.published.values()) track.clone.stop();
      this.published.clear();
      this.remoteTiles.clear();
      this.worker.terminate();
      this.tiles([]);
    }
  }
}
