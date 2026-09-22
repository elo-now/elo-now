import { invoke, isTauri } from "@tauri-apps/api/core";
import type {
  MediaAccess,
  MediaAdapter,
  MediaState,
  MediaTile,
  SignalPayload,
} from "./types";

export const usesNativePeer = () =>
  isTauri() && /iPhone|iPad|iPod/.test(navigator.userAgent);
export type NativeRequest = (request: Record<string, unknown>) => Promise<any>;
const request =
  (identity: string): NativeRequest =>
  (request) =>
    invoke<any>("native_call_media", { identity, request }).then((result) => {
      if (result.error) throw new Error(result.error);
      return result;
    });

export async function nativeMediaPermission(identity: string, video: boolean) {
  await request(identity)({ op: "permissions", video });
}

/** The native peer owns capture/playback. Only authenticated signaling crosses IPC. */
export class NativePeer implements MediaAdapter {
  readonly id = crypto.randomUUID();
  private stopped = false;
  private ready: Promise<void>;
  private timer?: ReturnType<typeof setTimeout>;
  private disconnected?: ReturnType<typeof setTimeout>;
  private queue: Promise<unknown> = Promise.resolve();
  private revision = -1;
  private connection = "new";
  private speakerMuted = false;
  private invoke: NativeRequest;
  private streams = new Map<string, MediaStream>();
  constructor(
    access: MediaAccess,
    private local: string,
    private remote: string,
    identity: string,
    private send: (signal: SignalPayload) => Promise<void>,
    private tiles: (tiles: MediaTile[]) => void,
    private failure: () => void,
    private connected: () => void,
    transport?: NativeRequest,
    context?: Record<string, unknown>,
  ) {
    this.invoke = transport ?? request(identity);
    this.ready = this.invoke({
      op: "start",
      id: this.id,
      ice_servers: access.ice_servers,
      context,
    }).then(async () => {
      if (this.stopped) {
        await this.invoke({ op: "stop", id: this.id });
        return;
      }
      void this.poll();
    });
  }
  private async poll() {
    if (this.stopped) return;
    try {
      const state = await this.invoke({ op: "poll", id: this.id });
      if (this.stopped) return;
      for (const signal of state.signals as SignalPayload[]) {
        await this.send(signal);
        if (this.stopped) return;
      }
      if (this.connection !== state.connection) {
        this.connection = state.connection;
        clearTimeout(this.disconnected);
        if (state.connection === "connected") this.connected();
        else if (state.connection === "disconnected")
          this.disconnected = setTimeout(() => {
            if (!this.stopped && this.connection === "disconnected")
              this.failure();
          }, 4000);
        else if (["failed", "closed"].includes(state.connection))
          this.failure();
      }
      if (this.stopped) return;
      if (this.revision !== state.revision) {
        this.revision = state.revision;
        const live = new Set<string>();
        this.tiles(
          state.tracks.map(
            (track: {
              id: string;
              local: boolean;
              source: "camera" | "screen";
            }) => {
              live.add(track.id);
              let stream = this.streams.get(track.id);
              if (!stream) {
                stream = new MediaStream();
                this.streams.set(track.id, stream);
              }
              return {
                ...track,
                stream,
                credential: track.local ? this.local : this.remote,
                native: {
                  session: this.id,
                  render: (frames: unknown[]) =>
                    this.command({ op: "render", frames }),
                  track: track.id,
                },
              };
            },
          ),
        );
        for (const id of this.streams.keys())
          if (!live.has(id)) this.streams.delete(id);
      }
    } catch {
      if (!this.stopped) this.failure();
    } finally {
      if (!this.stopped) this.timer = setTimeout(() => void this.poll(), 150);
    }
  }
  private async command(command: Record<string, unknown>) {
    await this.ready;
    if (this.stopped) return;
    return this.invoke({ ...command, id: this.id });
  }
  private serial(command: Record<string, unknown>) {
    const work = this.queue.then(() => this.command(command));
    this.queue = work.catch(() => {});
    return work.then(() => {});
  }
  offer(restart = false) {
    return this.serial({ op: "offer", restart });
  }
  signal(signal: SignalPayload) {
    return this.serial({ op: "signal", signal });
  }
  async update(state: MediaState) {
    await this.serial({
      op: "update",
      state,
      speaker_muted: this.speakerMuted,
    });
  }
  async setSpeakerMuted(muted: boolean) {
    this.speakerMuted = muted;
    await this.command({ op: "speaker", muted });
  }
  async stop() {
    this.stopped = true;
    clearTimeout(this.timer);
    clearTimeout(this.disconnected);
    this.tiles([]);
    this.streams.clear();
    // A pending start must finish before its matching stop; never close a successor.
    await this.ready.catch(() => {});
    await this.invoke({ op: "stop", id: this.id }).catch(() => {});
  }
}
