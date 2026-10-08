import { invoke, isTauri } from "../diagnosticInvoke";
import type { ActiveCall, MediaAdapter, MediaState, MediaTile } from "./types";

export const usesNativePeer = () =>
  isTauri() && /Android|iPhone|iPad|iPod/.test(navigator.userAgent);
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
/** Native signaling and capture remain active independently of WebView timers. */
export class NativePeer implements MediaAdapter {
  readonly id: string;
  private stopped = false;
  private ready: Promise<void>;
  private timer?: ReturnType<typeof setTimeout>;
  private queue: Promise<unknown> = Promise.resolve();
  private revision = -1;
  private connection = "new";
  private remote = "";
  private lastCall = "";
  private speakerMuted = false;
  private invoke: NativeRequest;
  private streams = new Map<string, MediaStream>();
  constructor(
    private local: string,
    identity: string,
    private tiles: (tiles: MediaTile[]) => void,
    private failure: (reason?: string) => void,
    private connected: () => void,
    private presence: (call: ActiveCall) => void,
    transport?: NativeRequest,
    context?: Record<string, unknown>,
    adoption?: { sessionId: string },
  ) {
    this.id = adoption?.sessionId ?? crypto.randomUUID();
    this.invoke = transport ?? request(identity);
    this.ready = (
      adoption
        ? Promise.resolve()
        : this.invoke({
            op: "start",
            id: this.id,
            ice_servers: [],
            context,
          })
    ).then(async () => {
      if (!this.stopped) void this.poll();
    });
  }
  private async poll() {
    if (this.stopped) return;
    try {
      const state = await this.invoke({ op: "poll", id: this.id });
      if (this.stopped) return;
      const remote = state.remote ?? "";
      if (remote !== this.remote) {
        this.remote = remote;
        this.revision = -1;
      }
      if (state.call) {
        const serialized = JSON.stringify(state.call);
        if (this.lastCall !== serialized) {
          this.lastCall = serialized;
          this.presence(state.call);
        }
      }
      if (this.connection !== state.connection) {
        this.connection = state.connection;
        if (state.connection === "connected") this.connected();
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
              source: "camera" | "screen" | "audio";
              credential?: string;
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
                credential:
                  track.credential ?? (track.local ? this.local : this.remote),
                native: {
                  session: this.id,
                  revision: state.revision,
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
    } catch (error) {
      if (!this.stopped)
        this.failure(
          error === "ended" ||
            (error instanceof Error && error.message === "ended")
            ? "ended"
            : "unavailable",
        );
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
  async setParticipantMuted(credential: string, muted: boolean) {
    await this.command({ op: "speaker", credential, muted });
  }
  detach() {
    this.stopped = true;
    clearTimeout(this.timer);
    this.streams.clear();
  }
  async stop() {
    this.detach();
    this.tiles([]);
    // A pending start must finish before its matching stop; never close a successor.
    await this.ready.catch(() => {});
    await this.invoke({ op: "stop", id: this.id }).catch(() => {});
  }
}
