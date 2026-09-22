import type { Calls } from "./controller";

export type NativeCall = {
  id: string;
  action: string;
  expires: number;
  event?: string;
  muted?: boolean;
  target: { identity: string; space: string; stream: string } | null;
};
type Controller = Pick<
  Calls,
  "getSnapshot" | "decline" | "leave" | "toggle" | "start" | "setNativeAnswer"
>;

/** Lives only inside an unlocked profile. Native payloads never authorize media. */
export class NativeCallSession {
  private accepted?: string;
  private observedActive = false;
  private notifiedConnected = false;
  private notifiedAnswer = false;
  private stopped = false;
  private cancelled?: string;
  constructor(
    private calls: Controller,
    private identity: string,
    private action: (op: string) => Promise<unknown>,
  ) {}
  stop() {
    this.stopped = true;
    this.calls.setNativeAnswer(undefined);
  }
  async consume(incoming?: NativeCall | null, now = Date.now() / 1000) {
    if (this.stopped) return;
    const state = this.calls.getSnapshot();
    if (!incoming || incoming.action !== "answer" || state.phase !== "idle")
      this.calls.setNativeAnswer(undefined);
    const acknowledge = () =>
      incoming?.event
        ? this.action(`calls_ack:${incoming.id}:${incoming.event}`)
        : Promise.resolve();
    if (incoming?.action === "mute") {
      if (
        state.active?.call_id === incoming.id &&
        typeof incoming.muted === "boolean"
      ) {
        if (state.media.audio_muted !== incoming.muted)
          await this.calls.toggle("audio");
        if (this.calls.getSnapshot().media.audio_muted !== incoming.muted)
          return;
      }
      if (!this.stopped) await acknowledge();
      return;
    }
    if (incoming?.action === "decline") {
      if (state.incoming?.call.call_id === incoming.id)
        await this.calls.decline();
      if (state.active?.call_id === incoming.id) await this.calls.leave();
      if (!this.stopped) await acknowledge();
      return;
    }
    if (incoming?.id && state.active?.call_id === incoming.id)
      this.accepted = incoming.id;
    if (this.accepted && state.active?.call_id === this.accepted) {
      this.observedActive = true;
      if (!this.notifiedAnswer) {
        await this.action(`calls_answering:${this.accepted}`);
        this.notifiedAnswer = true;
      }
      if (state.phase === "connected" && !this.notifiedConnected) {
        await this.action(`calls_connected:${this.accepted}`);
        this.notifiedConnected = true;
      }
    } else if (this.accepted && this.observedActive && state.phase === "idle") {
      await this.action(`calls_end:${this.accepted}`);
      this.accepted = undefined;
      this.observedActive = false;
      this.notifiedConnected = false;
      this.notifiedAnswer = false;
    }
    if (
      this.stopped ||
      !incoming?.id ||
      incoming.action !== "answer" ||
      this.accepted === incoming.id
    )
      return;
    if (
      !incoming.target ||
      incoming.target.identity !== this.identity ||
      !Number.isFinite(incoming.expires) ||
      incoming.expires <= now
    ) {
      this.calls.setNativeAnswer(undefined);
      await this.action(`calls_end:${incoming.id}`);
      return;
    }
    const known = Object.values(state.available).find(
      (call) => call.call_id === incoming.id,
    );
    if (known && !known.ringing && state.active?.call_id !== incoming.id) {
      this.calls.setNativeAnswer(undefined);
      await this.action(`calls_end:${incoming.id}`);
      return;
    }
    if (this.cancelled === incoming.id) {
      this.calls.setNativeAnswer(undefined);
      await this.calls.decline().catch(() => {});
      await this.action(`calls_end:${incoming.id}`);
      return;
    }
    if (state.phase === "idle")
      this.calls.setNativeAnswer({
        id: incoming.id,
        cancel: () => {
          this.cancelled = incoming.id;
          void this.calls.decline().catch(() => {});
          this.calls.setNativeAnswer(undefined);
          void this.action(`calls_end:${incoming.id}`).catch(() => {});
        },
      });
    const pending = state.incoming;
    if (
      state.phase !== "idle" ||
      !pending ||
      pending.call.kind !== "direct" ||
      !pending.call.ringing ||
      pending.call.call_id !== incoming.id ||
      pending.chat.space !== incoming.target.space ||
      pending.chat.stream !== incoming.target.stream
    ) {
      return;
    }
    this.accepted = incoming.id;
    this.notifiedConnected = false;
    await this.calls.start(pending.chat, false, pending.call);
    if (!this.stopped && this.calls.getSnapshot().phase === "idle") {
      await this.action(`calls_end:${incoming.id}`);
      this.accepted = undefined;
    }
  }
}
