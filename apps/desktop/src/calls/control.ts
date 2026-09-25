import { invoke } from "@tauri-apps/api/core";
import type { Stream } from "../model";
import type { ActiveCall, MediaAccess } from "./types";
export type Result = {
  type: string;
  call?: ActiveCall;
  media?: MediaAccess;
  code?: string;
  [key: string]: unknown;
};
export type Operate = (request: Record<string, unknown>) => Promise<any>;
/** Fixed labels only: native errors may contain paths or profile identifiers. */
export function callErrorCode(error: unknown): string {
  const message = error instanceof Error ? error.message : error;
  if (
    typeof message === "string" &&
    [
      "updateRequired",
      "ended",
      "unavailable",
      "unauthorized",
      "already_joined",
      "invalid",
      "full",
      "media_limit",
    ].includes(message)
  )
    return message;
  if (message === "Invalid call media layout") return "media_layout";
  if (message === "invalid ELO1 framing or size") return "record_framing";
  if (message === "invalid strict JSON or record schema")
    return "record_schema";
  if (message === "invalid record signature or signing key")
    return "record_signature";
  if (message === "record does not match trusted authority context")
    return "record_authority";
  const name = error instanceof Error ? error.name : "native_error";
  return [
    "Error",
    "OperationError",
    "InvalidStateError",
    "NotAllowedError",
    "NotSupportedError",
    "TypeError",
    "native_error",
  ].includes(name)
    ? name
    : "unknown_error";
}
export const operate: Operate = (request) => invoke("operate", { request });
export const requestContext = (chat: Stream, identity: string) => ({
  expected_identity: identity,
  target_space: chat.space_context,
  hosting_space_id: chat.space_context,
  space: chat.space,
  stream: chat.stream,
});
/** One in-flight signed command per socket; unsolicited presence/signals are independent. */
export class Control {
  private socket?: WebSocket;
  private opening?: Promise<void>;
  private cancelOpening?: () => void;
  private queue: Promise<unknown> = Promise.resolve();
  private pending?: {
    resolve: (value: Result) => void;
    reject: (e: Error) => void;
    timer: ReturnType<typeof setTimeout>;
  };
  private closed = false;
  constructor(
    readonly url: string,
    private identity: string,
    private onEvent: (value: Result) => void,
    private onClose: () => void,
    private native: Operate = operate,
  ) {}
  private connect() {
    if (this.closed) return Promise.reject(new Error("ended"));
    if (this.socket?.readyState === WebSocket.OPEN) return Promise.resolve();
    if (this.opening) return this.opening;
    const opening = new Promise<void>((resolve, reject) => {
      const address = new URL(this.url + "/connect");
      address.protocol = address.protocol === "https:" ? "wss:" : "ws:";
      const socket = (this.socket = new WebSocket(address));
      const current = () => this.socket === socket;
      const unavailable = () =>
        reject(new Error(this.closed ? "ended" : "unavailable"));
      this.cancelOpening = unavailable;
      const timer = setTimeout(() => {
        unavailable();
        socket.close();
      }, 8000);
      socket.onopen = () => {
        clearTimeout(timer);
        if (!current() || this.closed) {
          unavailable();
          socket.close();
          return;
        }
        resolve();
      };
      socket.onerror = () => {
        clearTimeout(timer);
        unavailable();
        socket.close();
      };
      socket.onclose = () => {
        clearTimeout(timer);
        unavailable();
        if (!current()) return;
        this.socket = undefined;
        if (this.pending) {
          clearTimeout(this.pending.timer);
          this.pending.reject(new Error("unavailable"));
          this.pending = undefined;
        }
        if (!this.closed) this.onClose();
      };
      socket.onmessage = (event) => {
        if (!current() || this.closed) return;
        if (
          typeof event.data !== "string" ||
          event.data.length > 2 * 1024 * 1024
        )
          return socket.close();
        try {
          const value = JSON.parse(event.data) as Result;
          if (
            (value.type === "result" || value.type === "error") &&
            this.pending
          ) {
            const pending = this.pending;
            this.pending = undefined;
            clearTimeout(pending.timer);
            if (value.type === "error")
              pending.reject(new Error(value.code ?? "unavailable"));
            else pending.resolve(value);
          } else this.onEvent(value);
        } catch {
          socket.close();
        }
      };
    });
    this.opening = opening;
    // A socket can close before onopen/onerror. Always settle that attempt so
    // the signed-command queue can reconnect instead of waiting forever.
    void opening.then(
      () => this.clearOpening(opening),
      () => this.clearOpening(opening),
    );
    return opening;
  }
  private clearOpening(opening: Promise<void>) {
    if (this.opening === opening) {
      this.opening = undefined;
      this.cancelOpening = undefined;
    }
  }
  command(chat: Stream, operation: Record<string, unknown>): Promise<Result> {
    const task = this.queue
      .catch(() => {})
      .then(async () => {
        if (this.closed) throw new Error("ended");
        // Sign before opening so proof generation cannot consume the authentication window.
        const signed = await this.native({
          ...requestContext(chat, this.identity),
          op: "call_authorization",
          audience: this.url,
          include_proof: true,
          operation,
        });
        await this.connect();
        const socket = this.socket;
        if (this.closed) throw new Error("ended");
        if (!socket || socket.readyState !== WebSocket.OPEN)
          throw new Error("unavailable");
        return new Promise<Result>((resolve, reject) => {
          const timer = setTimeout(() => {
            this.pending = undefined;
            socket.close();
            reject(new Error("unavailable"));
          }, 12000);
          this.pending = { resolve, reject, timer };
          try {
            socket.send(
              JSON.stringify({ command: signed.command, proof: signed.proof }),
            );
          } catch {
            clearTimeout(timer);
            this.pending = undefined;
            socket.close();
            reject(new Error("unavailable"));
          }
        });
      });
    this.queue = task;
    return task;
  }
  close() {
    this.closed = true;
    this.cancelOpening?.();
    if (this.pending) {
      clearTimeout(this.pending.timer);
      this.pending.reject(new Error("ended"));
      this.pending = undefined;
    }
    this.socket?.close();
  }
}
