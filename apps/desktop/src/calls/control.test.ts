import { afterEach, describe, it, expect, vi } from "vitest";
import { Control, callErrorCode } from "./control";
import type { Stream } from "../model";
afterEach(() => {
  vi.unstubAllGlobals();
  vi.useRealTimers();
});
describe("call control transport", () => {
  it("keeps native error contents and custom exception names out of call error codes", () => {
    const error = new Error("private profile path /Users/example/profile");
    error.name = "private-profile-name";
    expect(callErrorCode(error)).toBe("unknown_error");
    expect(callErrorCode("private native error with credentials")).toBe(
      "native_error",
    );
    expect(callErrorCode(new Error("unauthorized"))).toBe("unauthorized");
    expect(
      callErrorCode("record does not match trusted authority context"),
    ).toBe("record_authority");
  });
  it("sends only the signed command and proof, excluding native response annotations", async () => {
    let sent: Record<string, unknown> | undefined;
    class Socket {
      static OPEN = 1;
      readyState = 1;
      onopen?: () => void;
      onmessage?: (event: { data: string }) => void;
      onclose?: () => void;
      constructor(readonly url: URL) {
        queueMicrotask(() => this.onopen?.());
      }
      send(value: string) {
        sent = JSON.parse(value);
        queueMicrotask(() =>
          this.onmessage?.({
            data: JSON.stringify({ type: "result", call: null }),
          }),
        );
      }
      close() {
        this.onclose?.();
      }
    }
    vi.stubGlobal("WebSocket", Socket);
    const native = vi.fn(async () => ({
      command: "signed",
      proof: { v: 1 },
      identity: "native annotation",
    }));
    const control = new Control(
      "https://private.example/calls/v1",
      "identity",
      () => {},
      () => {},
      native,
    );
    await control.command(
      { space_context: "hosted", space: "genesis", stream: "stream" } as Stream,
      { type: "subscribe" },
    );
    expect(sent).toEqual({ command: "signed", proof: { v: 1 } });
    expect(native.mock.calls[0]).toBeDefined();
    control.close();
    vi.unstubAllGlobals();
  });
  it("does not send commands after disposal", async () => {
    const control = new Control(
      "https://private.example/calls/v1",
      "identity",
      () => {},
      () => {},
      async () => ({ command: "signed", proof: null }),
    );
    control.close();
    await expect(
      control.command({} as Stream, { type: "subscribe" }),
    ).rejects.toThrow("ended");
  });
  it("recovers when the socket closes during opening without an error event", async () => {
    const sockets: Socket[] = [];
    class Socket {
      static OPEN = 1;
      readyState = 0;
      onopen?: () => void;
      onmessage?: (event: { data: string }) => void;
      onclose?: () => void;
      constructor() {
        sockets.push(this);
      }
      send() {
        this.onmessage?.({ data: JSON.stringify({ type: "result" }) });
      }
      close() {
        this.readyState = 3;
        this.onclose?.();
      }
    }
    vi.stubGlobal("WebSocket", Socket);
    const closed = vi.fn();
    const control = new Control(
      "https://private.example/calls/v1",
      "me",
      () => {},
      closed,
      async () => ({ command: "signed" }),
    );
    const first = control.command({} as Stream, { type: "subscribe" });
    const rejected = expect(first).rejects.toThrow("unavailable");
    await vi.waitFor(() => expect(sockets).toHaveLength(1));
    sockets[0].close();
    await rejected;
    expect(closed).toHaveBeenCalledOnce();
    const second = control.command({} as Stream, { type: "subscribe" });
    await vi.waitFor(() => expect(sockets).toHaveLength(2));
    sockets[1].readyState = 1;
    sockets[1].onopen?.();
    await expect(second).resolves.toMatchObject({ type: "result" });
    // A delayed callback from the old socket cannot disconnect its replacement.
    sockets[0].close();
    expect(closed).toHaveBeenCalledOnce();
    await expect(
      control.command({} as Stream, { type: "subscribe" }),
    ).resolves.toMatchObject({ type: "result" });
    control.close();
  });
  it("settles an in-flight command on disposal even before the close event arrives", async () => {
    const sockets: Socket[] = [];
    class Socket {
      static OPEN = 1;
      readyState = 1;
      onopen?: () => void;
      onmessage?: (event: { data: string }) => void;
      onclose?: () => void;
      constructor() {
        sockets.push(this);
        queueMicrotask(() => this.onopen?.());
      }
      send = vi.fn();
      close() {}
    }
    vi.stubGlobal("WebSocket", Socket);
    const control = new Control(
      "https://private.example/calls/v1",
      "me",
      () => {},
      () => {},
      async () => ({ command: "signed" }),
    );
    const request = control.command({} as Stream, { type: "join" });
    const rejected = expect(request).rejects.toThrow("ended");
    await vi.waitFor(() => expect(sockets[0]?.send).toHaveBeenCalled());
    control.close();
    await rejected;
  });
});
