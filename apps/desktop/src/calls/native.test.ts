import { describe, expect, it, vi } from "vitest";
import type { Stream } from "../model";
import type { ActiveCall, Snapshot } from "./types";
import { NativeCallSession, type NativeCall } from "./native";
function fixture() {
  const chat = { space: "space", stream: "chat" } as Stream;
  const call = { call_id: "call", kind: "direct", ringing: true } as ActiveCall;
  let state: Snapshot = {
    phase: "idle",
    media: {
      audio_muted: false,
      video_published: false,
      screen_published: false,
    },
    tiles: [],
    available: {},
    incoming: { chat, call },
  };
  const controller = {
    getSnapshot: () => state,
    start: vi.fn(async () => {
      state = { ...state, active: call, phase: "connecting" };
    }),
    leave: vi.fn(async () => {
      state = { ...state, active: undefined, phase: "idle" };
    }),
    decline: vi.fn(async () => {
      state = { ...state, incoming: undefined };
    }),
    toggle: vi.fn(async () => {
      state.media.audio_muted = !state.media.audio_muted;
    }),
    setNativeAnswer: vi.fn((nativeAnswer: Snapshot["nativeAnswer"]) => {
      state = { ...state, nativeAnswer };
    }),
  };
  const action = vi.fn(async (_op: string) => {});
  const session = new NativeCallSession(controller, "me", action);
  const native: NativeCall = {
    id: "call",
    action: "answer",
    expires: 200,
    target: { identity: "me", space: "space", stream: "chat" },
  };
  return {
    session,
    controller,
    action,
    native,
    chat,
    call,
    update: (patch: Partial<Snapshot>) => {
      state = { ...state, ...patch };
    },
  };
}
describe("native incoming call admission", () => {
  it("answers a verified current direct call once, with camera off", async () => {
    const f = fixture();
    await f.session.consume(f.native, 100);
    await f.session.consume(f.native, 100);
    expect(f.controller.start).toHaveBeenCalledExactlyOnceWith(
      f.chat,
      false,
      f.call,
    );
    f.update({ phase: "connected" });
    await f.session.consume(f.native, 100);
    expect(f.action).toHaveBeenCalledWith("calls_connected:call");
    f.update({ phase: "idle", active: undefined });
    await f.session.consume(null, 100);
    expect(f.action).toHaveBeenCalledWith("calls_end:call");
  });
  it.each([null, { identity: "other", space: "space", stream: "chat" }])(
    "never opens another or unverifiable profile",
    async (target) => {
      const f = fixture();
      await f.session.consume({ ...f.native, target }, 100);
      expect(f.controller.start).not.toHaveBeenCalled();
      expect(f.action).toHaveBeenCalledWith("calls_end:call");
    },
  );
  it("waits for authenticated signaling and rejects expired Answer", async () => {
    const f = fixture();
    f.update({ incoming: undefined });
    await f.session.consume(f.native, 100);
    expect(f.controller.start).not.toHaveBeenCalled();
    expect(f.controller.getSnapshot().nativeAnswer?.id).toBe(f.native.id);
    await f.session.consume(f.native, 201);
    expect(f.action).toHaveBeenCalledWith("calls_end:call");
    expect(f.controller.getSnapshot().nativeAnswer).toBeUndefined();
  });
  it("lets the user cancel while waiting for signaling and never joins a late offer", async () => {
    const f = fixture();
    f.update({ incoming: undefined });
    await f.session.consume(f.native, 100);
    f.controller.getSnapshot().nativeAnswer!.cancel();
    expect(f.action).toHaveBeenCalledWith("calls_end:call");
    expect(f.controller.getSnapshot().nativeAnswer).toBeUndefined();
    f.update({ incoming: { chat: f.chat, call: f.call } });
    await f.session.consume(f.native, 101);
    expect(f.controller.start).not.toHaveBeenCalled();
  });
  it("clears pending Answer when the native ring ends or the profile closes", async () => {
    const f = fixture();
    f.update({ incoming: undefined });
    await f.session.consume(f.native, 100);
    await f.session.consume(null, 101);
    expect(f.controller.getSnapshot().nativeAnswer).toBeUndefined();
    await f.session.consume(f.native, 102);
    f.session.stop();
    expect(f.controller.getSnapshot().nativeAnswer).toBeUndefined();
  });
  it("does not join a different chat or call from a native payload", async () => {
    for (const patch of [
      { id: "other" },
      { target: { identity: "me", space: "space", stream: "other" } },
    ]) {
      const f = fixture();
      await f.session.consume({ ...f.native, ...patch }, 100);
      expect(f.controller.start).not.toHaveBeenCalled();
    }
  });
  it("does not consume Answer after the profile is locked or switched", async () => {
    const f = fixture();
    f.session.stop();
    await f.session.consume(f.native, 100);
    expect(f.controller.start).not.toHaveBeenCalled();
    expect(f.action).not.toHaveBeenCalled();
  });
  it("ends the native call when media admission fails", async () => {
    const f = fixture();
    f.controller.start.mockImplementation(async () => {});
    await f.session.consume(f.native, 100);
    expect(f.action).toHaveBeenCalledWith("calls_end:call");
  });
  it("applies native mute and acknowledges the exact event, then handles hangup", async () => {
    const f = fixture();
    f.update({ active: f.call, phase: "connected" });
    await f.session.consume(
      { ...f.native, action: "mute", event: "mute-event", muted: true },
      100,
    );
    expect(f.controller.getSnapshot().media.audio_muted).toBe(true);
    expect(f.action).toHaveBeenCalledWith("calls_ack:call:mute-event");
    await f.session.consume(
      { ...f.native, action: "decline", event: "end-event" },
      100,
    );
    expect(f.controller.leave).toHaveBeenCalledOnce();
    expect(f.action).toHaveBeenCalledWith("calls_ack:call:end-event");
  });
});
