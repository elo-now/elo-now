import { afterEach, expect, it, vi } from "vitest";
import { NativePeer, type NativeRequest } from "./nativePeer";
import type { MediaTile } from "./types";

function setup() {
  vi.useFakeTimers();
  vi.stubGlobal("MediaStream", class {});
  let state: Record<string, unknown> = {
    native_owned: true,
    connection: "connected",
    call: { call_id: "session", key_epoch: 1 },
    remote: null,
    revision: 1,
    signals: [{ type: "offer", sdp: "owned-by-native" }],
    tracks: [{ id: "local", local: true, source: "camera" }],
  };
  const transport = vi.fn<NativeRequest>(async (request) =>
    request.op === "poll" ? state : {},
  );
  const tiles = vi.fn<(tiles: MediaTile[]) => void>();
  const connected = vi.fn();
  const failed = vi.fn();
  const presence = vi.fn();
  const peer = new NativePeer(
    "local-device",
    "identity",
    tiles,
    failed,
    connected,
    presence,
    transport,
    { call_id: "session" },
  );
  return {
    peer,
    transport,
    tiles,
    connected,
    failed,
    presence,
    setState: (update: Record<string, unknown>) =>
      (state = { ...state, ...update }),
  };
}
afterEach(() => {
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

it("reads native session snapshots without duplicating signaling or unchanged presence", async () => {
  const f = setup();
  await vi.advanceTimersByTimeAsync(0);
  expect(f.transport).toHaveBeenCalledWith(
    expect.objectContaining({
      op: "start",
      ice_servers: [],
      context: { call_id: "session" },
    }),
  );
  expect(f.connected).toHaveBeenCalledOnce();
  expect(f.presence).toHaveBeenCalledOnce();
  await vi.advanceTimersByTimeAsync(450);
  expect(f.presence).toHaveBeenCalledOnce();
  expect(f.tiles).toHaveBeenCalledOnce();
  expect(
    f.transport.mock.calls.every(([request]) =>
      ["start", "poll"].includes(request.op as string),
    ),
  ).toBe(true);
  f.setState({
    call: { call_id: "session", key_epoch: 2 },
    remote: "peer-device",
    tracks: [{ id: "remote", local: false, source: "camera" }],
  });
  await vi.advanceTimersByTimeAsync(150);
  expect(f.presence).toHaveBeenCalledTimes(2);
  expect(f.tiles.mock.lastCall?.[0][0].credential).toBe("peer-device");
  await f.peer.stop();
});

it("leaves transient disconnect recovery to native and reports terminal failure", async () => {
  const f = setup();
  await vi.advanceTimersByTimeAsync(0);
  f.setState({ connection: "disconnected", call: null });
  await vi.advanceTimersByTimeAsync(5000);
  expect(f.failed).not.toHaveBeenCalled();
  expect(f.presence).toHaveBeenCalledOnce();
  f.setState({ connection: "failed" });
  await vi.advanceTimersByTimeAsync(150);
  expect(f.failed).toHaveBeenCalledOnce();
  await f.peer.stop();
});

it("waits for a pending native start before stopping its matching peer", async () => {
  let started!: () => void;
  const transport = vi.fn<NativeRequest>(async (request) => {
    if (request.op === "start")
      await new Promise<void>((resolve) => (started = resolve));
    return {};
  });
  const peer = new NativePeer(
    "local",
    "identity",
    vi.fn(),
    vi.fn(),
    vi.fn(),
    vi.fn(),
    transport,
  );
  const stopping = peer.stop();
  expect(transport.mock.calls.map(([request]) => request.op)).toEqual([
    "start",
  ]);
  started();
  await stopping;
  expect(transport.mock.calls.map(([request]) => request.op)).toEqual([
    "start",
    "stop",
  ]);
  expect(transport.mock.calls[1][0].id).toBe(peer.id);
});

it("invalidates native render bindings after a reset preserves the same camera track", async () => {
  const f = setup();
  await vi.advanceTimersByTimeAsync(0);
  const before = f.tiles.mock.lastCall![0][0].native!;
  f.setState({ revision: 2 });
  await vi.advanceTimersByTimeAsync(150);
  const after = f.tiles.mock.lastCall![0][0].native!;
  expect(after.session).toBe(before.session);
  expect(after.track).toBe(before.track);
  expect(before.revision).toBe(1);
  expect(after.revision).toBe(2);
  expect(f.tiles).toHaveBeenCalledTimes(2);
  await f.peer.stop();
});

it("adopts an existing native capture without starting a second peer or signaling", async () => {
  vi.useFakeTimers();
  const transport = vi.fn<NativeRequest>(async (request) =>
    request.op === "poll"
      ? { native_owned: true, connection: "connected", tracks: [], signals: [] }
      : {},
  );
  const connected = vi.fn();
  const peer = new NativePeer(
    "device",
    "identity",
    vi.fn(),
    vi.fn(),
    connected,
    vi.fn(),
    transport,
    undefined,
    { sessionId: "12345678-1234-1234-1234-123456789abc" },
  );
  await vi.advanceTimersByTimeAsync(0);
  expect(connected).toHaveBeenCalledOnce();
  expect(transport.mock.calls.map(([request]) => request.op)).toEqual(["poll"]);
  await peer.stop();
  expect(
    transport.mock.calls.every(
      ([request]) => request.id === "12345678-1234-1234-1234-123456789abc",
    ),
  ).toBe(true);
  expect(transport.mock.calls.map(([request]) => request.op)).toEqual([
    "poll",
    "stop",
  ]);
});
