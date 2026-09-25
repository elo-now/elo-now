import { afterEach, beforeEach, expect, test, vi } from "vitest";
import {
  acceptView,
  startLiveSync,
  type LiveContext,
  type SyncResult,
} from "./liveSync";
import type { View } from "./model";
import { pauseBackgroundSync } from "./backgroundSyncPause";

let page: EventTarget & { visibilityState: string };
let context: LiveContext;
let worker: ReturnType<typeof startLiveSync> | undefined;
const result = (identity = "alice", revision = 1): SyncResult => ({
  view: { identity, revision } as View,
});
beforeEach(() => {
  vi.useFakeTimers();
  vi.spyOn(Math, "random").mockReturnValue(0);
  page = Object.assign(new EventTarget(), { visibilityState: "visible" });
  vi.stubGlobal("document", page);
  vi.stubGlobal("window", new EventTarget());
  vi.stubGlobal("navigator", { onLine: true });
  context = {
    messages: true,
    invitations: false,
    conversation: false,
    busy: false,
  };
});
afterEach(() => {
  worker?.stop();
  vi.useRealTimers();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});
test("unlocked foreground sync starts once and adapts to the open conversation", async () => {
  const deliver = vi.fn(async () => result());
  worker = startLiveSync("alice", () => context, deliver, vi.fn());
  await vi.advanceTimersByTimeAsync(250);
  expect(deliver).toHaveBeenCalledTimes(1);
  await vi.advanceTimersByTimeAsync(19_999);
  expect(deliver).toHaveBeenCalledTimes(1);
  await vi.advanceTimersByTimeAsync(1);
  expect(deliver).toHaveBeenCalledTimes(2);
  context.conversation = true;
  worker.changed();
  await vi.advanceTimersByTimeAsync(4_000);
  expect(deliver).toHaveBeenCalledTimes(3);
  await vi.advanceTimersByTimeAsync(4_000);
  expect(deliver).toHaveBeenCalledTimes(4);
});

test("a foreground priority operation holds queued discovery until it finishes", async () => {
  context.invitations = true;
  context.busy = true;
  const deliver = vi.fn(async () => result());
  worker = startLiveSync("alice", () => context, deliver, vi.fn());
  page.dispatchEvent(new Event("visibilitychange"));
  worker.request(true);
  await vi.advanceTimersByTimeAsync(12_000);
  expect(deliver).not.toHaveBeenCalled();
  context.busy = false;
  await vi.advanceTimersByTimeAsync(500);
  expect(deliver).toHaveBeenNthCalledWith(1, "sync_live", false, true);
  expect(deliver).toHaveBeenNthCalledWith(2, "invitation_sync", true);
});

test("Space setup defers background work until every setup owner has left", async () => {
  context.invitations = true;
  const releaseSetup = pauseBackgroundSync();
  const releaseNested = pauseBackgroundSync();
  try {
    const deliver = vi.fn(async () => result());
    worker = startLiveSync("alice", () => context, deliver, vi.fn());
    worker.request(true);
    await vi.advanceTimersByTimeAsync(10_000);
    expect(deliver).not.toHaveBeenCalled();
    releaseSetup();
    releaseSetup();
    await vi.advanceTimersByTimeAsync(2_000);
    expect(deliver).not.toHaveBeenCalled();
    releaseNested();
    await vi.advanceTimersByTimeAsync(500);
    expect(deliver).toHaveBeenNthCalledWith(1, "sync_live", false, true);
    expect(deliver).toHaveBeenNthCalledWith(2, "invitation_sync", true);
  } finally {
    releaseSetup();
    releaseNested();
  }
});
test("hidden and offline clients stop polling and resume without overlapping calls", async () => {
  page.visibilityState = "hidden";
  let resolve!: (value: SyncResult) => void;
  const deliver = vi.fn(
    () =>
      new Promise<SyncResult>((done) => {
        resolve = done;
      }),
  );
  const update = vi.fn();
  worker = startLiveSync("alice", () => context, deliver, update);
  await vi.advanceTimersByTimeAsync(60_000);
  expect(deliver).not.toHaveBeenCalled();
  page.visibilityState = "visible";
  page.dispatchEvent(new Event("visibilitychange"));
  window.dispatchEvent(new Event("online"));
  await vi.advanceTimersByTimeAsync(100);
  expect(deliver).toHaveBeenCalledTimes(1);
  window.dispatchEvent(new Event("online"));
  await vi.advanceTimersByTimeAsync(500);
  expect(deliver).toHaveBeenCalledTimes(1);
  vi.stubGlobal("navigator", { onLine: false });
  window.dispatchEvent(new Event("offline"));
  resolve(result());
  await vi.advanceTimersByTimeAsync(60_000);
  expect(deliver).toHaveBeenCalledTimes(1);
  expect(update).toHaveBeenCalledTimes(1);
  vi.stubGlobal("navigator", { onLine: true });
  window.dispatchEvent(new Event("online"));
  await vi.advanceTimersByTimeAsync(100);
  expect(deliver).toHaveBeenCalledTimes(2);
  worker.stop();
  resolve(result());
  await vi.advanceTimersByTimeAsync(300_000);
  expect(update).toHaveBeenCalledTimes(1);
  expect(deliver).toHaveBeenCalledTimes(2);
});
test("another profile cannot receive the result of a pending sync", async () => {
  const update = vi.fn();
  worker = startLiveSync(
    "alice",
    () => context,
    async () => result("bob"),
    update,
  );
  await vi.advanceTimersByTimeAsync(250);
  expect(update).not.toHaveBeenCalled();
  const current = { identity: "alice", revision: 7 } as View;
  expect(acceptView(current, result("bob", 8).view!)).toBe(current);
  expect(acceptView(current, result("alice", 6).view!)).toBe(current);
  expect(acceptView(null, current)).toBeNull();
  expect(acceptView(current, result("alice", 8).view!)?.revision).toBe(8);
});
test("cold-start receipt retries twice promptly, then backs off transport failures", async () => {
  const deliver = vi
    .fn()
    .mockResolvedValueOnce({ ...result(), result: { retry: 1 } })
    .mockRejectedValue(new Error("Offline"));
  worker = startLiveSync("alice", () => context, deliver, vi.fn());
  await vi.advanceTimersByTimeAsync(250);
  expect(deliver).toHaveBeenCalledTimes(1);
  await vi.advanceTimersByTimeAsync(999);
  expect(deliver).toHaveBeenCalledTimes(1);
  await vi.advanceTimersByTimeAsync(1);
  expect(deliver).toHaveBeenCalledTimes(2);
  await vi.advanceTimersByTimeAsync(1_999);
  expect(deliver).toHaveBeenCalledTimes(2);
  await vi.advanceTimersByTimeAsync(1);
  expect(deliver).toHaveBeenCalledTimes(3);
  expect(deliver.mock.calls).toEqual(Array(3).fill(["sync_live", false, true]));
  await vi.advanceTimersByTimeAsync(39_999);
  expect(deliver).toHaveBeenCalledTimes(3);
  await vi.advanceTimersByTimeAsync(1);
  expect(deliver).toHaveBeenCalledTimes(4);
  expect(deliver).toHaveBeenLastCalledWith("sync_live");
});

test("cold start receives an active Space without a wake and respects retry delay during discovery", async () => {
  context.invitations = true;
  context.conversation = true;
  let received = false;
  const deliver = vi.fn(async (op: "sync_live" | "invitation_sync") => {
    if (op === "invitation_sync")
      return { identity: "alice", delivery: { retry: 1 } };
    if (!received) {
      received = true;
      return { identity: "alice", result: { retry: 1 } };
    }
    return {
      identity: "alice",
      result: { received_messages: ["after-restart"] },
    };
  });
  const update = vi.fn();
  worker = startLiveSync("alice", () => context, deliver, update);
  // No visibility, online, focus, request or navigation event after unlock.
  await vi.advanceTimersByTimeAsync(251);
  expect(deliver.mock.calls).toEqual([
    ["sync_live", false, true],
    ["invitation_sync"],
  ]);
  await vi.advanceTimersByTimeAsync(998);
  expect(deliver).toHaveBeenCalledTimes(2);
  await vi.advanceTimersByTimeAsync(1);
  expect(deliver).toHaveBeenLastCalledWith("sync_live", false, true);
  expect(update).toHaveBeenLastCalledWith({
    identity: "alice",
    result: { received_messages: ["after-restart"] },
  });
});

test("an unavailable Space cannot back off the next Space's message receipt", async () => {
  const deliver = vi
    .fn()
    .mockResolvedValueOnce({ identity: "alice" })
    .mockResolvedValueOnce({
      identity: "alice",
      result: { retry: 1, more: true, remaining_spaces: true },
    })
    .mockResolvedValue({
      identity: "alice",
      result: { received_messages: ["second-space"] },
    });
  const update = vi.fn();
  worker = startLiveSync("alice", () => context, deliver, update);
  await vi.advanceTimersByTimeAsync(20_250);
  expect(deliver).toHaveBeenCalledTimes(2);
  await vi.advanceTimersByTimeAsync(249);
  expect(deliver).toHaveBeenCalledTimes(2);
  await vi.advanceTimersByTimeAsync(1);
  expect(deliver).toHaveBeenCalledTimes(3);
  expect(update).toHaveBeenLastCalledWith({
    identity: "alice",
    result: { received_messages: ["second-space"] },
  });
});

test("reconnecting prioritizes receiving the open chat before discovery and clears old backoff", async () => {
  context.invitations = true;
  context.conversation = true;
  const deliver = vi.fn(async () => ({
    identity: "alice",
    result: { retry: 1 },
  }));
  worker = startLiveSync("alice", () => context, deliver, vi.fn());
  await vi.advanceTimersByTimeAsync(250);
  vi.stubGlobal("navigator", { onLine: false });
  window.dispatchEvent(new Event("offline"));
  const calls = deliver.mock.calls.length;
  await vi.advanceTimersByTimeAsync(60_000);
  expect(deliver).toHaveBeenCalledTimes(calls);
  vi.stubGlobal("navigator", { onLine: true });
  window.dispatchEvent(new Event("online"));
  await vi.advanceTimersByTimeAsync(100);
  expect(deliver.mock.calls[calls]).toEqual(["sync_live", false, true]);
  await vi.advanceTimersByTimeAsync(1);
  expect(deliver).toHaveBeenLastCalledWith("invitation_sync", true);
});

test("a missing online event cannot leave an open conversation offline indefinitely", async () => {
  vi.stubGlobal("navigator", { onLine: false });
  const deliver = vi.fn(async () => result());
  worker = startLiveSync("alice", () => context, deliver, vi.fn());
  await vi.advanceTimersByTimeAsync(10_000);
  expect(deliver).not.toHaveBeenCalled();
  vi.stubGlobal("navigator", { onLine: true });
  // No DOM event and no navigation: the foreground check must restart delivery.
  await vi.advanceTimersByTimeAsync(2_100);
  expect(deliver).toHaveBeenCalledExactlyOnceWith("sync_live", false, true);
  worker.stop();
  window.dispatchEvent(new Event("focus"));
  window.dispatchEvent(new Event("pageshow"));
  await vi.advanceTimersByTimeAsync(60_000);
  expect(deliver).toHaveBeenCalledTimes(1);
});

test("a connection wake during an in-flight discovery keeps one receive pass queued", async () => {
  context.invitations = true;
  let complete!: (value: SyncResult) => void;
  const deliver = vi.fn(
    () =>
      new Promise<SyncResult>((resolve) => {
        complete = resolve;
      }),
  );
  worker = startLiveSync("alice", () => context, deliver, vi.fn());
  await vi.advanceTimersByTimeAsync(250);
  complete(result());
  await vi.advanceTimersByTimeAsync(1);
  expect(deliver).toHaveBeenLastCalledWith("invitation_sync");
  window.dispatchEvent(new Event("online"));
  window.dispatchEvent(new Event("focus"));
  await vi.advanceTimersByTimeAsync(500);
  expect(deliver).toHaveBeenCalledTimes(2);
  complete(result());
  await vi.advanceTimersByTimeAsync(1);
  expect(deliver).toHaveBeenCalledTimes(3);
  expect(deliver).toHaveBeenLastCalledWith("sync_live", false, true);
  worker.stop();
  complete(result());
});
test("message and invitation delivery share one worker and keep separate cadences", async () => {
  context.invitations = true;
  const deliver = vi.fn(async (_op: "sync_live" | "invitation_sync") =>
    result(),
  );
  worker = startLiveSync("alice", () => context, deliver, vi.fn());
  await vi.advanceTimersByTimeAsync(251);
  expect(deliver.mock.calls).toEqual([
    ["sync_live", false, true],
    ["invitation_sync"],
  ]);
  await vi.advanceTimersByTimeAsync(20_000);
  expect(deliver.mock.calls.map((call) => call[0])).toEqual([
    "sync_live",
    "invitation_sync",
    "sync_live",
  ]);
  await vi.advanceTimersByTimeAsync(10_000);
  expect(deliver).toHaveBeenLastCalledWith("invitation_sync");
});
test("a send while syncing requests one additional pass and local work is not blocked by a spinner", async () => {
  let resolve!: (value: SyncResult) => void;
  const deliver = vi.fn(
    () =>
      new Promise<SyncResult>((done) => {
        resolve = done;
      }),
  );
  worker = startLiveSync("alice", () => context, deliver, vi.fn());
  context.busy = true;
  await vi.advanceTimersByTimeAsync(1_000);
  expect(deliver).not.toHaveBeenCalled();
  context.busy = false;
  await vi.advanceTimersByTimeAsync(500);
  expect(deliver).toHaveBeenCalledTimes(1);
  worker.request();
  worker.request();
  resolve(result());
  await vi.advanceTimersByTimeAsync(1);
  expect(deliver).toHaveBeenCalledTimes(2);
  resolve(result());
  await vi.advanceTimersByTimeAsync(1_000);
  expect(deliver).toHaveBeenCalledTimes(2);
});
test("a profile without delivery configuration makes no network requests", async () => {
  context.messages = false;
  const deliver = vi.fn(async () => result());
  worker = startLiveSync("alice", () => context, deliver, vi.fn());
  await vi.advanceTimersByTimeAsync(60_000);
  expect(deliver).not.toHaveBeenCalled();
  context.messages = true;
  worker.changed();
  await vi.advanceTimersByTimeAsync(100);
  expect(deliver).toHaveBeenCalledTimes(1);
});

test("backlog pages drain promptly without a view and return to idle polling", async () => {
  const update = vi.fn(),
    progress = vi.fn();
  const deliver = vi
    .fn()
    .mockResolvedValueOnce({
      identity: "alice",
      result: { more: true, received_messages: ["one", "two"] },
    })
    .mockResolvedValueOnce({
      identity: "alice",
      result: { more: true, received_messages: ["three"] },
    })
    .mockResolvedValue({ identity: "alice", result: { more: false } });
  worker = startLiveSync("alice", () => context, deliver, update, progress);
  await vi.advanceTimersByTimeAsync(250);
  expect(progress).toHaveBeenLastCalledWith({
    phase: "receiving",
    received: 2,
  });
  await vi.advanceTimersByTimeAsync(250);
  expect(progress).toHaveBeenLastCalledWith({
    phase: "receiving",
    received: 3,
  });
  await vi.advanceTimersByTimeAsync(250);
  expect(progress).toHaveBeenLastCalledWith(null);
  expect(update).toHaveBeenCalledTimes(3);
  await vi.advanceTimersByTimeAsync(19_999);
  expect(deliver).toHaveBeenCalledTimes(3);
  await vi.advanceTimersByTimeAsync(1);
  expect(deliver).toHaveBeenCalledTimes(4);
});

test("backlog waits offline and backs off retries before resuming", async () => {
  const progress = vi.fn();
  const deliver = vi
    .fn()
    .mockResolvedValueOnce({
      identity: "alice",
      result: { more: true, received_messages: ["one"] },
    })
    .mockResolvedValueOnce({
      identity: "alice",
      result: { more: true, retry: 1 },
    })
    .mockResolvedValue({ identity: "alice", result: { more: false } });
  worker = startLiveSync("alice", () => context, deliver, vi.fn(), progress);
  await vi.advanceTimersByTimeAsync(250);
  vi.stubGlobal("navigator", { onLine: false });
  window.dispatchEvent(new Event("offline"));
  expect(progress).toHaveBeenLastCalledWith({ phase: "waiting", received: 1 });
  await vi.advanceTimersByTimeAsync(60_000);
  expect(deliver).toHaveBeenCalledTimes(1);
  vi.stubGlobal("navigator", { onLine: true });
  window.dispatchEvent(new Event("online"));
  await vi.advanceTimersByTimeAsync(100);
  expect(progress).toHaveBeenLastCalledWith({ phase: "waiting", received: 1 });
  await vi.advanceTimersByTimeAsync(999);
  expect(deliver).toHaveBeenCalledTimes(2);
  await vi.advanceTimersByTimeAsync(1);
  expect(deliver).toHaveBeenCalledTimes(3);
  expect(progress).toHaveBeenLastCalledWith(null);
});

test("an idle Space round has no progress banner and stale identities have no effect", async () => {
  const progress = vi.fn(),
    update = vi.fn();
  const deliver = vi
    .fn()
    .mockResolvedValueOnce({ identity: "bob", result: { more: true } })
    .mockResolvedValueOnce({
      identity: "alice",
      view: { identity: "bob" },
      result: { more: true },
    })
    .mockResolvedValue({
      identity: "alice",
      result: { more: true, catching_up: false },
    });
  worker = startLiveSync("alice", () => context, deliver, update, progress);
  await vi.advanceTimersByTimeAsync(20_250);
  expect(progress).not.toHaveBeenCalled();
  expect(update).not.toHaveBeenCalled();
  await vi.advanceTimersByTimeAsync(20_000);
  expect(progress).toHaveBeenLastCalledWith(null);
  await vi.advanceTimersByTimeAsync(250);
  expect(deliver).toHaveBeenCalledTimes(4);
});

test("discovery backlog drains promptly and a received DM configuration wakes message delivery", async () => {
  context.invitations = true;
  let pages = 0;
  const deliver = vi.fn(async (op: "sync_live" | "invitation_sync") => {
    if (op === "sync_live") return { identity: "alice" };
    pages++;
    return {
      identity: "alice",
      delivery: { more: pages < 3, received: pages === 3 ? 1 : 0 },
    };
  });
  worker = startLiveSync("alice", () => context, deliver, vi.fn());
  await vi.advanceTimersByTimeAsync(752);
  expect(deliver.mock.calls.map(([op]) => op)).toEqual([
    "sync_live",
    "invitation_sync",
    "invitation_sync",
    "invitation_sync",
    "sync_live",
  ]);
  expect(pages).toBe(3);
  await vi.advanceTimersByTimeAsync(29_999);
  expect(pages).toBe(4);
});

test("committed discovery progress continues despite a concurrent Space status failure", async () => {
  context.invitations = true;
  context.messages = false;
  const deliver = vi
    .fn()
    .mockResolvedValueOnce({
      identity: "alice",
      delivery: { more: true, retry: 1, progressed: true },
    })
    .mockResolvedValue({
      identity: "alice",
      delivery: { more: true, retry: 1, progressed: false },
    });
  worker = startLiveSync("alice", () => context, deliver, vi.fn());
  await vi.advanceTimersByTimeAsync(500);
  expect(deliver).toHaveBeenCalledTimes(2);
  await vi.advanceTimersByTimeAsync(59_999);
  expect(deliver).toHaveBeenCalledTimes(2);
  await vi.advanceTimersByTimeAsync(1);
  expect(deliver).toHaveBeenCalledTimes(3);
});

test("discovery backlog retains network backoff and stops while hidden", async () => {
  context.invitations = true;
  context.messages = false;
  const deliver = vi.fn(async () => ({
    identity: "alice",
    delivery: { more: true, retry: 1 },
  }));
  worker = startLiveSync("alice", () => context, deliver, vi.fn());
  await vi.advanceTimersByTimeAsync(250);
  await vi.advanceTimersByTimeAsync(59_999);
  expect(deliver).toHaveBeenCalledTimes(1);
  await vi.advanceTimersByTimeAsync(1);
  expect(deliver).toHaveBeenCalledTimes(2);
  page.visibilityState = "hidden";
  page.dispatchEvent(new Event("visibilitychange"));
  await vi.advanceTimersByTimeAsync(300_000);
  expect(deliver).toHaveBeenCalledTimes(2);
});

test("a failed Space yields to remaining Spaces before retry backoff", async () => {
  context.invitations = true;
  context.messages = false;
  const deliver = vi
    .fn()
    .mockResolvedValueOnce({
      identity: "alice",
      delivery: { retry: 1, more: true, remaining_spaces: true },
    })
    .mockResolvedValue({ identity: "alice", delivery: { more: false } });
  worker = startLiveSync("alice", () => context, deliver, vi.fn());
  await vi.advanceTimersByTimeAsync(250);
  expect(deliver).toHaveBeenCalledTimes(1);
  await vi.advanceTimersByTimeAsync(250);
  expect(deliver).toHaveBeenCalledTimes(2);
  await vi.advanceTimersByTimeAsync(29_999);
  expect(deliver).toHaveBeenCalledTimes(2);
});

test("a new pending Space bypasses old discovery backoff without repeated polling wakes", async () => {
  context.invitations = true;
  context.messages = false;
  const deliver = vi
    .fn()
    .mockResolvedValueOnce({ identity: "alice", delivery: { retry: 1 } })
    .mockResolvedValue({ identity: "alice", delivery: { retry: 0 } });
  worker = startLiveSync("alice", () => context, deliver, vi.fn());
  await vi.advanceTimersByTimeAsync(250);
  expect(deliver).toHaveBeenCalledTimes(1);

  context.pendingSpaces = ["new-space"];
  worker.changed();
  await vi.advanceTimersByTimeAsync(100);
  expect(deliver).toHaveBeenCalledTimes(2);
  expect(deliver).toHaveBeenLastCalledWith("invitation_sync", true);

  // New view objects and ordinary navigation must not repeatedly hit the server.
  context.pendingSpaces = ["new-space"];
  worker.changed();
  await vi.advanceTimersByTimeAsync(1_000);
  context.pendingSpaces = [];
  worker.changed();
  await vi.advanceTimersByTimeAsync(1_000);
  expect(deliver).toHaveBeenCalledTimes(2);
});

test("an explicit membership wake overrides polling delay and survives an in-flight pass", async () => {
  context.invitations = true;
  context.messages = false;
  let resolve!: (value: SyncResult) => void;
  const deliver = vi.fn(
    () =>
      new Promise<SyncResult>((done) => {
        resolve = done;
      }),
  );
  worker = startLiveSync("alice", () => context, deliver, vi.fn());
  await vi.advanceTimersByTimeAsync(250);
  worker.request(true);
  resolve({ identity: "alice" });
  await vi.advanceTimersByTimeAsync(1);
  expect(deliver.mock.calls).toEqual([
    ["invitation_sync"],
    ["invitation_sync", true],
  ]);
  resolve({ identity: "alice" });
  await vi.advanceTimersByTimeAsync(1_000);
  expect(deliver).toHaveBeenCalledTimes(2);
});

test("repeated push hints during discovery cannot starve message delivery", async () => {
  context.invitations = true;
  let complete!: (value: SyncResult) => void;
  const deliver = vi.fn(
    () =>
      new Promise<SyncResult>((resolve) => {
        complete = resolve;
      }),
  );
  const update = vi.fn();
  worker = startLiveSync("alice", () => context, deliver, update);
  await vi.advanceTimersByTimeAsync(250);
  complete({ identity: "alice" });
  await vi.advanceTimersByTimeAsync(1);
  expect(deliver).toHaveBeenLastCalledWith("invitation_sync");
  // The pending native push used to request both loops again on every status poll.
  worker.request(true);
  complete({ identity: "alice", delivery: { more: true } });
  await vi.advanceTimersByTimeAsync(1);
  expect(deliver).toHaveBeenLastCalledWith("sync_live");
  complete({ ...result(), result: { received_messages: ["new-message"] } });
  await vi.advanceTimersByTimeAsync(1);
  expect(update).toHaveBeenCalledWith(
    expect.objectContaining({ result: { received_messages: ["new-message"] } }),
  );
  expect(deliver).toHaveBeenLastCalledWith("invitation_sync", true);
});
