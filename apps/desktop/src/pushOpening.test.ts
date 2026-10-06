import { afterEach, beforeEach, expect, test, vi } from "vitest";
import type { View } from "./model";

const runtime = vi.hoisted(() => ({
  cursor: 0,
  slots: [] as any[],
  effects: [] as (() => void)[],
  cleanups: new Map<number, () => void>(),
  invoke: vi.fn(),
  open: vi.fn(async () => true),
  sync: vi.fn(),
  error: vi.fn(),
  wake: undefined as (() => void) | undefined,
}));
vi.mock("react", async (original) => ({
  ...(await original<typeof import("react")>()),
  useRef: (initial: unknown) => {
    const index = runtime.cursor++;
    return (runtime.slots[index] ??= { current: initial });
  },
  useState: (initial: unknown) => {
    const index = runtime.cursor++;
    if (!(index in runtime.slots))
      runtime.slots[index] =
        typeof initial === "function" ? initial() : initial;
    return [
      runtime.slots[index],
      (value: unknown) => {
        runtime.slots[index] =
          typeof value === "function" ? value(runtime.slots[index]) : value;
      },
    ];
  },
  useEffect: (effect: () => void | (() => void), deps?: unknown[]) => {
    const index = runtime.cursor++;
    const previous = runtime.slots[index] as unknown[] | undefined;
    if (
      deps &&
      previous &&
      deps.length === previous.length &&
      deps.every((value, i) => Object.is(value, previous[i]))
    )
      return;
    runtime.slots[index] = deps;
    runtime.effects.push(() => {
      runtime.cleanups.get(index)?.();
      runtime.cleanups.delete(index);
      const cleanup = effect();
      if (cleanup) runtime.cleanups.set(index, cleanup);
    });
  },
}));
vi.mock("@tauri-apps/api/core", () => ({ invoke: runtime.invoke }));
vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn(async (_event: string, handler: () => void) => {
    runtime.wake = handler;
    return () => {
      runtime.wake = undefined;
    };
  }),
}));
import {
  NotificationOpeningAttempt,
  NOTIFICATION_OPEN_TIMEOUT_MS,
  usePushNotifications,
} from "./usePushNotifications";

const identity = "a".repeat(64);
const id = "b".repeat(64);
const target = {
  identity,
  category: "invitation",
  space: "work",
  chat: { space: "scope", stream: "chat", invitation: "proof" },
};
const baseView = {
  identity,
  active_space: "work",
  streams: [],
  spaces: [{ id: "work", status: "joined" }],
} as unknown as View;
const status = {
  available: true,
  enabled: true,
  pending: false,
  opened: { id, target },
};
let storage: Map<string, string>;
const never = () => new Promise(() => {});

function unmount() {
  runtime.cleanups.forEach((cleanup) => cleanup());
  runtime.cleanups.clear();
  runtime.effects = [];
  runtime.slots = [];
}
function render(view: View | null = baseView) {
  runtime.cursor = 0;
  const result = usePushNotifications(
    view,
    false,
    vi.fn(),
    runtime.sync,
    runtime.open,
    runtime.error,
  );
  while (runtime.effects.length) runtime.effects.shift()!();
  return result;
}
async function settle(view: View | null = baseView) {
  for (let i = 0; i < 4; i++) {
    await Promise.resolve();
    render(view);
  }
  return render(view);
}
beforeEach(() => {
  runtime.cursor = 0;
  runtime.slots = [];
  runtime.effects = [];
  runtime.cleanups = new Map();
  runtime.invoke.mockReset();
  runtime.open.mockReset().mockResolvedValue(true);
  runtime.sync.mockReset();
  runtime.error.mockReset();
  storage = new Map();
  vi.stubGlobal("localStorage", {
    getItem: (key: string) => storage.get(key) ?? null,
    setItem: (key: string, value: string) => storage.set(key, value),
  });
  vi.stubGlobal(
    "document",
    Object.assign(new EventTarget(), { visibilityState: "visible" }),
  );
  vi.stubGlobal("window", new EventTarget());
  vi.useFakeTimers();
  vi.setSystemTime(1_000_000);
});
afterEach(() => {
  unmount();
  vi.clearAllTimers();
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

test("a hung status after a native hint releases the UI and does not return after restart", async () => {
  runtime.invoke.mockImplementation((_command, payload) =>
    payload.op === "hint" ? Promise.resolve({ opened: id }) : never(),
  );
  render();
  expect((await settle()).showOpening).toBe(true);
  await vi.advanceTimersByTimeAsync(NOTIFICATION_OPEN_TIMEOUT_MS);
  const expired = await settle();
  expect(expired.showOpening).toBe(false);
  expect(expired.isOpening()).toBe(false);
  expect(runtime.error).toHaveBeenCalledOnce();
  expect(
    runtime.invoke.mock.calls.some(([, payload]) =>
      payload.op?.startsWith("ack:"),
    ),
  ).toBe(false);
  unmount();
  render();
  const restarted = await settle();
  expect(restarted.showOpening).toBe(false);
  expect(restarted.isOpening()).toBe(false);
  expect(runtime.open).not.toHaveBeenCalled();
});

test("status arriving after an anonymous deadline cannot start a second opening attempt", async () => {
  let resolveStatus!: (value: unknown) => void;
  runtime.invoke.mockImplementation((_command, payload) => {
    if (payload.op === "hint") return Promise.resolve({});
    if (payload.op === "status")
      return new Promise((done) => {
        resolveStatus = done;
      });
    return Promise.resolve(status);
  });
  render();
  await settle();
  await vi.advanceTimersByTimeAsync(30_000);
  resolveStatus(status);
  const result = await settle();
  expect(result.showOpening).toBe(false);
  expect(result.isOpening()).toBe(false);
  expect(runtime.open).not.toHaveBeenCalled();
  expect(
    runtime.invoke.mock.calls.some(([, payload]) => payload.op === `ack:${id}`),
  ).toBe(true);
  expect(runtime.error).toHaveBeenCalledOnce();
});

test("a fresh matching hint may authorize a late status within the new attempt's deadline", async () => {
  let resolveStatus!: (value: unknown) => void;
  let tapped = false;
  runtime.invoke.mockImplementation((_command, payload) => {
    if (payload.op === "hint")
      return Promise.resolve(tapped ? { opened: id } : {});
    if (payload.op === "status")
      return new Promise((done) => {
        resolveStatus = done;
      });
    return Promise.resolve(status);
  });
  render();
  await settle();
  await vi.advanceTimersByTimeAsync(9000);
  tapped = true;
  runtime.wake?.();
  await settle();
  resolveStatus(status);
  expect((await settle()).showOpening).toBe(true);
});

test.each(["old tap", "no tap", "error"])(
  "a stale status with %s cannot replace or cancel a newer hint",
  async (result) => {
    let resolveStatus!: (value: unknown) => void;
    let rejectStatus!: (error: Error) => void;
    let hintId = id;
    runtime.invoke.mockImplementation((_command, payload) => {
      if (payload.op === "hint") return Promise.resolve({ opened: hintId });
      if (payload.op === "status")
        return new Promise((resolve, reject) => {
          resolveStatus = resolve;
          rejectStatus = reject;
        });
      return never();
    });
    render();
    await settle();
    await vi.advanceTimersByTimeAsync(2000);
    hintId = "c".repeat(64);
    runtime.wake?.();
    expect((await settle()).showOpening).toBe(true);
    if (result === "error") rejectStatus(new Error("Unavailable"));
    else
      resolveStatus(
        result === "old tap" ? status : { ...status, opened: null },
      );
    expect((await settle()).showOpening).toBe(true);
    expect(runtime.open).not.toHaveBeenCalled();
    expect(
      runtime.invoke.mock.calls.some(([command]) => command === "operate"),
    ).toBe(false);
    // The first tap's deadline must not cancel the newer tap or replace its ID.
    await vi.advanceTimersByTimeAsync(6000);
    expect((await settle()).showOpening).toBe(true);
    expect(runtime.error).not.toHaveBeenCalled();
    await vi.advanceTimersByTimeAsync(2000);
    expect((await settle()).showOpening).toBe(false);
    expect(runtime.error).toHaveBeenCalledOnce();
    const handled = JSON.parse([...storage.values()][0]);
    expect(handled).toEqual([{ identity, id: hintId }]);
  },
);

test("a stuck invitation catch-up consumes only the tap and never marks the invitation seen", async () => {
  runtime.invoke.mockImplementation((command, payload) => {
    if (command === "operate") return never();
    if (payload.op === "hint") return Promise.resolve({ opened: id });
    return Promise.resolve(status);
  });
  render();
  await settle();
  expect(
    runtime.invoke.mock.calls.some(
      ([, payload]) => payload.request?.op === "invitation_sync",
    ),
  ).toBe(true);
  await vi.advanceTimersByTimeAsync(NOTIFICATION_OPEN_TIMEOUT_MS);
  expect((await settle()).showOpening).toBe(false);
  expect(
    runtime.invoke.mock.calls.some(([, payload]) => payload.op === `ack:${id}`),
  ).toBe(true);
  expect(
    runtime.invoke.mock.calls.some(([, payload]) =>
      ["mark_read", "invitation_activity_seen"].includes(payload.request?.op),
    ),
  ).toBe(false);
  expect(runtime.open).not.toHaveBeenCalled();
});

test("late catch-up cannot update or navigate after the deadline", async () => {
  let resolve!: (value: unknown) => void;
  runtime.invoke.mockImplementation((command, payload) =>
    command === "operate"
      ? new Promise((done) => {
          resolve = done;
        })
      : Promise.resolve(payload.op === "hint" ? { opened: id } : status),
  );
  render();
  await settle();
  await vi.advanceTimersByTimeAsync(NOTIFICATION_OPEN_TIMEOUT_MS);
  await settle();
  resolve({ view: baseView, result: {} });
  await settle();
  expect(runtime.sync).not.toHaveBeenCalled();
  expect(runtime.open).not.toHaveBeenCalled();
});

test("a slow navigation loses its scope guard at timeout and does not emit a seen receipt", async () => {
  const joined = {
    ...baseView,
    streams: [
      {
        space: "scope",
        stream: "chat",
        rows: [],
        members: [{ identity_id: identity, capabilities: ["READ"] }],
      },
    ],
  } as unknown as View;
  let complete!: (value: boolean) => void;
  runtime.open.mockImplementation(
    () =>
      new Promise((done) => {
        complete = done;
      }),
  );
  runtime.invoke.mockImplementation((_command, payload) =>
    Promise.resolve(payload.op === "hint" ? { opened: id } : status),
  );
  render(joined);
  await settle(joined);
  expect(runtime.open).toHaveBeenCalledOnce();
  const args = runtime.open.mock.calls[0] as unknown as [
    unknown,
    unknown,
    unknown,
    unknown,
    () => boolean,
    number,
    string,
  ];
  expect(args[4]()).toBe(true);
  expect(args[5]).toBe(1_000_000 + NOTIFICATION_OPEN_TIMEOUT_MS);
  expect(args[6]).toBe(id);
  await vi.advanceTimersByTimeAsync(NOTIFICATION_OPEN_TIMEOUT_MS);
  expect(args[4]()).toBe(false);
  complete(true);
  expect((await settle(joined)).showOpening).toBe(false);
  expect(
    runtime.invoke.mock.calls.some(
      ([, payload]) => payload.request?.op === "invitation_activity_seen",
    ),
  ).toBe(false);
});

test("repeated hints and status do not extend an opening budget", () => {
  const changed = vi.fn(),
    expired = vi.fn();
  const attempt = new NotificationOpeningAttempt(changed, expired);
  attempt.begin(identity);
  vi.advanceTimersByTime(2000);
  attempt.begin(identity, id);
  vi.advanceTimersByTime(3000);
  attempt.begin(identity, id);
  vi.advanceTimersByTime(3000);
  expect(expired).toHaveBeenCalledExactlyOnceWith(identity, id);
  expect(changed).toHaveBeenLastCalledWith(false, false);
});

test("a new tap replaces the old navigation guard and owns its own bounded deadline", () => {
  const expired = vi.fn();
  const attempt = new NotificationOpeningAttempt(vi.fn(), expired);
  attempt.begin(identity, id);
  vi.advanceTimersByTime(3000);
  const newer = "c".repeat(64);
  attempt.begin(identity, newer);
  expect(attempt.current(identity, id)).toBe(false);
  vi.advanceTimersByTime(5000);
  expect(expired).not.toHaveBeenCalled();
  expect(attempt.current(identity, newer)).toBe(true);
  vi.advanceTimersByTime(3000);
  expect(expired).toHaveBeenCalledExactlyOnceWith(identity, newer);
});

test("handled tap suppression is identity-scoped and bounded without storing targets", () => {
  const attempt = new NotificationOpeningAttempt(vi.fn(), vi.fn());
  for (let i = 0; i < 40; i++) {
    attempt.begin(identity, String(i));
    attempt.complete(identity, String(i));
  }
  expect(attempt.begin(identity, "39")).toBe(false);
  expect(attempt.begin("other-profile", "39")).toBe(true);
  const saved = JSON.parse([...storage.values()][0]);
  expect(saved).toHaveLength(32);
  expect(Object.keys(saved[0]).sort()).toEqual(["id", "identity"]);
  attempt.reset();
});

test("local storage failure cannot keep the UI blocked", () => {
  vi.stubGlobal("localStorage", {
    getItem: () => {
      throw new Error("unavailable");
    },
    setItem: () => {
      throw new Error("full");
    },
  });
  const changed = vi.fn(),
    expired = vi.fn();
  const attempt = new NotificationOpeningAttempt(changed, expired);
  attempt.begin(identity, id);
  vi.advanceTimersByTime(NOTIFICATION_OPEN_TIMEOUT_MS);
  expect(changed).toHaveBeenLastCalledWith(false, false);
  expect(expired).toHaveBeenCalledOnce();
});
