import { afterEach, beforeEach, expect, it, vi } from "vitest";

const runtime = vi.hoisted(() => ({
  cleanup: undefined as undefined | (() => void),
  deps: undefined as unknown[] | undefined,
  invoke: vi.fn(),
  native: true,
  sound: "soft",
}));
vi.mock("react", () => ({
  useEffect: (effect: () => void | (() => void), deps: unknown[]) => {
    if (runtime.deps?.every((value, i) => Object.is(value, deps[i]))) return;
    runtime.cleanup?.();
    runtime.deps = deps;
    runtime.cleanup = effect() || undefined;
  },
}));
vi.mock("@tauri-apps/api/core", () => ({
  invoke: runtime.invoke,
  isTauri: () => runtime.native,
}));
vi.mock("../notificationSounds", () => ({
  readNotificationSound: () => runtime.sound,
}));
import { useIncomingRingtone } from "./useIncomingRingtone";

let visible: boolean;
let focused: boolean;
let page: EventTarget;
let win: EventTarget;
let players: {
  pause: ReturnType<typeof vi.fn>;
  play: ReturnType<typeof vi.fn>;
  volume: number;
}[];
let finishPlay: (() => void) | undefined;
let delayedPlay: boolean;
const defaults = {
  identity: "me",
  ringKey: "invitation",
  expiresAt: 160,
  activeCall: false,
};
const render = (
  options: Partial<Parameters<typeof useIncomingRingtone>[0]> = {},
) => useIncomingRingtone({ ...defaults, ...options });
const requests = () => runtime.invoke.mock.calls.map((call) => call[1].request);

beforeEach(() => {
  vi.useFakeTimers();
  vi.setSystemTime(100_000);
  runtime.cleanup = undefined;
  runtime.deps = undefined;
  runtime.native = true;
  runtime.sound = "soft";
  runtime.invoke.mockReset().mockResolvedValue(undefined);
  visible = focused = true;
  finishPlay = undefined;
  delayedPlay = false;
  players = [];
  page = new EventTarget();
  Object.defineProperties(page, {
    visibilityState: { get: () => (visible ? "visible" : "hidden") },
    hasFocus: { value: () => focused },
  });
  win = new EventTarget();
  vi.stubGlobal("document", page);
  vi.stubGlobal("window", win);
  vi.stubGlobal("navigator", { userAgent: "iPhone" });
  vi.stubGlobal(
    "Audio",
    class {
      volume = 0;
      pause = vi.fn();
      play = vi.fn(() =>
        delayedPlay
          ? new Promise<void>((resolve) => {
              finishPlay = resolve;
            })
          : Promise.resolve(),
      );
      constructor() {
        players.push(this);
      }
    },
  );
});

afterEach(() => {
  runtime.cleanup?.();
  vi.clearAllTimers();
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

it("rings natively on iOS and Android without a WebView audio player", async () => {
  render();
  expect(requests()[0]).toMatchObject({ active: true, expires: 104_000 });
  expect(players).toHaveLength(0);
  await vi.advanceTimersByTimeAsync(1500);
  expect(requests()[1].token).toBe(requests()[0].token);
  expect(requests()[1].revision).toBeGreaterThan(requests()[0].revision);
  runtime.cleanup?.();
  runtime.deps = undefined;
  vi.stubGlobal("navigator", { userAgent: "Android" });
  render();
  expect(requests().at(-1)).toMatchObject({ active: true });
  expect(players).toHaveLength(0);
});

it("stops immediately for answer, native takeover, ended invitation and logout", () => {
  for (const update of [
    { answering: true },
    { nativePresented: true },
    { ringKey: undefined },
    { identity: "" },
  ]) {
    render();
    const token = requests().at(-1).token;
    render(update);
    expect(requests().at(-1)).toMatchObject({ active: false, token });
  }
});

it("does not ring when already answered, expired, or owned by the system", () => {
  render({ answering: true });
  render({ nativePresented: true });
  render({ expiresAt: 99 });
  expect(runtime.invoke).not.toHaveBeenCalled();
});

it("uses a new token after mobile blur even if visibility never changes", () => {
  render();
  const first = requests()[0].token;
  win.dispatchEvent(new Event("blur"));
  expect(requests().at(-1)).toMatchObject({ active: false, token: first });
  win.dispatchEvent(new Event("focus"));
  expect(requests().at(-1).active).toBe(true);
  expect(requests().at(-1).token).not.toBe(first);
});

it("cancels on background and does not let an old pending start block resume", async () => {
  let complete!: () => void;
  runtime.invoke.mockImplementationOnce(
    () =>
      new Promise<void>((resolve) => {
        complete = resolve;
      }),
  );
  render();
  const first = requests()[0].token;
  visible = false;
  page.dispatchEvent(new Event("visibilitychange"));
  expect(requests().at(-1)).toMatchObject({ active: false, token: first });
  visible = true;
  page.dispatchEvent(new Event("visibilitychange"));
  const second = requests().at(-1).token;
  expect(second).not.toBe(first);
  complete();
  await vi.advanceTimersByTimeAsync(1500);
  expect(
    requests().filter((value) => value.token === first && value.active),
  ).toHaveLength(1);
  expect(requests().at(-1)).toMatchObject({ active: true, token: second });
});

it("replaces an expired native lease after a stalled foreground WebView", async () => {
  render();
  const first = requests()[0].token;
  vi.setSystemTime(105_000);
  await vi.advanceTimersByTimeAsync(1500);
  expect(requests()).toContainEqual(
    expect.objectContaining({ active: false, token: first }),
  );
  expect(requests().at(-1).active).toBe(true);
  expect(requests().at(-1).token).not.toBe(first);
});

it("expires without another call snapshot and removes lifecycle listeners on unmount", async () => {
  render({ expiresAt: 102 });
  expect(requests()[0].expires).toBe(102_000);
  await vi.advanceTimersByTimeAsync(3000);
  expect(requests().at(-1).active).toBe(false);
  runtime.cleanup?.();
  const count = runtime.invoke.mock.calls.length;
  win.dispatchEvent(new Event("focus"));
  page.dispatchEvent(new Event("visibilitychange"));
  await vi.advanceTimersByTimeAsync(10_000);
  expect(runtime.invoke).toHaveBeenCalledTimes(count);
});

it("keeps desktop call audio independent and stops delayed playback after cleanup", async () => {
  vi.stubGlobal("navigator", { userAgent: "Macintosh" });
  delayedPlay = true;
  render();
  expect(players).toHaveLength(1);
  expect(runtime.invoke).not.toHaveBeenCalled();
  const first = players[0];
  runtime.cleanup?.();
  finishPlay?.();
  await Promise.resolve();
  expect(first.pause).toHaveBeenCalledTimes(2);
});

it("respects desktop silence and uses quieter audio while already in a call", () => {
  vi.stubGlobal("navigator", { userAgent: "Macintosh" });
  runtime.sound = "none";
  render();
  expect(players).toHaveLength(0);
  runtime.sound = "soft";
  render({ activeCall: true });
  expect(players[0].volume).toBe(0.25);
  focused = false;
  win.dispatchEvent(new Event("blur"));
  expect(players[0].pause).toHaveBeenCalled();
});
