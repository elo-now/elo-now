import { afterEach, beforeEach, expect, it, vi } from "vitest";
import type { View } from "../model";
import type { NativeIncomingStatus } from "./incomingNative";

const runtime = vi.hoisted(() => ({
  effects: [] as { effect: () => void | (() => void); deps: unknown[] }[],
  status: vi.fn(),
  listen: vi.fn(),
  presented: vi.fn(),
  adopt: vi.fn(),
  action: vi.fn(),
}));
vi.mock("react", async (original) => ({
  ...(await original<typeof import("react")>()),
  useEffect: (effect: () => void | (() => void), deps: unknown[]) => {
    runtime.effects.push({ effect, deps });
  },
  useState: (initial: () => unknown) => [initial(), vi.fn()],
}));
vi.mock("./controller", () => ({
  Calls: class {
    setNativePresented = runtime.presented;
    adoptNative = runtime.adopt;
    handleNativeAction = runtime.action;
  },
}));
vi.mock("./incomingNative", () => ({
  incomingStatus: runtime.status,
  listenIncomingCalls: runtime.listen,
}));
import { useCalls } from "./CallUI";

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((done) => (resolve = done));
  return { promise, resolve };
}
const tick = async () => {
  await Promise.resolve();
  await Promise.resolve();
  await Promise.resolve();
};
let cleanup: (() => void) | undefined;
function mount() {
  useCalls({ identity: "me" } as View);
  const effect = runtime.effects.find(
    (entry) => entry.deps.length === 2 && entry.deps[1] === "me",
  );
  expect(effect).toBeDefined();
  cleanup = effect!.effect() || undefined;
}
beforeEach(() => {
  runtime.effects = [];
  runtime.status.mockReset().mockResolvedValue({});
  runtime.listen.mockReset();
  runtime.presented.mockReset();
  runtime.adopt.mockReset().mockResolvedValue(false);
  runtime.action.mockReset();
});
afterEach(() => {
  cleanup?.();
  cleanup = undefined;
});

it("resamples native ownership after listeners attach so a missed presentation is recovered", async () => {
  const attached = deferred<() => void>();
  const stop = vi.fn();
  runtime.listen.mockReturnValue(attached.promise);
  mount();
  await tick();
  expect(runtime.presented).toHaveBeenLastCalledWith(undefined);
  const presented = [{ call_id: "call", invitation_id: "attempt" }];
  runtime.status.mockResolvedValue({ presented });
  attached.resolve(stop);
  await tick();
  expect(runtime.presented).toHaveBeenLastCalledWith(presented);
  cleanup?.();
  expect(stop).toHaveBeenCalledOnce();
  cleanup = undefined;
});

it("ignores an older status result after the post-subscription refresh", async () => {
  const initial = deferred<NativeIncomingStatus>();
  const attached = deferred<() => void>();
  const presented = [{ call_id: "call", invitation_id: "attempt" }];
  runtime.status
    .mockReturnValueOnce(initial.promise)
    .mockResolvedValue({ presented });
  runtime.listen.mockReturnValue(attached.promise);
  mount();
  attached.resolve(vi.fn());
  await tick();
  expect(runtime.presented).toHaveBeenLastCalledWith(presented);
  initial.resolve({ presented: [] });
  await tick();
  expect(runtime.presented).toHaveBeenCalledOnce();
  expect(runtime.presented).toHaveBeenLastCalledWith(presented);
});

it("does not refresh or publish late native ownership after the profile effect is disposed", async () => {
  const initial = deferred<NativeIncomingStatus>();
  const attached = deferred<() => void>();
  const stop = vi.fn();
  runtime.status.mockReturnValue(initial.promise);
  runtime.listen.mockReturnValue(attached.promise);
  mount();
  cleanup?.();
  cleanup = undefined;
  attached.resolve(stop);
  initial.resolve({
    presented: [{ call_id: "call", invitation_id: "attempt" }],
  });
  await tick();
  expect(stop).toHaveBeenCalledOnce();
  expect(runtime.status).toHaveBeenCalledOnce();
  expect(runtime.presented).not.toHaveBeenCalled();
});
