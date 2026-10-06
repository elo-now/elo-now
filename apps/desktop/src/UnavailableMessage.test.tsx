import { afterEach, beforeEach, expect, test, vi } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import type { EffectCallback } from "react";
import { UnavailableMessage } from "./UnavailableMessage";
import { RETRIEVE_WINDOW_MS } from "./liveSync";

const lifecycle = vi.hoisted(() => ({
  effects: [] as EffectCallback[],
  click: undefined as (() => void) | undefined,
}));
vi.mock("react", async (importOriginal) => ({
  ...(await importOriginal<typeof import("react")>()),
  // SSR captures the actual component's handler; explicitly running its effect
  // also exercises disposal while the native request is still unresolved.
  useEffect: (effect: EffectCallback) => lifecycle.effects.push(effect),
}));
vi.mock("react/jsx-dev-runtime", async (importOriginal) => {
  const original =
    await importOriginal<typeof import("react/jsx-dev-runtime")>();
  return {
    ...original,
    jsxDEV: (...args: Parameters<typeof original.jsxDEV>) => {
      const element = original.jsxDEV(...args);
      if (element.type === "button")
        lifecycle.click = (element.props as { onClick?: () => void }).onClick;
      return element;
    },
  };
});

beforeEach(() => {
  vi.useFakeTimers();
  lifecycle.effects = [];
  lifecycle.click = undefined;
});
afterEach(() => {
  vi.clearAllTimers();
  vi.useRealTimers();
});

function mount(
  onRequest: () => Promise<void | (() => void)>,
  onUnavailable = vi.fn(),
  active = true,
) {
  renderToStaticMarkup(
    <UnavailableMessage
      active={active}
      disabled={false}
      onRequest={onRequest}
      onUnavailable={onUnavailable}
    />,
  );
  const cleanup = lifecycle.effects.map((effect) => effect());
  return {
    click: () => lifecycle.click!(),
    dispose: () => cleanup.forEach((stop) => stop?.()),
    onUnavailable,
  };
}

test("a resolved placeholder releases retrieval work and never shows a late failure", async () => {
  const release = vi.fn();
  const request = vi.fn(async () => release);
  const component = mount(request);
  component.click();
  component.click();
  await vi.advanceTimersByTimeAsync(0);
  expect(request).toHaveBeenCalledTimes(1);
  component.dispose();
  expect(release).toHaveBeenCalledTimes(1);
  await vi.advanceTimersByTimeAsync(RETRIEVE_WINDOW_MS);
  expect(component.onUnavailable).not.toHaveBeenCalled();
});

test("navigation releases a lease returned after its placeholder was disposed", async () => {
  let complete!: (release: () => void) => void;
  const release = vi.fn();
  const component = mount(
    () =>
      new Promise((resolve) => {
        complete = resolve;
      }),
  );
  component.click();
  component.dispose();
  complete(release);
  await vi.advanceTimersByTimeAsync(RETRIEVE_WINDOW_MS);
  expect(release).toHaveBeenCalledTimes(1);
  expect(component.onUnavailable).not.toHaveBeenCalled();
});

test("the Retrieve deadline includes time waiting for the initial native request", async () => {
  let complete!: (release: () => void) => void;
  const release = vi.fn();
  const component = mount(
    () =>
      new Promise((resolve) => {
        complete = resolve;
      }),
  );
  component.click();
  await vi.advanceTimersByTimeAsync(RETRIEVE_WINDOW_MS - 1);
  expect(component.onUnavailable).not.toHaveBeenCalled();
  await vi.advanceTimersByTimeAsync(1);
  expect(component.onUnavailable).toHaveBeenCalledTimes(1);
  complete(release);
  await vi.advanceTimersByTimeAsync(0);
  expect(release).toHaveBeenCalledTimes(1);
  component.dispose();
  expect(release).toHaveBeenCalledTimes(1);
});

test("a missing message releases its receive lease when the wait expires", async () => {
  const release = vi.fn();
  const component = mount(async () => release);
  component.click();
  await vi.advanceTimersByTimeAsync(RETRIEVE_WINDOW_MS);
  expect(release).toHaveBeenCalledTimes(1);
  expect(component.onUnavailable).toHaveBeenCalledTimes(1);
  component.dispose();
  expect(release).toHaveBeenCalledTimes(1);
});

test("a conversation hidden behind another screen cannot start Retrieve", async () => {
  const request = vi.fn(async () => {});
  const component = mount(request, vi.fn(), false);
  component.click();
  await vi.advanceTimersByTimeAsync(RETRIEVE_WINDOW_MS);
  expect(request).not.toHaveBeenCalled();
  expect(component.onUnavailable).not.toHaveBeenCalled();
  component.dispose();
});
