import { afterEach, describe, expect, it, vi } from "vitest";
import { navigateBackWithFade } from "./navigationFade";

afterEach(() => vi.unstubAllGlobals());

function screen(reducedMotion = false) {
  const animations: {
    finished: Promise<void>;
    resolve: () => void;
    reject: (error: Error) => void;
    cancel: ReturnType<typeof vi.fn>;
  }[] = [];
  const root = {
    animate: vi.fn((_frames: Keyframe[], _options: KeyframeAnimationOptions) => {
      let resolve!: () => void;
      let reject!: (error: Error) => void;
      const finished = new Promise<void>((yes, no) => {
        resolve = yes;
        reject = no;
      });
      const animation = { finished, resolve, reject, cancel: vi.fn() };
      animations.push(animation);
      return animation;
    }),
  };
  const classList = { add: vi.fn(), remove: vi.fn() };
  vi.stubGlobal("document", {
    getElementById: () => root,
    querySelectorAll: () => [],
    documentElement: { classList },
  });
  vi.stubGlobal("innerWidth", 393);
  vi.stubGlobal("matchMedia", () => ({ matches: reducedMotion }));
  return { root, animations, classList };
}

describe("back navigation fade", () => {
  it("commits once between fades, then restores interaction", async () => {
    const { root, animations, classList } = screen();
    const navigate = vi.fn();
    const done = navigateBackWithFade(navigate, () => true);
    await navigateBackWithFade(navigate, () => true);
    expect(navigate).not.toHaveBeenCalled();
    animations[0].resolve();
    await vi.waitFor(() => expect(animations).toHaveLength(2));
    expect(navigate).toHaveBeenCalledTimes(1);
    expect(root.animate.mock.calls[1]?.[0]).toEqual([
      { opacity: 0 },
      { opacity: 1 },
    ]);
    animations[1].resolve();
    await done;
    expect(
      animations.every((animation) => animation.cancel.mock.calls.length),
    ).toBe(true);
    expect(classList.remove).toHaveBeenCalledWith("back-fading");
  });

  it("navigates immediately with reduced motion", async () => {
    const { root } = screen(true);
    const navigate = vi.fn();
    await navigateBackWithFade(navigate, () => true);
    expect(navigate).toHaveBeenCalledOnce();
    expect(root.animate).not.toHaveBeenCalled();
  });

  it("restores the app after cancellation without navigating", async () => {
    const { animations, classList } = screen();
    const navigate = vi.fn();
    const done = navigateBackWithFade(navigate, () => true);
    animations[0].reject(new DOMException("Cancelled", "AbortError"));
    await done;
    expect(navigate).not.toHaveBeenCalled();
    expect(classList.remove).toHaveBeenCalledWith("back-fading");
    expect(animations[0].cancel).toHaveBeenCalled();
  });
});
