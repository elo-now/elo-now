import { describe, expect, it } from "vitest";
import {
  floatingAnchor,
  floatingPosition,
  floatingReleaseAnchor,
} from "./floatingPosition";

describe("floating call placement", () => {
  const size = { width: 288, height: 112 };
  const screen = { left: 12, top: 84, width: 366, height: 676 };

  it("clamps a drag beyond the screen to the available edges", () => {
    const anchor = floatingAnchor(screen, size, { x: 800, y: -400 });
    expect(floatingPosition(screen, size, anchor)).toEqual({ x: 90, y: 84 });
  });

  it("keeps a docked widget above the composer when the keyboard reduces space", () => {
    const anchor = floatingAnchor(screen, size, { x: 90, y: 648 });
    const keyboard = { ...screen, height: 252 };
    expect(floatingPosition(keyboard, size, anchor)).toEqual({ x: 90, y: 224 });
    expect(floatingPosition(screen, size, anchor)).toEqual({ x: 90, y: 648 });
  });

  it("preserves a relative dragged position through rotation", () => {
    const point = { x: 51, y: 225 };
    const anchor = floatingAnchor(screen, size, point);
    expect(floatingPosition(screen, size, anchor)).toEqual(point);
    expect(
      floatingPosition(
        { left: 12, top: 80, width: 820, height: 300 },
        size,
        anchor,
      ),
    ).toEqual({ x: 278, y: 127 });
  });

  it("keeps controls at the available origin when the viewport is too small", () => {
    const tiny = { left: 12, top: 12, width: 260, height: 80 };
    expect(floatingPosition(tiny, size, { x: 1, y: 1 })).toEqual({
      x: 12,
      y: 12,
    });
    expect(floatingAnchor(tiny, size, { x: -20, y: -20 })).toEqual({
      x: 0,
      y: 0,
    });
  });

  it("docks vertical swipes to the nearest top or bottom corner", () => {
    expect(
      floatingReleaseAnchor(
        screen,
        size,
        { x: 40, y: 250 },
        { x: 5, y: -70, duration: 100 },
      ),
    ).toEqual({ x: 0, y: 0 });
    expect(
      floatingReleaseAnchor(
        screen,
        size,
        { x: 70, y: 400 },
        { x: -5, y: 70, duration: 100 },
      ),
    ).toEqual({ x: 1, y: 1 });
  });

  it("docks horizontal swipes to an edge without changing their height", () => {
    const point = { x: 50, y: 300 };
    expect(
      floatingPosition(
        screen,
        size,
        floatingReleaseAnchor(screen, size, point, {
          x: -80,
          y: 5,
          duration: 100,
        }),
      ),
    ).toEqual({ x: 12, y: 300 });
    expect(
      floatingPosition(
        screen,
        size,
        floatingReleaseAnchor(screen, size, point, {
          x: 80,
          y: -5,
          duration: 100,
        }),
      ),
    ).toEqual({ x: 90, y: 300 });
  });

  it("docks diagonal swipes in the intended corner", () => {
    expect(
      floatingReleaseAnchor(
        screen,
        size,
        { x: 40, y: 300 },
        { x: 60, y: -65, duration: 100 },
      ),
    ).toEqual({ x: 1, y: 0 });
    expect(
      floatingReleaseAnchor(
        screen,
        size,
        { x: 60, y: 300 },
        { x: -65, y: 60, duration: 100 },
      ),
    ).toEqual({ x: 0, y: 1 });
  });

  it("keeps a deliberate slow drag where it was released, with a small edge magnet", () => {
    const point = { x: 50, y: 300 };
    expect(
      floatingPosition(
        screen,
        size,
        floatingReleaseAnchor(screen, size, point, {
          x: -40,
          y: -100,
          duration: 600,
        }),
      ),
    ).toEqual(point);
    expect(
      floatingReleaseAnchor(
        screen,
        size,
        { x: 20, y: 92 },
        { x: 0, y: 0, duration: 400 },
      ),
    ).toEqual({ x: 0, y: 0 });
  });

  it("does not turn a short tap jitter or release after a pause into a swipe", () => {
    const point = { x: 50, y: 300 };
    for (const motion of [
      { x: 4, y: 4, duration: 2 },
      { x: -70, y: -20, duration: 300 },
      { x: 0, y: 0, duration: 0 },
    ]) {
      expect(
        floatingPosition(
          screen,
          size,
          floatingReleaseAnchor(screen, size, point, motion),
        ),
      ).toEqual(point);
    }
  });

  it("keeps both edges reachable on narrow phones", () => {
    const narrow = { ...screen, width: 296 };
    expect(
      floatingReleaseAnchor(
        narrow,
        size,
        { x: 20, y: 300 },
        { x: 0, y: 0, duration: 200 },
      ).x,
    ).toBe(1);
    expect(
      floatingReleaseAnchor(
        narrow,
        size,
        { x: 16, y: 300 },
        { x: 0, y: 0, duration: 200 },
      ).x,
    ).toBe(0.5);
  });
});
