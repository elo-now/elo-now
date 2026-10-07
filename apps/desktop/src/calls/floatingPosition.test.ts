import { describe, expect, it } from "vitest";
import { floatingAnchor, floatingPosition } from "./floatingPosition";

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
});
