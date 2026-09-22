import { describe, expect, it } from "vitest";
import {
  MAX_DRAW_POINTS,
  MAX_DRAW_STROKES,
  readCustomMotif,
  strokePath,
  type DrawStroke,
} from "./customMotif";

describe("custom theme drawing", () => {
  it("rejects malformed or oversized persisted drawings before rendering", () => {
    const drawing = { v: 1, smooth: true, strokes: [[[10, 20]]] };
    expect(readCustomMotif(drawing)).toEqual(drawing);
    for (const invalid of [
      null,
      "<svg onload='bad()'>",
      { ...drawing, v: 2 },
      { ...drawing, smooth: "true" },
      { ...drawing, strokes: [] },
      { ...drawing, strokes: [[]] },
      { ...drawing, strokes: Array(MAX_DRAW_STROKES + 1).fill([[1, 1]]) },
      { ...drawing, strokes: [Array(MAX_DRAW_POINTS + 1).fill([1, 1])] },
      ...[
        [-1, 1],
        [257, 1],
        [NaN, 1],
        [Infinity, 1],
        ["1", 1],
        [1],
        [1, 1, 1],
      ].map((point) => ({ ...drawing, strokes: [[point]] })),
    ])
      expect(readCustomMotif(invalid)).toBeNull();
  });

  it("retains source strokes and endpoints while smoothing jitter without overshoot", () => {
    const points: DrawStroke = [
      [10, 50],
      [30, 56],
      [50, 44],
      [70, 56],
      [90, 44],
      [110, 50],
    ];
    const original = JSON.stringify(points);
    const smooth = strokePath(points, true);
    const raw = strokePath(points, false);
    expect(smooth).toMatch(/^M10 50Q/);
    expect(smooth).toMatch(/L110 50$/);
    expect(raw).not.toContain("Q");
    // The convex hull of all curve control points is narrower than the raw
    // jitter band, so every interpolated point also remains within this band.
    const coordinates = smooth.match(/-?\d+(?:\.\d+)?/g)!.map(Number);
    const ys = coordinates.filter((_, i) => i % 2 === 1);
    expect(Math.max(...ys) - Math.min(...ys)).toBeLessThan(12);
    expect(
      Math.min(...coordinates.filter((_, i) => i % 2 === 0)),
    ).toBeGreaterThanOrEqual(10);
    expect(
      Math.max(...coordinates.filter((_, i) => i % 2 === 0)),
    ).toBeLessThanOrEqual(110);
    expect(JSON.stringify(points)).toBe(original);
    expect(strokePath([[4, 8]], true)).toBe("M4 8h0");
    expect(
      strokePath(
        [
          [4, 8],
          [20, 30],
        ],
        true,
      ),
    ).toBe("M4 8L20 30");
  });
});
