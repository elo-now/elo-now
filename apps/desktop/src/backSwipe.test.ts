import { describe, expect, it } from "vitest";
import {
  backSwipeDirection,
  backSwipeStartArea,
  shouldFinishBackSwipe,
} from "./backSwipe";

describe("back swipe intent", () => {
  it("accepts the left third on both narrow and wide phones", () => {
    expect(backSwipeStartArea(393)).toBe(131);
    expect(backSwipeStartArea(320)).toBeCloseTo(106.67, 2);
    expect(backSwipeStartArea(450)).toBe(150);
  });
  it("leaves taps and vertical scroll alone", () => {
    expect(backSwipeDirection(5, 3)).toBe("wait");
    expect(backSwipeDirection(8, 20)).toBe("cancel");
    expect(backSwipeDirection(-20, 0)).toBe("cancel");
    expect(backSwipeDirection(25, 5)).toBe("back");
  });
  it("finishes a deliberate drag or flick but cancels a short or retreated gesture", () => {
    expect(shouldFinishBackSwipe(115, 393, 0)).toBe(true);
    expect(shouldFinishBackSwipe(52, 393, 0.7)).toBe(true);
    expect(shouldFinishBackSwipe(20, 393, 1.2)).toBe(false);
    expect(shouldFinishBackSwipe(52, 393, -0.7)).toBe(false);
    expect(shouldFinishBackSwipe(52, 393, 0)).toBe(false);
  });
});
