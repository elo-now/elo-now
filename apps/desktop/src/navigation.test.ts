import { describe, expect, it, vi } from "vitest";
import { navigateBack } from "./navigation";

describe("back navigation", () => {
  it("navigates before returning without waiting for animation support", () => {
    const navigate = vi.fn();

    navigateBack(navigate, () => true);

    expect(navigate).toHaveBeenCalledOnce();
  });

  it("ignores a callback from a screen that is no longer current", () => {
    const navigate = vi.fn();

    navigateBack(navigate, () => false);

    expect(navigate).not.toHaveBeenCalled();
  });

  it("does not block a second valid Back action during content entrance", () => {
    const first = vi.fn();
    const next = vi.fn();

    navigateBack(first, () => true);
    navigateBack(next, () => true);

    expect(first).toHaveBeenCalledOnce();
    expect(next).toHaveBeenCalledOnce();
  });
});
