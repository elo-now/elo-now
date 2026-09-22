import { afterEach, expect, test, vi } from "vitest";
import { canReadVisibleMessages } from "./messageReadVisibility";

afterEach(() => vi.unstubAllGlobals());
test("desktop messages stay unread behind another app, while hidden or behind a dialog", () => {
  const page = {
    hidden: false,
    documentElement: { dataset: { windowPlatform: "macos" } },
    hasFocus: () => false,
    querySelector: () => null as object | null,
  };
  vi.stubGlobal("document", page);
  expect(canReadVisibleMessages()).toBe(false);
  page.hasFocus = () => true;
  expect(canReadVisibleMessages()).toBe(true);
  page.hidden = true;
  expect(canReadVisibleMessages()).toBe(false);
  page.hidden = false;
  page.querySelector = () => ({});
  expect(canReadVisibleMessages()).toBe(false);
});

test("mobile retains its visibility rule without requiring desktop window focus", () => {
  vi.stubGlobal("document", {
    hidden: false,
    documentElement: { dataset: {} },
    hasFocus: () => false,
    querySelector: () => null,
  });
  expect(canReadVisibleMessages()).toBe(true);
});
