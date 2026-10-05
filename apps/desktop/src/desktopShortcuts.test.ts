import { expect, test } from "vitest";
import { desktopShortcut } from "./desktopShortcuts";

const event = (key: string, extra: Partial<KeyboardEvent> = {}) => ({
  key,
  metaKey: false,
  ctrlKey: false,
  altKey: false,
  shiftKey: false,
  isComposing: false,
  defaultPrevented: false,
  repeat: false,
  ...extra,
});
test.each([true, false])(
  "common shortcuts use the platform modifier (Mac: %s)",
  (mac) => {
    const modifier = mac ? { metaKey: true } : { ctrlKey: true };
    for (const [key, action] of [
      ["k", "switch"],
      ["f", "search"],
      ["n", "compose"],
      ["o", "attach"],
      [",", "preferences"],
      ["/", "help"],
    ]) {
      expect(desktopShortcut(event(key, modifier), mac)).toBe(action);
      expect(desktopShortcut(event(key), mac)).toBeUndefined();
    }
    expect(
      desktopShortcut(event("K", { ...modifier, shiftKey: true }), mac),
    ).toBe("compose");
    expect(
      desktopShortcut(
        event("k", mac ? { ctrlKey: true } : { metaKey: true }),
        mac,
      ),
    ).toBeUndefined();
  },
);
test("navigation distinguishes unread chats and leaves typing, IME and handled events alone", () => {
  expect(desktopShortcut(event("ArrowUp", { altKey: true }), true)).toBe(
    "previous",
  );
  expect(
    desktopShortcut(
      event("ArrowDown", { altKey: true, shiftKey: true }),
      false,
    ),
  ).toBe("unreadNext");
  for (const extra of [
    { isComposing: true },
    { defaultPrevented: true },
    { repeat: true },
    { altKey: true },
    { ctrlKey: true },
  ])
    expect(
      desktopShortcut(event("k", { metaKey: true, ...extra }), true),
    ).toBeUndefined();
  expect(desktopShortcut(event("Enter"), false)).toBeUndefined();
});
