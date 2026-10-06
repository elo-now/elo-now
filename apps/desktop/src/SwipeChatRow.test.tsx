import { afterEach, beforeEach, expect, test, vi } from "vitest";
import {
  Children,
  isValidElement,
  type ReactElement,
  type ReactNode,
} from "react";
import type { View } from "./model";

const hooks = vi.hoisted(() => ({ cursor: 0, slots: [] as any[] }));
vi.mock("react", async (original) => ({
  ...(await original<typeof import("react")>()),
  useState: (initial: unknown) => {
    const index = hooks.cursor++;
    if (!(index in hooks.slots)) hooks.slots[index] = initial;
    return [
      hooks.slots[index],
      (value: unknown) => {
        hooks.slots[index] = value;
      },
    ];
  },
  useRef: (initial: unknown) => {
    const index = hooks.cursor++;
    return (hooks.slots[index] ??= { current: initial });
  },
  useEffect: () => {},
}));
import { SwipeChatRow } from "./SwipeChatRow";
import { DeleteLocalChatDialog } from "./DeleteLocalChatDialog";
import { ChatList } from "./ChatOrganization";

class Target {
  closest() {
    return null;
  }
}
function descendants(node: ReactNode): ReactElement<any>[] {
  return Children.toArray(node).flatMap((item) =>
    isValidElement(item)
      ? [
          item,
          ...descendants((item.props as { children?: ReactNode }).children),
        ]
      : [],
  );
}
function mount() {
  let revealed = false;
  const open = vi.fn();
  const requestDelete = vi.fn();
  const reveal = vi.fn((value: boolean) => {
    revealed = value;
  });
  const render = () => {
    hooks.cursor = 0;
    return SwipeChatRow({
      children: <button onClick={open}>Alice</button>,
      chatName: "Alice",
      revealed,
      onReveal: reveal,
      onRequestDelete: requestDelete,
    });
  };
  const pointer = (x: number, y: number, overrides = {}) => ({
    pointerId: 1,
    pointerType: "touch",
    button: 0,
    isPrimary: true,
    clientX: x,
    clientY: y,
    target: new Target(),
    currentTarget: { setPointerCapture: vi.fn() },
    preventDefault: vi.fn(),
    stopPropagation: vi.fn(),
    ...overrides,
  });
  const content = () =>
    descendants(render()).find((node) =>
      node.props.className?.includes("swipe-chat-open"),
    )!;
  const trash = () =>
    descendants(render()).find(
      (node) => node.props.className === "swipe-chat-delete",
    )!;
  const swipe = (fromX = 220, toX = 120) => {
    render().props.onPointerDown(pointer(fromX, 100));
    render().props.onPointerMove(pointer(toX, 103));
    render().props.onPointerUp(pointer(toX, 103));
  };
  const click = (detail = 1) => ({
    detail,
    preventDefault: vi.fn(),
    stopPropagation: vi.fn(),
  });
  return {
    render,
    content,
    trash,
    swipe,
    pointer,
    click,
    open,
    requestDelete,
    reveal,
  };
}
beforeEach(() => {
  hooks.cursor = 0;
  hooks.slots = [];
  vi.stubGlobal("Element", Target);
});
afterEach(() => vi.unstubAllGlobals());

test("a left swipe reveals only the action and suppresses its trailing click", () => {
  const row = mount();
  row.swipe();
  expect(row.trash().props.tabIndex).toBe(0);
  expect(row.content().props.style.transform).toBe("translateX(-64px)");
  row.content().props.onClick(row.click());
  expect(row.open).not.toHaveBeenCalled();
  expect(row.requestDelete).not.toHaveBeenCalled();
  expect(row.trash().props.tabIndex).toBe(0);
  row.trash().props.onClick(row.click());
  expect(row.requestDelete).toHaveBeenCalledOnce();
  expect(row.open).not.toHaveBeenCalled();
  expect(row.trash().props.tabIndex).toBe(-1);
});

test("vertical scrolling and small finger movement do not acquire or delete a row", () => {
  const row = mount();
  row.render().props.onPointerDown(row.pointer(220, 100));
  const move = row.pointer(205, 160);
  row.render().props.onPointerMove(move);
  row.render().props.onPointerUp(move);
  expect(move.preventDefault).not.toHaveBeenCalled();
  expect(move.currentTarget.setPointerCapture).not.toHaveBeenCalled();
  expect(row.reveal).not.toHaveBeenCalled();
  expect(row.requestDelete).not.toHaveBeenCalled();
  row.render().props.onPointerDown(row.pointer(200, 100));
  row.render().props.onPointerMove(row.pointer(197, 103));
  row.render().props.onPointerUp(row.pointer(197, 103));
  row.content().props.onClick(row.click());
  expect(row.open).toHaveBeenCalledOnce();
});

test("transferring implicit touch capture from the child button does not cancel the swipe", () => {
  const row = mount();
  row.render().props.onPointerDown(row.pointer(220, 100));
  row.render().props.onPointerMove(row.pointer(204, 100));
  row.render().props.onLostPointerCapture({ target: {}, currentTarget: {} });
  row.render().props.onPointerMove(row.pointer(140, 100));
  row.render().props.onPointerUp(row.pointer(140, 100));
  expect(row.trash().props.tabIndex).toBe(0);
  expect(row.requestDelete).not.toHaveBeenCalled();
});

test("an interrupted or short swipe never requests deletion or opens the chat", () => {
  const row = mount();
  row.render().props.onPointerDown(row.pointer(220, 100));
  row.render().props.onPointerMove(row.pointer(160, 103));
  row.render().props.onPointerCancel();
  row.content().props.onClick(row.click());
  expect(row.trash().props.tabIndex).toBe(-1);
  row.swipe(220, 200);
  row.content().props.onClick(row.click());
  expect(row.trash().props.tabIndex).toBe(-1);
  expect(row.open).not.toHaveBeenCalled();
  expect(row.requestDelete).not.toHaveBeenCalled();
});

test("swiping right closes an exposed action and never navigates", () => {
  const row = mount();
  row.swipe();
  row.swipe(100, 210);
  row.content().props.onClick(row.click());
  expect(row.trash().props.tabIndex).toBe(-1);
  expect(row.open).not.toHaveBeenCalled();
  expect(row.requestDelete).not.toHaveBeenCalled();
});

test("Escape closes the action and keyboard Delete requests confirmation", () => {
  const row = mount();
  row.swipe();
  row.render().props.onKeyDown({ key: "Escape", ...row.click() });
  expect(row.trash().props.tabIndex).toBe(-1);
  expect(row.requestDelete).not.toHaveBeenCalled();
  row.content().props.onKeyDown({ key: "Delete", ...row.click(0) });
  expect(row.requestDelete).toHaveBeenCalledOnce();
  expect(row.open).not.toHaveBeenCalled();
});

test("ordinary mouse clicks still open the chat without acquiring a gesture", () => {
  const row = mount();
  row
    .render()
    .props.onPointerDown(row.pointer(220, 100, { pointerType: "mouse" }));
  row
    .render()
    .props.onPointerMove(row.pointer(100, 100, { pointerType: "mouse" }));
  row.content().props.onClick(row.click());
  expect(row.open).toHaveBeenCalledOnce();
  expect(row.reveal).not.toHaveBeenCalled();
});

test("General and streams without explicit local permission never expose deletion", () => {
  const streams = [
    { name: "General", is_general: true, can_delete_local: true },
    { name: "Unknown" },
    { name: "Protected", can_delete_local: false },
    { name: "Alice", can_delete_local: true },
  ].map((value, index) => ({
    ...value,
    stream: String(index),
    space: "space",
    rows: [],
    members: [],
  }));
  const view = {
    identity: "self",
    active_space: "space",
    streams,
  } as unknown as View;
  const tree = ChatList({
    view,
    filter: "overview",
    onOpen: vi.fn(),
    onRequestDelete: vi.fn(),
  });
  const swipeRows = descendants(tree).filter(
    (node) => node.type === SwipeChatRow,
  );
  expect(swipeRows).toHaveLength(1);
  expect(swipeRows[0].props.chatName).toBe("Alice");
});

test("local deletion confirmation explains scope, Cancel leaves data untouched, Delete is explicit", () => {
  const confirm = vi.fn(),
    close = vi.fn();
  const dialog = DeleteLocalChatDialog({
    chatName: "Alice",
    busy: false,
    onConfirm: confirm,
    onClose: close,
  });
  const nodes = descendants(dialog);
  expect(dialog.props.title).toBe("Delete chat from this device?");
  expect(nodes.find((node) => node.type === "p")?.props.children).toBe(
    "Conversation: Alice",
  );
  expect(
    nodes.some(
      (node) =>
        node.props.children ===
        "This removes the conversation and its history from this device. New messages will make it appear again. Other devices and participants keep their copies.",
    ),
  ).toBe(true);
  nodes
    .find((node) => node.type === "button" && node.props.children === "Cancel")!
    .props.onClick();
  expect(close).toHaveBeenCalledOnce();
  expect(confirm).not.toHaveBeenCalled();
  nodes
    .find((node) => node.type === "button" && node.props.children === "Delete")!
    .props.onClick();
  expect(confirm).toHaveBeenCalledOnce();
});

test("an in-flight deletion disables both actions and prevents dismissal", () => {
  const confirm = vi.fn(),
    close = vi.fn();
  const dialog = DeleteLocalChatDialog({
    chatName: "Alice",
    busy: true,
    onConfirm: confirm,
    onClose: close,
  });
  expect(
    descendants(dialog)
      .filter((node) => node.type === "button")
      .every((node) => node.props.disabled),
  ).toBe(true);
  dialog.props.onClose();
  expect(close).not.toHaveBeenCalled();
  expect(confirm).not.toHaveBeenCalled();
});
