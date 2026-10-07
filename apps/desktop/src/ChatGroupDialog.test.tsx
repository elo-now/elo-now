import { beforeEach, expect, test, vi } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import type { EffectCallback, KeyboardEvent, ReactNode } from "react";
import { ChatGroupDialog } from "./ChatGroupDialog";

const harness = vi.hoisted(() => ({
  name: "  Project team  ",
  effects: [] as EffectCallback[],
  actions: [] as { label: string; onClick: () => void }[],
  keyDown: undefined as
    ((event: KeyboardEvent<HTMLInputElement>) => void) | undefined,
  close: undefined as (() => void) | undefined,
  reportError: vi.fn(),
}));
vi.mock("./Toast", () => ({
  useToast: () => ({ reportError: harness.reportError }),
}));
vi.mock("./ActionDialog", () => ({
  ActionDialog: ({
    children,
    onClose,
  }: {
    children: ReactNode;
    onClose: () => void;
  }) => {
    harness.close = onClose;
    return <div role="dialog">{children}</div>;
  },
}));
vi.mock("react", async (importOriginal) => {
  const original = await importOriginal<typeof import("react")>();
  return {
    ...original,
    useState: (initial: unknown) =>
      original.useState(typeof initial === "string" ? harness.name : initial),
    useEffect: (effect: EffectCallback) => harness.effects.push(effect),
  };
});
vi.mock("react/jsx-dev-runtime", async (importOriginal) => {
  const original =
    await importOriginal<typeof import("react/jsx-dev-runtime")>();
  return {
    ...original,
    jsxDEV: (...args: Parameters<typeof original.jsxDEV>) => {
      const element = original.jsxDEV(...args);
      const props = element.props as Record<string, unknown>;
      if (element.type === "input")
        harness.keyDown = props.onKeyDown as typeof harness.keyDown;
      if (element.type === "button")
        harness.actions.push({
          label: props.children as string,
          onClick: props.onClick as () => void,
        });
      return element;
    },
  };
});

beforeEach(() => {
  vi.clearAllMocks();
  harness.name = "  Project team  ";
  harness.effects = [];
  harness.actions = [];
  harness.keyDown = undefined;
  harness.close = undefined;
});

function mount(disabled = false) {
  const onCreate = vi
    .fn()
    .mockResolvedValue({ id: "project", name: "Project team" });
  const onAdded = vi.fn();
  const onClose = vi.fn();
  const html = renderToStaticMarkup(
    <ChatGroupDialog
      disabled={disabled}
      onCreate={onCreate}
      onAdded={onAdded}
      onClose={onClose}
    />,
  );
  const cleanups = harness.effects.map((effect) => effect());
  return {
    html,
    onCreate,
    onAdded,
    onClose,
    add: () =>
      harness.actions.find((action) => action.label === "Add")!.onClick(),
    cancel: () =>
      harness.actions.find((action) => action.label === "Cancel")!.onClick(),
    dispose: () => cleanups.forEach((cleanup) => cleanup?.()),
  };
}

test("adding once selects the created group before returning to the preserved form", async () => {
  const form = mount();
  let finish!: (group: { id: string; name: string }) => void;
  form.onCreate.mockReturnValue(
    new Promise((resolve) => {
      finish = resolve;
    }),
  );
  form.add();
  form.add();
  form.cancel();
  expect(form.onCreate).toHaveBeenCalledExactlyOnceWith("Project team");
  expect(form.onClose).not.toHaveBeenCalled();
  finish({ id: "project", name: "Project team" });
  await vi.waitFor(() => expect(form.onClose).toHaveBeenCalledOnce());
  expect(form.onAdded).toHaveBeenCalledExactlyOnceWith({
    id: "project",
    name: "Project team",
  });
  expect(form.onAdded.mock.invocationCallOrder[0]).toBeLessThan(
    form.onClose.mock.invocationCallOrder[0],
  );
});

test("Enter creates the group without submitting the underlying New chat form", async () => {
  const form = mount();
  const event = {
    key: "Enter",
    nativeEvent: { isComposing: false },
    preventDefault: vi.fn(),
    stopPropagation: vi.fn(),
  };
  harness.keyDown!(event as unknown as KeyboardEvent<HTMLInputElement>);
  expect(event.preventDefault).toHaveBeenCalledOnce();
  expect(event.stopPropagation).toHaveBeenCalledOnce();
  await vi.waitFor(() => expect(form.onAdded).toHaveBeenCalledOnce());
  expect(form.html).not.toContain("<form");
  expect(form.html.match(/type="button"/g)).toHaveLength(2);
});

test("cancel dismisses only the group dialog without creating or changing a group", () => {
  const form = mount();
  form.cancel();
  expect(form.onClose).toHaveBeenCalledOnce();
  expect(form.onCreate).not.toHaveBeenCalled();
  expect(form.onAdded).not.toHaveBeenCalled();
});

test("a rejected group keeps its name available for correction and retry", async () => {
  const form = mount();
  form.onCreate.mockRejectedValueOnce(
    new Error("chat group name already exists"),
  );
  form.add();
  await vi.waitFor(() => expect(harness.reportError).toHaveBeenCalledOnce());
  expect(form.onClose).not.toHaveBeenCalled();
  expect(form.onAdded).not.toHaveBeenCalled();
  form.add();
  await vi.waitFor(() => expect(form.onAdded).toHaveBeenCalledOnce());
});

test.each([true, false])(
  "empty input or a busy parent cannot create a group (busy: %s)",
  (disabled) => {
    harness.name = disabled ? "Project team" : "   ";
    const form = mount(disabled);
    form.add();
    expect(form.onCreate).not.toHaveBeenCalled();
  },
);

test("finishing after the surrounding screen closes does not change its selection", async () => {
  const form = mount();
  let finish!: (group: { id: string; name: string }) => void;
  form.onCreate.mockReturnValue(
    new Promise((resolve) => {
      finish = resolve;
    }),
  );
  form.add();
  form.dispose();
  finish({ id: "project", name: "Project team" });
  await Promise.resolve();
  expect(form.onAdded).not.toHaveBeenCalled();
  expect(form.onClose).not.toHaveBeenCalled();
});
