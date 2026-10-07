import { expect, test, vi } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import type { SyntheticEvent } from "react";
import { ActionDialog } from "./ActionDialog";

const harness = vi.hoisted(() => ({
  cancel: undefined as
    ((event: SyntheticEvent<HTMLDialogElement>) => void) | undefined,
}));
vi.mock("react/jsx-dev-runtime", async (importOriginal) => {
  const original =
    await importOriginal<typeof import("react/jsx-dev-runtime")>();
  return {
    ...original,
    jsxDEV: (...args: Parameters<typeof original.jsxDEV>) => {
      const element = original.jsxDEV(...args);
      if (element.type === "dialog")
        harness.cancel = (
          element.props as { onCancel: typeof harness.cancel }
        ).onCancel;
      return element;
    },
  };
});

test("Escape dismisses the active dialog without canceling its underlying workflow", () => {
  const onClose = vi.fn();
  renderToStaticMarkup(
    <ActionDialog title="New group" onClose={onClose}>
      <input aria-label="Name" />
    </ActionDialog>,
  );
  const event = { preventDefault: vi.fn(), stopPropagation: vi.fn() };
  harness.cancel!(event as unknown as SyntheticEvent<HTMLDialogElement>);
  expect(event.preventDefault).toHaveBeenCalledOnce();
  expect(event.stopPropagation).toHaveBeenCalledOnce();
  expect(onClose).toHaveBeenCalledOnce();
});
