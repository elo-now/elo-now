import { expect, test } from "vitest";
import { updateKeyboardViewport } from "./useViewport";

const portrait = {
  layoutWidth: 390,
  layoutHeight: 844,
  height: 844,
  scale: 1,
  editing: false,
};

test("an open keyboard survives temporary blur and refocus until the viewport returns", () => {
  let state = updateKeyboardViewport(undefined, portrait);
  state = updateKeyboardViewport(state, {
    ...portrait,
    height: 500,
    editing: true,
  });
  expect(state.keyboardOpen).toBe(true);
  state = updateKeyboardViewport(state, { ...portrait, height: 500 });
  expect(state.keyboardOpen).toBe(true);
  state = updateKeyboardViewport(state, {
    ...portrait,
    height: 500,
    editing: true,
  });
  expect(state.keyboardOpen).toBe(true);
  state = updateKeyboardViewport(state, portrait);
  expect(state.keyboardOpen).toBe(false);
});

test("keyboard dismissal is detected even while the textarea remains focused", () => {
  let state = updateKeyboardViewport(undefined, portrait);
  state = updateKeyboardViewport(state, {
    ...portrait,
    height: 500,
    editing: true,
  });
  state = updateKeyboardViewport(state, { ...portrait, editing: true });
  expect(state.keyboardOpen).toBe(false);
  state = updateKeyboardViewport(state, {
    ...portrait,
    height: 500,
    editing: true,
  });
  expect(state.keyboardOpen).toBe(true);
});

test("a new keyboard needs an editable focus rather than a reduced viewport alone", () => {
  let state = updateKeyboardViewport(undefined, portrait);
  state = updateKeyboardViewport(state, { ...portrait, height: 500 });
  expect(state.keyboardOpen).toBe(false);
  state = updateKeyboardViewport(state, {
    ...portrait,
    height: 500,
    editing: true,
  });
  expect(state.keyboardOpen).toBe(true);
});

test("a WebView that shrinks both viewports retains the height before editing", () => {
  let state = updateKeyboardViewport(undefined, portrait);
  const reduced = { ...portrait, layoutHeight: 500, height: 500 };
  state = updateKeyboardViewport(state, { ...reduced, editing: true });
  expect(state.keyboardOpen).toBe(true);
  expect(state.fullHeight).toBe(844);
  state = updateKeyboardViewport(state, reduced);
  expect(state.keyboardOpen).toBe(true);
  state = updateKeyboardViewport(state, portrait);
  expect(state.keyboardOpen).toBe(false);
});

test("rotation discards the old height and the keyboard latch", () => {
  let state = updateKeyboardViewport(undefined, portrait);
  state = updateKeyboardViewport(state, {
    ...portrait,
    height: 500,
    editing: true,
  });
  const landscape = {
    ...portrait,
    layoutWidth: 844,
    layoutHeight: 390,
    height: 390,
  };
  state = updateKeyboardViewport(state, landscape);
  expect(state.keyboardOpen).toBe(false);
  expect(state.fullHeight).toBe(390);
  state = updateKeyboardViewport(state, { ...landscape, height: 200 });
  expect(state.keyboardOpen).toBe(false);
  state = updateKeyboardViewport(state, {
    ...landscape,
    height: 200,
    editing: true,
  });
  expect(state.keyboardOpen).toBe(true);
});

test("a focused textarea does not preserve a stale keyboard after rotation", () => {
  let state = updateKeyboardViewport(undefined, portrait);
  state = updateKeyboardViewport(state, {
    ...portrait,
    height: 500,
    editing: true,
  });
  state = updateKeyboardViewport(state, {
    ...portrait,
    layoutWidth: 844,
    layoutHeight: 390,
    height: 390,
    editing: true,
  });
  expect(state.keyboardOpen).toBe(false);
});

test("a small window and an unfocused height resize do not become a keyboard on focus", () => {
  const small = { ...portrait, layoutHeight: 450, height: 450 };
  expect(updateKeyboardViewport(undefined, small).keyboardOpen).toBe(false);
  let state = updateKeyboardViewport(undefined, portrait);
  state = updateKeyboardViewport(state, small);
  expect(state.fullHeight).toBe(450);
  state = updateKeyboardViewport(state, { ...small, editing: true });
  expect(state.keyboardOpen).toBe(false);
});

test("pinch zoom alone does not open a keyboard even with editable focus", () => {
  let state = updateKeyboardViewport(undefined, portrait);
  state = updateKeyboardViewport(state, {
    ...portrait,
    height: 422,
    scale: 2,
    editing: true,
  });
  expect(state.keyboardOpen).toBe(false);
  expect(state.fullHeight).toBe(844);
  state = updateKeyboardViewport(state, { ...portrait, editing: true });
  expect(state.keyboardOpen).toBe(false);
});
