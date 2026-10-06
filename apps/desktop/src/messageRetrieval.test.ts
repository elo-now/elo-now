import { expect, test, vi } from "vitest";
import type { View } from "./model";
import { retrieveUnavailableMessage } from "./messageRetrieval";

const view = (changes: Partial<View> = {}) =>
  ({
    identity: "alice",
    active_space: "work",
    revision: 3,
    ...changes,
  }) as View;

function pendingRequest() {
  let complete!: (result: { view?: View }) => void;
  const result = new Promise<{ view?: View }>((resolve) => {
    complete = resolve;
  });
  let current: View | null = view();
  let scope: string | undefined = "alice:work:chat";
  const release = vi.fn();
  const receive = vi.fn(() => release);
  const updateView = vi.fn((update: (current: View | null) => View | null) => {
    current = update(current);
  });
  const options = {
    identity: "alice",
    space: "work",
    scope: "alice:work:chat",
    currentScope: () => scope,
    request: () => result,
    updateView,
    receive,
  };
  return {
    options,
    complete,
    receive,
    release,
    updateView,
    current: () => current,
    navigate: (next: string | undefined, nextView: View | null = current) => {
      scope = next;
      current = nextView;
    },
  };
}

test.each([
  ["alice:work:another-chat", view()],
  ["alice:work:chat:thread", view()],
  ["alice:friends:chat", view({ active_space: "friends", revision: 4 })],
  ["bob:work:chat", view({ identity: "bob" })],
  [undefined, null],
] as const)(
  "a delayed Retrieve reply cannot change the destination %s",
  async (scope, current) => {
    const request = pendingRequest();
    const completion = retrieveUnavailableMessage(request.options);
    request.navigate(scope, current);
    request.complete({ view: view({ revision: 5 }) });
    expect(await completion).toBeUndefined();
    expect(request.current()).toBe(current);
    expect(request.updateView).not.toHaveBeenCalled();
    expect(request.receive).not.toHaveBeenCalled();
  },
);

test("a delayed Retrieve reply preserves a newer view of its original conversation", async () => {
  const request = pendingRequest();
  const completion = retrieveUnavailableMessage(request.options);
  const newer = view({ revision: 8 });
  request.navigate(request.options.scope, newer);
  request.complete({ view: view({ revision: 7 }) });
  expect(await completion).toBe(request.release);
  expect(request.current()).toBe(newer);
  expect(request.receive).toHaveBeenCalledTimes(1);
});

test("an accepted Retrieve reply updates its view and returns the receive lease", async () => {
  const request = pendingRequest();
  const completion = retrieveUnavailableMessage(request.options);
  const next = view({ revision: 4 });
  request.complete({ view: next });
  expect(await completion).toBe(request.release);
  expect(request.current()).toBe(next);
  expect(request.receive).toHaveBeenCalledTimes(1);
});

test.each([
  view({ identity: "bob", revision: 4 }),
  view({ active_space: "friends", revision: 4 }),
])(
  "a Retrieve reply cannot replace the profile or selected Space",
  async (next) => {
    const request = pendingRequest();
    const original = request.current();
    const completion = retrieveUnavailableMessage(request.options);
    request.complete({ view: next });
    await completion;
    expect(request.current()).toBe(original);
  },
);

test("a queued React view update rechecks navigation before applying the native reply", async () => {
  const request = pendingRequest();
  let queued!: (current: View | null) => View | null;
  const completion = retrieveUnavailableMessage({
    ...request.options,
    updateView: (update) => {
      queued = update;
    },
  });
  request.complete({ view: view({ revision: 4 }) });
  await completion;
  const other = view({ active_space: "friends", revision: 5 });
  request.navigate("alice:friends:chat", other);
  expect(queued(other)).toBe(other);
  expect(queued(null)).toBeNull();
});
