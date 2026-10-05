import { afterEach, beforeEach, expect, it, vi } from "vitest";
import type { Stream, View } from "./model";
import type { StreamEntry } from "./streamFeed";
import type { HistoryPage } from "./messageHistory";

const runtime = vi.hoisted(() => ({
  cursor: 0,
  slots: [] as any[],
  effects: [] as (() => void)[],
  cleanups: [] as (() => void)[],
  focused: true,
  dialog: false,
  mutation: (() => {}) as () => void,
  show: vi.fn(),
  play: vi.fn(async () => {}),
  stop: vi.fn(),
  invoke: vi.fn(),
}));
vi.mock("react", async (original) => ({
  ...(await original<typeof import("react")>()),
  useRef: (initial: unknown) => {
    const index = runtime.cursor++;
    return (runtime.slots[index] ??= { current: initial });
  },
  useState: (initial: unknown) => {
    const index = runtime.cursor++;
    if (!(index in runtime.slots))
      runtime.slots[index] =
        typeof initial === "function" ? initial() : initial;
    return [
      runtime.slots[index],
      (value: unknown) => {
        runtime.slots[index] =
          typeof value === "function" ? value(runtime.slots[index]) : value;
      },
    ];
  },
  useEffect: (effect: () => void | (() => void), deps?: unknown[]) => {
    const index = runtime.cursor++;
    const previous = runtime.slots[index] as unknown[] | undefined;
    if (
      deps &&
      previous &&
      deps.length === previous.length &&
      deps.every((value, index) => Object.is(value, previous[index]))
    )
      return;
    runtime.slots[index] = deps;
    runtime.effects.push(() => {
      const cleanup = effect();
      if (cleanup) runtime.cleanups.push(cleanup);
    });
  },
}));
vi.mock("@tauri-apps/api/core", () => ({
  invoke: runtime.invoke,
  isTauri: () => false,
}));
vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn(async () => () => {}),
}));
vi.mock("./Toast", () => ({ useToast: () => ({ showMessage: runtime.show }) }));
vi.mock("./notificationSounds", async (original) => ({
  ...(await original<typeof import("./notificationSounds")>()),
  playNotificationSound: runtime.play,
  stopNotificationSound: runtime.stop,
  readNotificationSound: () => "soft",
}));
import {
  appHasAttention,
  messageNoticeLabel,
  useActivityNotifications,
} from "./useActivityNotifications";
import {
  notificationEntry,
  resolveNotificationEntry,
} from "./usePushNotifications";

function fixture() {
  const row: Stream["rows"][number] = {
    id: "record",
    state: "ACCEPTED",
    unread: true,
    body: {
      kind: "chat.message",
      issuer_identity: "peer",
      payload: { text: "Hello" },
    },
  };
  const chat = {
    name: "General",
    space_context: "work",
    space: "space",
    stream: "general",
    head: "head",
    can_post: true,
    forked: false,
    member_names: { peer: "Alex" },
    rows: [row],
    members: [
      { identity_id: "me", capabilities: ["READ", "POST"] },
      { identity_id: "peer", capabilities: ["READ", "POST"] },
    ],
  } as unknown as Stream;
  const view = {
    identity: "me",
    active_space: "work",
    streams: [chat],
    spaces: [
      { id: "work", name: "Work", status: "joined" },
      { id: "friends", name: "Friends", status: "joined" },
    ],
  } as unknown as View;
  const entry: StreamEntry = { key: "work:space:general:record", chat, row };
  const options = {
    view,
    mobile: false,
    ready: true,
    onMessage: vi.fn(async () => true),
    onChat: vi.fn(async () => {}),
    onInbox: vi.fn(),
    onError: vi.fn(),
    isSessionAvailable: vi.fn(() => true),
  };
  return { view, chat, row, entry, options };
}
function render(options: Parameters<typeof useActivityNotifications>[0]) {
  runtime.cursor = 0;
  const hook = useActivityNotifications(options);
  while (runtime.effects.length) runtime.effects.shift()!();
  return hook;
}
function closeDialog() {
  runtime.dialog = false;
  runtime.mutation();
}

beforeEach(() => {
  runtime.cursor = 0;
  runtime.slots = [];
  runtime.effects = [];
  runtime.cleanups = [];
  runtime.focused = true;
  runtime.dialog = false;
  runtime.show.mockClear();
  runtime.play.mockClear();
  runtime.stop.mockClear();
  runtime.invoke.mockReset();
  vi.stubGlobal("document", {
    visibilityState: "visible",
    hasFocus: () => runtime.focused,
    querySelector: () => (runtime.dialog ? {} : null),
    body: {},
  });
  vi.stubGlobal(
    "MutationObserver",
    class {
      constructor(callback: () => void) {
        runtime.mutation = callback;
      }
      observe() {}
      disconnect() {}
    },
  );
  vi.stubGlobal("localStorage", { getItem: () => null, setItem: vi.fn() });
  vi.useFakeTimers();
  vi.setSystemTime(1_000_000);
});
afterEach(() => {
  runtime.cleanups.forEach((cleanup) => cleanup());
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

it("requires both visibility and focus before foreground sound or toast delivery", () => {
  const f = fixture();
  const notices = render(f.options);
  runtime.focused = false;
  expect(appHasAttention()).toBe(false);
  notices.messages([f.entry], f.view);
  runtime.focused = true;
  Object.defineProperty(document, "visibilityState", {
    value: "hidden",
    configurable: true,
  });
  expect(appHasAttention()).toBe(false);
  notices.messages([f.entry], f.view);
  expect(runtime.play).not.toHaveBeenCalled();
  expect(runtime.show).not.toHaveBeenCalled();
});

it("suppresses additional sound in a message burst without stopping the first or swallowing a session start", () => {
  const f = fixture();
  const notices = render(f.options);
  notices.messages([f.entry], f.view);
  notices.messages([{ ...f.entry, row: { ...f.row, id: "second" } }], f.view);
  expect(runtime.play).toHaveBeenCalledExactlyOnceWith("soft");
  notices.session(f.chat, "call", "Alex started a session");
  expect(runtime.play.mock.calls).toEqual([["soft"], ["soft"]]);
});

it("does not sound or announce messages and sessions without current read permission or after mute", () => {
  for (const change of ["revoked", "muted"] as const) {
    runtime.slots = [];
    const f = fixture();
    const notices = render(f.options);
    if (change === "revoked")
      f.chat.members = f.chat.members.filter(
        (member) => member.identity_id !== f.view.identity,
      );
    else f.chat.muted = true;
    notices.messages([f.entry], f.view);
    notices.session(f.chat, "call", "Alex started a session");
  }
  expect(runtime.play).not.toHaveBeenCalled();
  expect(runtime.show).not.toHaveBeenCalled();
});

it("does not display a queued session after it ended while a dialog was open", () => {
  const f = fixture();
  const notices = render(f.options);
  runtime.dialog = true;
  notices.session(f.chat, "call", "Alex started a session");
  expect(runtime.show).not.toHaveBeenCalled();
  f.options.isSessionAvailable.mockReturnValue(false);
  closeDialog();
  expect(runtime.show).not.toHaveBeenCalled();
});

it("a previously displayed session still opens only its chat after ending", async () => {
  const f = fixture();
  const notices = render(f.options);
  notices.session(f.chat, "call", "Alex started a session");
  expect(runtime.show).toHaveBeenCalledOnce();
  f.options.isSessionAvailable.mockReturnValue(false);
  runtime.show.mock.calls[0][1]();
  await Promise.resolve();
  expect(f.options.onChat).toHaveBeenCalledExactlyOnceWith(f.chat, "call");
  expect(f.options.onMessage).not.toHaveBeenCalled();
  expect(runtime.invoke).not.toHaveBeenCalled();
});

it("drops a dialog-deferred message after it is read, muted, expired as a notice, or the profile changes", () => {
  for (const change of ["read", "muted", "old", "profile"] as const) {
    runtime.slots = [];
    runtime.show.mockClear();
    const f = fixture();
    const notices = render(f.options);
    runtime.dialog = true;
    notices.messages([f.entry], f.view);
    if (change === "read") f.row.unread = false;
    if (change === "muted") f.chat.muted = true;
    if (change === "old") vi.advanceTimersByTime(60_001);
    if (change === "profile")
      render({ ...f.options, view: { ...f.view, identity: "other" } });
    closeDialog();
    expect(runtime.show).not.toHaveBeenCalled();
  }
});

it("counts conversations in distinct hosting contexts separately", () => {
  const f = fixture();
  const other = { ...f.entry, chat: { ...f.chat, space_context: "friends" } };
  expect(messageNoticeLabel([f.entry, other], f.view)).toBe(
    "2 new messages in 2 conversations",
  );
  const notices = render(f.options);
  f.view.all_streams = [f.chat, other.chat];
  notices.messages([f.entry, other], f.view);
  runtime.show.mock.calls[0][1]();
  expect(f.options.onInbox).toHaveBeenCalledOnce();
});

it("resolves a record only inside the notification's exact hosting context", async () => {
  const f = fixture();
  const other = { ...f.chat, space_context: "friends" };
  f.view.all_streams = [f.chat, other];
  const target = {
    identity: "me",
    space: "space",
    stream: "general",
    space_context: "friends",
    record: "record",
  };
  expect(notificationEntry(f.view, target)?.chat).toBe(other);
  const read = vi.fn(async () => ({
    history: {
      identity: "me",
      space_context: "friends",
      space: "space",
      stream: "general",
      revision: 1,
      rows: [f.row],
      context: [],
      next: null,
      newer: null,
    } as HistoryPage,
  }));
  const entry = await resolveNotificationEntry(
    { ...f.view, paged: true },
    target,
    read,
  );
  expect(entry?.chat).toBe(other);
  expect(read).toHaveBeenCalledExactlyOnceWith(
    expect.objectContaining({ target_space: "friends" }),
  );
  expect(
    notificationEntry(f.view, { ...target, space_context: "missing" }),
  ).toBeUndefined();
  // Normalization still supports the active Space's streams without a redundant context field.
  f.view.streams[0] = { ...f.chat, space_context: undefined };
  f.view.all_streams = f.view.streams;
  expect(
    notificationEntry(f.view, { ...target, space_context: "work" })?.chat,
  ).toBe(f.view.streams[0]);
});

it("a missing or mismatched session availability proof cannot announce a start", () => {
  const f = fixture();
  const unconfigured = render({ ...f.options, isSessionAvailable: undefined });
  unconfigured.session(f.chat, "call", "Alex started a session");
  const unavailable = render({ ...f.options, isSessionAvailable: () => false });
  unavailable.session(f.chat, "call", "Alex started a session");
  expect(runtime.show).not.toHaveBeenCalled();
  expect(runtime.play).not.toHaveBeenCalled();
});

it("uses the verified sync snapshot for a just-discovered chat before React commits the new view", async () => {
  const f = fixture();
  const oldView = { ...f.view, streams: [], all_streams: [] };
  const notices = render({ ...f.options, view: oldView });
  // receiveSync updates React state and immediately reports verified arrivals.
  // The hook still sees the preceding render, without this newly joined chat.
  notices.messages([f.entry], f.view);
  expect(runtime.show).toHaveBeenCalledOnce();
  expect(runtime.show.mock.calls[0][0]).toContain("Hello");
  expect(runtime.play).toHaveBeenCalledExactlyOnceWith("soft");
  render(f.options);
  runtime.show.mock.calls[0][1]();
  await Promise.resolve();
  expect(f.options.onMessage).toHaveBeenCalledExactlyOnceWith(
    expect.objectContaining({ chat: f.chat, row: f.row }),
  );
});

it("a sync snapshot cannot bypass a profile change or revive a queued message after mute", () => {
  const f = fixture();
  const notices = render(f.options);
  notices.messages([f.entry], { ...f.view, identity: "another-profile" });
  expect(runtime.show).not.toHaveBeenCalled();
  expect(runtime.play).not.toHaveBeenCalled();
  runtime.dialog = true;
  notices.messages([f.entry], f.view);
  render({
    ...f.options,
    view: { ...f.view, streams: [{ ...f.chat, muted: true }] },
  });
  closeDialog();
  expect(runtime.show).not.toHaveBeenCalled();
});
