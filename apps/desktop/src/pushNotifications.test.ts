import { expect, test, vi } from "vitest";
import {
  markNotificationOfferHandled,
  notificationOfferHandled,
  shouldOfferNotifications,
} from "./NotificationOffer";
import {
  notificationEntry,
  notificationCatchUpRequest,
  notificationPage,
  resolveNotificationEntry,
} from "./usePushNotifications";
import type { HistoryPage } from "./messageHistory";
import type { View } from "./model";
const view = {
  identity: "me",
  streams: [
    {
      space: "space",
      stream: "chat",
      rows: [
        { id: "message", body: { kind: "chat.message" } },
        {
          id: "reply",
          body: { kind: "chat.message", payload: { thread_root: "message" } },
        },
      ],
    },
  ],
} as View;

test("a tapped known chat receives first in its joined Space; unknown authority requires discovery", () => {
  const target = {
    identity: "me",
    space: "space",
    stream: "chat",
    record: "new",
  };
  const spaces = {
    ...view,
    active_space: "company-a",
    streams: [],
    all_streams: [{ ...view.streams[0], space_context: "company-b" }],
  };
  expect(notificationCatchUpRequest(spaces, target)).toEqual({
    op: "sync_live",
    receive_only: true,
    target_space: "company-b",
    expected_identity: "me",
    expected_space: "company-a",
  });
  const discovery = {
    op: "invitation_sync",
    force: true,
    expected_identity: "me",
  };
  expect(notificationCatchUpRequest(spaces, target, true)).toEqual(discovery);
  expect(
    notificationCatchUpRequest({ ...spaces, all_streams: [] }, target),
  ).toEqual(discovery);
  expect(
    notificationCatchUpRequest(spaces, { ...target, identity: "other" }),
  ).toBeUndefined();
  expect(notificationCatchUpRequest(spaces, null)).toBeUndefined();
});
test("notification consent waits for authenticated setup and is not repeated after a decision", () => {
  const stored = new Map<string, string>();
  vi.stubGlobal("localStorage", {
    getItem: (key: string) => stored.get(key) ?? null,
    setItem: (key: string, value: string) => stored.set(key, value),
  });
  try {
    const available = { available: true, enabled: false };
    expect(
      shouldOfferNotifications(false, available, notificationOfferHandled()),
    ).toBe(false);
    expect(
      shouldOfferNotifications(true, { ...available, available: false }, false),
    ).toBe(false);
    expect(
      shouldOfferNotifications(true, { ...available, enabled: true }, false),
    ).toBe(false);
    expect(
      shouldOfferNotifications(true, available, notificationOfferHandled()),
    ).toBe(true);
    markNotificationOfferHandled();
    // Both Not now and Enable persist a device choice, including permission denial.
    expect(
      shouldOfferNotifications(true, available, notificationOfferHandled()),
    ).toBe(false);
    expect(
      shouldOfferNotifications(false, available, notificationOfferHandled()),
    ).toBe(false);
    expect(
      shouldOfferNotifications(true, available, notificationOfferHandled()),
    ).toBe(false);
  } finally {
    vi.unstubAllGlobals();
  }
});
test("push navigation resolves only the matching profile and exact verified row", () => {
  const target = {
    identity: "me",
    space: "space",
    stream: "chat",
    record: "message",
  };
  expect(notificationEntry(view, target)?.row.id).toBe("message");
  expect(
    notificationEntry(view, { ...target, identity: "other" }),
  ).toBeUndefined();
  expect(
    notificationEntry(view, { ...target, space: "other" }),
  ).toBeUndefined();
  expect(
    notificationEntry(view, { ...target, record: "missing" }),
  ).toBeUndefined();
  expect(notificationEntry(view, null)).toBeUndefined();
  expect(
    notificationEntry(view, { ...target, record: "reply" })?.row.body.payload
      ?.thread_root,
  ).toBe("message");
  expect(view.streams[0].rows[0].unread).toBeUndefined();
});

test("a push resolves a verified message in another connected Space without adding it to the selected list", () => {
  const background = { ...view.streams[0], space_context: "company-b" };
  const switched = {
    ...view,
    active_space: "company-a",
    streams: [],
    all_streams: [background],
  };
  expect(
    notificationEntry(switched, {
      identity: "me",
      space: "space",
      stream: "chat",
      record: "message",
    })?.chat.space_context,
  ).toBe("company-b");
  expect(switched.streams).toHaveLength(0);
  expect(
    notificationEntry(
      { ...switched, all_streams: [] },
      { identity: "me", space: "space", stream: "chat", record: "message" },
    ),
  ).toBeUndefined();
});

test("a push prepares the reply's thread page in a connected Space before switching", async () => {
  const chat = { ...view.streams[0], rows: [], space_context: "company-b" };
  const summary = {
    ...view,
    paged: true,
    active_space: "company-a",
    streams: [],
    all_streams: [chat],
  };
  const target = {
    identity: "me",
    space: "space",
    stream: "chat",
    record: "reply",
  };
  const page: HistoryPage = {
    identity: "me",
    space_context: "company-b",
    space: "space",
    stream: "chat",
    rows: [view.streams[0].rows[1]],
    context: [],
    next: null,
    revision: 1,
  };
  const read = vi.fn(async (request: Record<string, unknown>) => ({
    history: request.thread
      ? {
          ...page,
          thread: String(request.thread),
          context: [view.streams[0].rows[0]],
        }
      : page,
  }));
  const entry = await resolveNotificationEntry(summary, target, read);
  expect(entry?.row.body.payload?.thread_root).toBe("message");
  expect(entry?.chat.space_context).toBe("company-b");
  expect(entry?.history?.thread).toBe("message");
  expect(entry?.history?.context[0].id).toBe("message");
  expect(read).toHaveBeenCalledTimes(2);
  expect(read).toHaveBeenNthCalledWith(1, {
    op: "history_page",
    expected_identity: "me",
    expected_space: "company-a",
    target_space: "company-b",
    space: "space",
    stream: "chat",
    around: "reply",
  });
  expect(read).toHaveBeenNthCalledWith(2, {
    ...read.mock.calls[0][0],
    thread: "message",
  });
  expect(summary.active_space).toBe("company-a");
  expect(chat.rows).toHaveLength(0);
  for (const mismatch of [
    { identity: "other" },
    { space_context: "company-a" },
    { space: "other" },
    { stream: "other" },
    { rows: [view.streams[0].rows[0]] },
    { rows: [] },
  ]) {
    expect(
      await resolveNotificationEntry(summary, target, async () => ({
        history: { ...page, ...mismatch },
      })),
    ).toBeUndefined();
  }
  read.mockClear();
  expect(
    await resolveNotificationEntry(
      summary,
      { ...target, identity: "other" },
      read,
    ),
  ).toBeUndefined();
  expect(
    await resolveNotificationEntry(
      { ...summary, all_streams: [] },
      target,
      read,
    ),
  ).toBeUndefined();
  expect(read).not.toHaveBeenCalled();
});

test("a paged push prepares the surrounding messages even if its target is already in the summary", async () => {
  const summary = { ...view, paged: true };
  const target = {
    identity: "me",
    space: "space",
    stream: "chat",
    record: "message",
  };
  const history: HistoryPage = {
    identity: "me",
    space: "space",
    stream: "chat",
    revision: 7,
    rows: [view.streams[0].rows[0]],
    context: [],
    next: "older",
    newer: null,
  };
  const read = vi.fn(async () => ({ history }));
  const entry = await resolveNotificationEntry(summary, target, read);
  expect(entry?.history).toBe(history);
  expect(read).toHaveBeenCalledExactlyOnceWith({
    op: "history_page",
    expected_identity: "me",
    expected_space: undefined,
    target_space: undefined,
    space: "space",
    stream: "chat",
    around: "message",
  });
  for (const mismatch of [
    { identity: "other" },
    { space_context: "other" },
    { space: "other" },
    { stream: "other" },
    { rows: [] },
  ]) {
    expect(
      await resolveNotificationEntry(summary, target, async () => ({
        history: { ...history, ...mismatch },
      })),
    ).toBeUndefined();
  }
});

test("old invitation pushes never open an empty Invitations screen or cross profiles", () => {
  const target = { identity: "me", category: "invitation" };
  expect(notificationPage(view, target)).toBeUndefined();
  const pending = {
    ...view,
    all_invitations: { actionable: 1, notifications: 1 },
  } as View;
  expect(notificationPage(pending, target)).toBe("activity");
  expect(notificationPage(pending, { ...target, category: "membership" })).toBe(
    "notifications",
  );
  expect(
    notificationPage(pending, {
      ...target,
      category: "message",
      record: "message",
    }),
  ).toBeUndefined();
  expect(
    notificationPage(pending, { ...target, identity: "other" }),
  ).toBeUndefined();
  expect(notificationPage(pending, null)).toBeUndefined();
});
