import { expect, test, vi } from "vitest";
import { invitationSeenRequest } from "./invitationAttention";
import {
  markNotificationOfferHandled,
  notificationOfferHandled,
  shouldOfferNotifications,
} from "./NotificationOffer";
import {
  notificationEntry,
  notificationCatchUpRequest,
  notificationPage,
  notificationSpace,
  notificationChat,
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
    foreground: true,
    receive_only: true,
    target_space: "company-b",
    expected_identity: "me",
    expected_space: "company-a",
  });
  const discovery = {
    op: "invitation_sync",
    foreground: true,
    force: true,
    expected_identity: "me",
  };
  expect(notificationCatchUpRequest(spaces, target, true)).toEqual({
    ...discovery,
    target_space: "company-b",
  });
  expect(
    notificationCatchUpRequest({ ...spaces, all_streams: [] }, target),
  ).toEqual(discovery);
  expect(
    notificationCatchUpRequest(spaces, { ...target, identity: "other" }),
  ).toBeUndefined();
  expect(notificationCatchUpRequest(spaces, null)).toBeUndefined();
});
test("a new chat push discovers only its locally joined Space without scanning stale Spaces", () => {
  const current = {
    ...view,
    active_space: "other-space",
    spaces: [
      { id: "joined-space", status: "joined" },
      { id: "pending-space", status: "pending" },
    ],
  } as View;
  const target = {
    identity: "me",
    category: "invitation",
    space: "joined-space",
    chat: { space: "new-space", stream: "new-chat", invitation: "proof" },
  };
  const discovery = {
    op: "invitation_sync",
    foreground: true,
    force: true,
    expected_identity: "me",
  };
  expect(notificationCatchUpRequest(current, target)).toEqual({
    ...discovery,
    target_space: "joined-space",
    receive_only: true,
  });
  expect(
    notificationCatchUpRequest(current, { ...target, category: "membership" }),
  ).toEqual({ ...discovery, target_space: "joined-space" });
  for (const space of ["pending-space", "unknown-space", null]) {
    expect(notificationCatchUpRequest(current, { ...target, space })).toEqual(
      discovery,
    );
  }
  expect(
    notificationCatchUpRequest(current, { ...target, identity: "other" }),
  ).toBeUndefined();
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

test("membership invitation taps open only a locally joined chat, including empty chats", () => {
  const chat = {
    ...view.streams[0],
    space_context: "joined-space",
    rows: [],
    members: [
      {
        identity_id: "me",
        capabilities: ["READ"],
        external: true,
        credential_ids: ["credential"],
      },
    ],
  } as View["streams"][number];
  const current = {
    ...view,
    all_streams: [chat],
    all_invitations: { actionable: 1 },
  } as View;
  const target = {
    identity: "me",
    category: "invitation",
    chat: { space: "space", stream: "chat", invitation: "proof" },
  };
  expect(notificationChat(current, target)).toBe(chat);
  expect(notificationSpace(current, target)).toBe("joined-space");
  expect(notificationPage(current, target)).toBeUndefined();
  expect(
    notificationChat(current, { ...target, identity: "other" }),
  ).toBeUndefined();
  expect(
    notificationChat(current, { ...target, category: "message" }),
  ).toBeUndefined();
  for (const members of [
    [],
    [{ identity_id: "other", capabilities: ["READ"] }],
    [{ identity_id: "me", capabilities: [] }],
  ]) {
    expect(
      notificationChat(
        { ...current, all_streams: [{ ...chat, members } as typeof chat] },
        target,
      ),
    ).toBeUndefined();
  }
  const pending = { ...current, all_streams: [] };
  expect(notificationChat(pending, target)).toBeUndefined();
  expect(notificationPage(pending, target)).toBe("activity");
  expect(notificationCatchUpRequest(pending, target)?.op).toBe(
    "invitation_sync",
  );
});

test("invitation taps select only a joined Space owned by the unlocked profile", () => {
  const scoped = {
    ...view,
    active_space: "a",
    spaces: [
      { id: "a", status: "joined" },
      { id: "b", status: "joined" },
      { id: "c", status: "pending" },
    ],
  } as View;
  const target = { identity: "me", category: "invitation", space: "b" };
  expect(notificationSpace(scoped, target)).toBe("b");
  expect(
    notificationSpace(scoped, { ...target, identity: "other" }),
  ).toBeUndefined();
  expect(notificationSpace(scoped, { ...target, space: "c" })).toBeUndefined();
  expect(
    notificationSpace(scoped, { ...target, space: "unknown" }),
  ).toBeUndefined();
  expect(
    notificationSpace(scoped, { ...target, record: "message" }),
  ).toBeUndefined();
});

test("a seen pending invitation still opens Invitations until explicitly accepted", () => {
  const target = {
    identity: "me",
    category: "invitation",
    space: "joined-space",
    chat: { space: "new-space", stream: "new-chat", invitation: "proof" },
  };
  const pending = {
    ...view,
    active_space: "other-space",
    spaces: [{ id: "joined-space", status: "joined", activity: 1 }],
    all_streams: [],
    all_invitations: { actionable: 1, unseen: 0 },
  } as unknown as View;
  expect(notificationSpace(pending, target)).toBe("joined-space");
  expect(notificationPage(pending, target)).toBe("activity");
  expect(notificationChat(pending, target)).toBeUndefined();

  const handled = {
    ...pending,
    spaces: [{ ...pending.spaces![0], activity: 0 }],
    all_invitations: { actionable: 0, unseen: 0 },
  } as View;
  expect(notificationPage(handled, target)).toBeUndefined();
  expect(notificationChat(handled, target)).toBeUndefined();

  const chat = {
    ...view.streams[0],
    space: "new-space",
    stream: "new-chat",
    space_context: "joined-space",
    rows: [],
    members: [
      {
        identity_id: "me",
        capabilities: ["READ"],
        external: true,
        credential_ids: ["credential"],
      },
    ],
  } as View["streams"][number];
  const accepted = { ...handled, all_streams: [chat] };
  expect(notificationPage(accepted, target)).toBeUndefined();
  expect(notificationChat(accepted, target)).toBe(chat);
  expect(notificationSpace(accepted, target)).toBe("joined-space");
});

test("viewing Invitations never marks hidden notices or a future approval as seen", () => {
  const activity = {
    received: [{ id: "invite" }],
    incoming: [{ id: "request" }],
    outgoing: [
      { id: "waiting", status: "waiting" },
      { id: "ready", status: "approved" },
      { id: "declined", status: "declined", seen: false },
    ],
    notices: [
      { id: "removal", seen: false },
      { id: "old", seen: true },
    ],
  };
  expect(invitationSeenRequest("activity", activity)).toEqual({
    op: "invitation_activity_seen",
    ids: ["invitation:invite", "request:request", "approved:ready"],
  });
  expect(invitationSeenRequest("notifications", activity)).toEqual({
    op: "invitation_notifications_seen",
    ids: ["removal", "declined"],
  });
  expect(invitationSeenRequest("invite", activity)).toBeUndefined();
  expect(invitationSeenRequest("activity", {})).toBeUndefined();
});

function sessionTargetFixture() {
  const chat = {
    ...view.streams[0],
    space_context: "company-b",
    forked: false,
    members: [
      {
        identity_id: "me",
        credential_ids: ["device"],
        capabilities: ["READ", "POST"],
        external: false,
      },
    ],
  };
  const current = {
    ...view,
    active_space: "company-a",
    streams: [],
    all_streams: [chat],
    spaces: [
      {
        id: "company-a",
        name: "Company A",
        status: "joined",
        owner: false,
        requests: 0,
        managed: true,
      },
      {
        id: "company-b",
        name: "Company B",
        status: "joined",
        owner: false,
        requests: 0,
        managed: true,
      },
    ],
  } as View;
  const target = {
    identity: "me",
    category: "session_start",
    space_context: "company-b",
    space: "space",
    stream: "chat",
    call_id: "a".repeat(32),
    expires: Date.now() + 60_000,
  };
  return { chat, current, target };
}

test("a session notification selects only its known readable chat in the matching profile and Space", () => {
  const { chat, current, target } = sessionTargetFixture();
  const before = structuredClone(current);
  expect(notificationChat(current, target)).toBe(chat);
  expect(notificationSpace(current, target)).toBe("company-b");
  expect(notificationPage(current, target)).toBeUndefined();
  expect(notificationEntry(current, target)).toBeUndefined();
  for (const change of [
    { identity: "other" },
    { space_context: "company-a" },
    { space: "unknown" },
    { stream: "unknown" },
    { category: "message" },
    { record: "message" },
    { call_id: "" },
    { call_id: "a".repeat(31) },
    { call_id: "a".repeat(33) },
    { call_id: "A".repeat(32) },
    { call_id: "z".repeat(32) },
  ])
    expect(notificationChat(current, { ...target, ...change })).toBeUndefined();
  for (const change of [
    { forked: true },
    { members: [] },
    {
      members: [
        {
          identity_id: "me",
          capabilities: ["POST"],
          credential_ids: ["device"],
          external: false,
        },
      ],
    },
  ])
    expect(
      notificationChat(
        { ...current, all_streams: [{ ...chat, ...change }] },
        target,
      ),
    ).toBeUndefined();
  expect(current).toEqual(before);
});

test("an expired session notification can still navigate to its verified chat but never confers session availability", () => {
  const { chat, current, target } = sessionTargetFixture();
  const expired = { ...target, expires: 1 };
  expect(notificationChat(current, expired)).toBe(chat);
  expect(notificationSpace(current, expired)).toBe("company-b");
  // No call is returned or started: the caller receives only the local chat.
  // Join is separately gated by the latest ready session in Calls.
  expect(
    notificationChat({ ...current, all_streams: [] }, expired),
  ).toBeUndefined();
  expect(
    notificationChat(current, { ...expired, identity: "other" }),
  ).toBeUndefined();
  expect(notificationCatchUpRequest(current, target)).toEqual({
    op: "sync_live",
    foreground: true,
    receive_only: true,
    target_space: "company-b",
    expected_identity: "me",
    expected_space: "company-a",
  });
});

test("session routing keeps exact hosting context when the same chat IDs occur in two Spaces", () => {
  const { chat, current, target } = sessionTargetFixture();
  const other = { ...chat, space_context: "company-a" };
  current.all_streams = [other, chat];
  expect(notificationChat(current, target)).toBe(chat);
  expect(notificationCatchUpRequest(current, target)?.target_space).toBe(
    "company-b",
  );
  expect(
    notificationChat(current, { ...target, space_context: "missing" }),
  ).toBeUndefined();
  current.all_streams = [{ ...other, space_context: undefined }];
  expect(
    notificationChat(current, { ...target, space_context: "company-a" }),
  ).toBe(current.all_streams[0]);
});
