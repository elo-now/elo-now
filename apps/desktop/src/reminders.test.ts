import { beforeEach, expect, it, vi } from "vitest";
const native = vi.hoisted(() => ({
  invoke: vi.fn(),
  pending: vi.fn(),
  active: vi.fn(),
  cancel: vi.fn(),
  removeActive: vi.fn(),
  onAction: vi.fn(),
}));
vi.mock("@tauri-apps/api/core", () => ({ invoke: native.invoke }));
vi.mock("@tauri-apps/plugin-notification", () => ({
  ...native,
  Schedule: { at: (date: Date) => ({ at: { date } }) },
}));
import {
  scheduleReminder,
  cancelReminder,
  reconcileReminders,
  cancelProfileReminders,
  reminderActionProfile,
  reminderProfileMatches,
  watchReminderActions,
} from "./reminders";
import type { View } from "./model";
let saved: Map<string, string>;
beforeEach(() => {
  vi.clearAllMocks();
  saved = new Map();
  vi.stubGlobal("localStorage", {
    getItem: (key: string) => saved.get(key) ?? null,
    setItem: (key: string, value: string) => saved.set(key, value),
  });
  native.invoke.mockImplementation(async (command: string) =>
    command.endsWith("is_permission_granted") ? true : undefined,
  );
  native.pending.mockResolvedValue([]);
  native.active.mockResolvedValue([]);
  native.cancel.mockResolvedValue(undefined);
  native.removeActive.mockResolvedValue(undefined);
});
it("schedules generic text without leaking any profile, chat, record or message text", async () => {
  const due = Date.now() + 60000;
  expect(
    await scheduleReminder(
      "private-profile",
      "private-chat",
      "private-record",
      due,
      true,
    ),
  ).toBe(true);
  const notify = native.invoke.mock.calls.find(([command]) =>
    command.endsWith("|notify"),
  )!;
  expect(notify[1].options.schedule.at.date.getTime()).toBe(due);
  expect(JSON.stringify(notify)).not.toMatch(
    /private-profile|private-chat|private-record/,
  );
  expect(JSON.stringify([...saved.values()])).not.toMatch(
    /private-profile|private-chat|private-record/,
  );
});
it("denied permission and desktop keep the durable in-app reminder without scheduling", async () => {
  native.invoke.mockResolvedValue(false);
  expect(await scheduleReminder("a", "b", "c", Date.now() + 60000, true)).toBe(
    false,
  );
  expect(
    native.invoke.mock.calls.some(([command]) => command.endsWith("|notify")),
  ).toBe(false);
  native.invoke.mockClear();
  expect(await scheduleReminder("a", "b", "c", Date.now() + 60000, false)).toBe(
    false,
  );
  expect(native.invoke).not.toHaveBeenCalled();
});
it("rescheduling replaces the same OS request and Done cancels only that reminder", async () => {
  await scheduleReminder("a", "b", "c", Date.now() + 60000, true);
  await scheduleReminder("other", "b", "c", Date.now() + 60000, true);
  const notifications = () =>
    native.invoke.mock.calls.filter(([c]) => c.endsWith("|notify"));
  const id = notifications()[0][1].options.id;
  const other = notifications()[1][1].options.id;
  expect(other).not.toBe(id);
  await scheduleReminder("a", "b", "c", Date.now() + 120000, true);
  expect(notifications()[2][1].options.id).toBe(id);
  await cancelReminder("a", "b", "c", true);
  expect(native.cancel).toHaveBeenLastCalledWith([id]);
  expect(native.removeActive).toHaveBeenLastCalledWith([{ id }]);
  expect(native.cancel.mock.calls.flat(2)).not.toContain(other);
});
it("restart reconciles future reminders without another permission prompt or repeating due ones", async () => {
  const view = {
    identity: "a",
    reminders: [
      {
        stream: "b",
        record: "c",
        due_at: Date.now() + 60000,
        system_notification: true,
      },
      { stream: "b", record: "past", due_at: 1, system_notification: true },
    ],
  } as View;
  await reconcileReminders(view, true);
  expect(
    native.invoke.mock.calls.filter(([c]) => c.endsWith("|notify")),
  ).toHaveLength(1);
  expect(
    native.invoke.mock.calls.some(([c]) => c.endsWith("|request_permission")),
  ).toBe(false);
  const id = native.invoke.mock.calls.find(([c]) => c.endsWith("|notify"))![1]
    .options.id;
  native.pending.mockResolvedValue([{ id }]);
  await reconcileReminders(view, true);
  expect(
    native.invoke.mock.calls.filter(([c]) => c.endsWith("|notify")),
  ).toHaveLength(1);
});
it("native scheduling errors propagate instead of claiming a notification exists", async () => {
  native.invoke.mockImplementation(async (c: string) => {
    if (c.endsWith("|notify")) throw new Error("native scheduling failed");
    return true;
  });
  await expect(
    scheduleReminder("a", "b", "c", Date.now() + 60000, true),
  ).rejects.toThrow("native scheduling failed");
});

it("profile removal cancels only its own reminders and erases its scheduling registry", async () => {
  await scheduleReminder("a", "b", "c", Date.now() + 60_000, true);
  await scheduleReminder("other", "b", "c", Date.now() + 60_000, true);
  const calls = native.invoke.mock.calls.filter(([c]) => c.endsWith("|notify"));
  await cancelProfileReminders("a", true);
  expect(native.cancel).toHaveBeenLastCalledWith([calls[0][1].options.id]);
  expect(Object.values(JSON.parse([...saved.values()][0]))).toHaveLength(1);
  const remaining = JSON.stringify([...saved.values()]);
  expect(remaining).toContain(String(calls[1][1].options.id));
});

it("accepts Android's wrapped active notification list before scheduling", async () => {
  native.active.mockResolvedValue({
    values: [{ nameValuePairs: { id: 123, title: "elo.now" } }],
  });
  expect(await scheduleReminder("a", "b", "c", Date.now() + 60000, true)).toBe(
    true,
  );
  const notify = native.invoke.mock.calls.find(([command]) =>
    command.endsWith("|notify"),
  )!;
  expect(notify[1].options.id).not.toBe(123);
});

it("bounds scheduled reminders when Android reports an empty pending list", async () => {
  const due = Date.now() + 60000;
  for (let n = 0; n < 60; n++) {
    expect(await scheduleReminder("a", "b", String(n), due, true)).toBe(true);
  }
  expect(await scheduleReminder("other", "b", "new", due, true)).toBe(false);
  expect(await scheduleReminder("a", "b", "0", due + 60000, true)).toBe(true);
});

it("keeps notifications opt-in and cancels a reminder when its option is turned off", async () => {
  const view = {
    identity: "a",
    reminders: [{ stream: "b", record: "c", due_at: Date.now() + 60000 }],
  } as View;
  await reconcileReminders(view, true);
  expect(native.invoke).not.toHaveBeenCalled();
  await scheduleReminder("a", "b", "c", view.reminders![0].due_at, true);
  native.invoke.mockClear();
  await reconcileReminders(view, true);
  expect(native.cancel).toHaveBeenCalledTimes(1);
  expect(native.invoke).not.toHaveBeenCalled();
});

it("notification taps match only a registered request and its unlocked profile", async () => {
  await scheduleReminder("owner", "chat", "message", Date.now() + 60000, true);
  const { id } = native.invoke.mock.calls.find(([c]) =>
    c.endsWith("|notify"),
  )![1].options;
  const profile = reminderActionProfile({
    actionId: "tap",
    notification: { id },
  })!;
  expect(profile).toMatch(/^[0-9a-f]{64}$/);
  expect(await reminderProfileMatches(profile, "owner")).toBe(true);
  expect(await reminderProfileMatches(profile, "other")).toBe(false);
  expect(
    reminderActionProfile({ actionId: "dismiss", notification: { id } }),
  ).toBeUndefined();
  expect(
    reminderActionProfile({ actionId: "tap", notification: { id: id + 1 } }),
  ).toBeUndefined();
  expect(reminderActionProfile(null)).toBeUndefined();
  await cancelReminder("owner", "chat", "message", true);
  expect(
    reminderActionProfile({ actionId: "tap", notification: { id } }),
  ).toBeUndefined();
});
it("drains a cold-start tap after listener registration and ignores stale wakeups", async () => {
  await scheduleReminder("owner", "chat", "message", Date.now() + 60000, true);
  const { id } = native.invoke.mock.calls.find(([c]) =>
    c.endsWith("|notify"),
  )![1].options;
  const unregister = vi.fn();
  native.onAction.mockResolvedValue({ unregister });
  let event: unknown = { actionId: "tap", notification: { id } };
  native.invoke.mockImplementation(async (c) => {
    expect(c).toBe("plugin:notification|pending_action");
    expect(native.onAction).toHaveBeenCalledTimes(1);
    const result = event;
    event = null;
    return result;
  });
  const open = vi.fn();
  const stop = await watchReminderActions(open);
  expect(open).toHaveBeenCalledTimes(1);
  native.onAction.mock.calls[0][0]({});
  await vi.waitFor(() =>
    expect(native.invoke).toHaveBeenLastCalledWith(
      "plugin:notification|pending_action",
    ),
  );
  expect(open).toHaveBeenCalledTimes(1);
  stop();
  expect(unregister).toHaveBeenCalledOnce();
});
