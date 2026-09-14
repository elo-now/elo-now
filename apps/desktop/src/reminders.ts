import { invoke } from "@tauri-apps/api/core";
import {
  cancel,
  pending,
  active,
  removeActive,
  Schedule,
  onAction,
} from "@tauri-apps/plugin-notification";
import { t } from "./i18n";
import type { View } from "./model";

// Only opaque OS identifiers and hashed lookup keys live here. Message text,
// author, chat name and profile identifiers remain in encrypted storage.
const storageKey = "elo.reminder-notifications.v1";
// Android's getActive returns { values: [...] }; iOS returns the bare array.
// The plugin's TypeScript declaration currently only describes the latter.
function activeItems(value: unknown): { id: number }[] {
  const list = Array.isArray(value)
    ? value
    : (value as { values?: unknown } | null)?.values;
  const items = Array.isArray(list)
    ? list.map((item) => item?.nameValuePairs ?? item)
    : list;
  if (
    !Array.isArray(items) ||
    items.some((item) => !Number.isInteger(item?.id))
  )
    throw new Error("Invalid active notification list.");
  return items;
}
type Registry = Record<string, Record<string, { id: number; due: number }>>;
const registry = (): Registry => {
  try {
    return JSON.parse(localStorage.getItem(storageKey) ?? "{}");
  } catch {
    return {};
  }
};
async function hash(value: string) {
  return [
    ...new Uint8Array(
      await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value)),
    ),
  ]
    .map((n) => n.toString(16).padStart(2, "0"))
    .join("");
}
const keys = async (identity: string, stream: string, record: string) =>
  [
    await hash(identity),
    await hash(`${identity}:${stream}:${record}`),
  ] as const;
let queue = Promise.resolve<unknown>(undefined);
function serialize<T>(work: () => Promise<T>): Promise<T> {
  const result = queue.then(work, work);
  queue = result.catch(() => {});
  return result;
}

export function scheduleReminder(
  identity: string,
  stream: string,
  record: string,
  due: number,
  mobile: boolean,
  ask = true,
): Promise<boolean> {
  return serialize(async () => {
    if (!mobile) return false;
    let permission = await invoke<boolean | null>(
      "plugin:notification|is_permission_granted",
    );
    if (!permission && ask)
      permission =
        (await invoke<string>("plugin:notification|request_permission")) ===
        "granted";
    if (!permission) return false;
    const [profile, key] = await keys(identity, stream, record);
    const saved = registry();
    const current = saved[profile]?.[key];
    const scheduled = await pending();
    if (
      current?.due === due &&
      scheduled.some((item) => item.id === current.id)
    )
      return true;
    // Android's plugin does not list individually scheduled alarms in pending().
    // Count our persisted future requests too, across all local profiles.
    const future = new Set(scheduled.map((item) => item.id));
    Object.values(saved).forEach((profile) =>
      Object.values(profile).forEach((item) => {
        if (item.due > Date.now()) future.add(item.id);
      }),
    );
    if (future.size >= 60 && (!current || !future.has(current.id)))
      return false;
    const taken = new Set(
      [...scheduled, ...activeItems(await active())].map((item) => item.id),
    );
    Object.values(saved).forEach((profile) =>
      Object.values(profile).forEach((item) => taken.add(item.id)),
    );
    let id = current?.id;
    if (id === undefined) {
      do {
        id = crypto.getRandomValues(new Uint32Array(1))[0] & 0x7fffffff;
      } while (!id || taken.has(id));
    }
    if (current) {
      await cancel([id]);
      await removeActive([{ id }]);
    }
    saved[profile] ??= {};
    saved[profile][key] = { id, due };
    localStorage.setItem(storageKey, JSON.stringify(saved));
    // Await the native acknowledgement; sendNotification() returns void.
    await invoke("plugin:notification|notify", {
      options: {
        id,
        title: "elo.now",
        body: t("reminders.notification"),
        schedule: Schedule.at(new Date(due)),
        autoCancel: true,
        extra: { eloReminderProfile: profile },
      },
    });
    return true;
  });
}
export function cancelReminder(
  identity: string,
  stream: string,
  record: string,
  mobile: boolean,
): Promise<void> {
  return serialize(async () => {
    if (!mobile) return;
    const [profile, key] = await keys(identity, stream, record);
    const saved = registry();
    const item = saved[profile]?.[key];
    if (!item) return;
    await cancel([item.id]);
    await removeActive([{ id: item.id }]);
    delete saved[profile][key];
    localStorage.setItem(storageKey, JSON.stringify(saved));
  });
}
/** Reconcile after unlock/restart without asking for notification permission. */
export async function reconcileReminders(view: View, mobile: boolean) {
  if (!mobile) return;
  const reminders = (view.all_reminders ?? view.reminders ?? []).filter(
    (reminder) => reminder.system_notification,
  );
  const profile = await hash(view.identity);
  const wanted = new Set(
    await Promise.all(
      reminders.map((r) => hash(`${view.identity}:${r.stream}:${r.record}`)),
    ),
  );
  await serialize(async () => {
    const saved = registry();
    for (const [key, value] of Object.entries(saved[profile] ?? {})) {
      if (wanted.has(key)) continue;
      await cancel([value.id]);
      await removeActive([{ id: value.id }]);
      delete saved[profile][key];
    }
    localStorage.setItem(storageKey, JSON.stringify(saved));
  });
  for (const reminder of reminders) {
    if (reminder.due_at > Date.now())
      await scheduleReminder(
        view.identity,
        reminder.stream,
        reminder.record,
        reminder.due_at,
        mobile,
        false,
      );
  }
}

/** Local profile deletion must not leave its scheduled notifications behind. */
export function cancelProfileReminders(
  identity: string,
  mobile: boolean,
): Promise<void> {
  return serialize(async () => {
    const profile = await hash(identity);
    const saved = registry();
    const ids = Object.values(saved[profile] ?? {}).map((value) => value.id);
    if (mobile && ids.length) {
      await cancel(ids);
      await removeActive(ids.map((id) => ({ id })));
    }
    delete saved[profile];
    localStorage.setItem(storageKey, JSON.stringify(saved));
  });
}

/** OS taps identify only our opaque request. Never open another profile implicitly. */
export function reminderActionProfile(value: unknown): string | undefined {
  const event = value as {
    actionId?: unknown;
    notification?: { id?: unknown };
  } | null;
  if (event?.actionId !== "tap" || !Number.isInteger(event.notification?.id))
    return;
  const id = event.notification!.id;
  return Object.entries(registry()).find(
    ([profile, items]) =>
      /^[0-9a-f]{64}$/.test(profile) &&
      Object.values(items).some((item) => item.id === id),
  )?.[0];
}
export async function reminderProfileMatches(
  profile: string,
  identity: string,
) {
  return profile === (await hash(identity));
}

/** Drain a native one-item handoff after subscribing, including a cold-start tap. */
export async function watchReminderActions(open: (profile: string) => void) {
  let alive = true;
  const drain = async () => {
    const event = await invoke<unknown>("plugin:notification|pending_action");
    const profile = reminderActionProfile(event);
    if (alive && profile) open(profile);
  };
  const listener = await onAction(() => {
    void drain().catch(() => {});
  });
  try {
    await drain();
  } catch (error) {
    alive = false;
    await listener.unregister();
    throw error;
  }
  return () => {
    alive = false;
    void listener.unregister();
  };
}
