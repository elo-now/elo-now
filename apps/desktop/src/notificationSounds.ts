export const notificationSounds = [
  "default",
  "soft",
  "elo-male",
  "elo-female",
  "none",
] as const;
export type NotificationSound = (typeof notificationSounds)[number];
const preferenceKey = "elo.notification-sound.v1";

export function parseNotificationSound(value: unknown): NotificationSound {
  return notificationSounds.includes(value as NotificationSound)
    ? (value as NotificationSound)
    : "default";
}

export function readNotificationSound(): NotificationSound {
  return parseNotificationSound(localStorage.getItem(preferenceKey));
}

export function saveNotificationSound(value: NotificationSound): void {
  localStorage.setItem(preferenceKey, value);
}

let player: HTMLAudioElement | undefined;
let revision = 0;

export function stopNotificationSound() {
  revision++;
  player?.pause();
  player = undefined;
}

/** Only used while the app is focused, or after explicit selection of a preview.
 * Background notification sound belongs exclusively to the operating system. */
export async function playNotificationSound(
  choice: NotificationSound,
): Promise<void> {
  stopNotificationSound();
  if (choice === "none") return;
  const current = revision;
  const audio = new Audio(`/sounds/${choice}.wav`);
  audio.volume = 0.75;
  player = audio;
  try {
    await audio.play();
  } catch (error) {
    if (current !== revision) return;
    throw error;
  }
}

/** Independent lanes let a session start be heard during a burst of messages. */
export class NotificationSoundGate {
  private last = new Map<string, number>();
  allow(kind: "message" | "session", now: number): boolean {
    const previous = this.last.get(kind);
    if (previous !== undefined && now - previous < 3000) return false;
    this.last.set(kind, now);
    return true;
  }
  reset() {
    this.last.clear();
  }
}
