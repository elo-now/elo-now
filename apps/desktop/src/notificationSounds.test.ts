import { afterEach, describe, expect, it, vi } from "vitest";
import {
  NotificationSoundGate,
  parseNotificationSound,
  playNotificationSound,
  stopNotificationSound,
} from "./notificationSounds";

describe("notification sound policy", () => {
  it("uses a known sound for missing, obsolete or manipulated preferences", () => {
    for (const value of [
      undefined,
      null,
      "../private",
      "https://example.org/a.wav",
      "",
    ])
      expect(parseNotificationSound(value)).toBe("default");
    expect(parseNotificationSound("none")).toBe("none");
    expect(parseNotificationSound("elo-female")).toBe("elo-female");
  });
  it("coalesces message bursts without swallowing session starts", () => {
    const gate = new NotificationSoundGate();
    expect(gate.allow("message", 0)).toBe(true);
    expect(gate.allow("message", 500)).toBe(false);
    expect(gate.allow("session", 500)).toBe(true);
    expect(gate.allow("message", 3000)).toBe(true);
    gate.reset();
    expect(gate.allow("message", 3001)).toBe(true);
  });
});

it("a sustained burst cannot keep postponing the next allowed notification sound", () => {
  const gate = new NotificationSoundGate();
  expect(gate.allow("message", 100)).toBe(true);
  for (let at = 600; at < 3100; at += 500)
    expect(gate.allow("message", at)).toBe(false);
  expect(gate.allow("message", 3100)).toBe(true);
  expect(gate.allow("session", 3100)).toBe(true);
  gate.reset();
  expect(gate.allow("session", 3101)).toBe(true);
  expect(gate.allow("message", 3101)).toBe(true);
});

afterEach(() => {
  stopNotificationSound();
  vi.unstubAllGlobals();
});

it("selecting no sound or locking releases an existing player without allocating another", async () => {
  const pause = vi.fn();
  const construct = vi.fn();
  vi.stubGlobal(
    "Audio",
    class {
      volume = 1;
      pause = pause;
      play = vi.fn(async () => {});
      constructor(source: string) {
        construct(source);
      }
    },
  );
  await playNotificationSound("soft");
  expect(construct).toHaveBeenCalledExactlyOnceWith("/sounds/soft.wav");
  await playNotificationSound("none");
  expect(pause).toHaveBeenCalledOnce();
  expect(construct).toHaveBeenCalledOnce();
  await playNotificationSound("default");
  stopNotificationSound();
  expect(pause).toHaveBeenCalledTimes(2);
});

it("a cancelled player rejection cannot become an error for a newer preview", async () => {
  let rejectFirst!: (error: Error) => void;
  const play = vi
    .fn()
    .mockImplementationOnce(
      () =>
        new Promise<void>((_resolve, reject) => {
          rejectFirst = reject;
        }),
    )
    .mockResolvedValueOnce(undefined)
    .mockRejectedValueOnce(new Error("Current output unavailable"));
  const pause = vi.fn();
  vi.stubGlobal(
    "Audio",
    class {
      volume = 1;
      play = play;
      pause = pause;
    },
  );
  const first = playNotificationSound("soft");
  await playNotificationSound("elo-female");
  rejectFirst(new Error("Superseded output unavailable"));
  await expect(first).resolves.toBeUndefined();
  expect(pause).toHaveBeenCalledOnce();
  await expect(playNotificationSound("elo-male")).rejects.toThrow(
    "Current output unavailable",
  );
});
