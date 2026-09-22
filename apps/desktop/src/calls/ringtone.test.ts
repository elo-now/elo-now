import { afterEach, expect, it, vi } from "vitest";
import { CallRinger, type AudibleRingtone } from "./ringtone";
import {
  defaultPreferences,
  readPreferences,
  savePreferences,
} from "../preferences";

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
});
function setup() {
  vi.useFakeTimers();
  const stopped: ReturnType<typeof vi.fn>[] = [];
  const play = vi.fn((_tone: AudibleRingtone) => {
    const stop = vi.fn();
    stopped.push(stop);
    return stop;
  });
  return { ringer: new CallRinger(play), play, stopped };
}
it("rings once per incoming call and stops immediately on answer, decline, mute or logout", () => {
  const { ringer, play, stopped } = setup();
  ringer.update("first", "classic");
  ringer.update("first", "classic");
  expect(play).toHaveBeenCalledOnce();
  ringer.update(undefined, "classic", true);
  expect(stopped[0]).toHaveBeenCalledOnce();
  ringer.update(undefined, "classic");
  ringer.update("second", "chime");
  ringer.update(undefined, "chime");
  expect(stopped[1]).toHaveBeenCalledOnce();
  ringer.update("third", "pulse");
  ringer.stop();
  expect(stopped[2]).toHaveBeenCalledOnce();
  expect(vi.getTimerCount()).toBe(0);
});
it("replaces a ringing sound without overlap and honors Silent", () => {
  const { ringer, play, stopped } = setup();
  ringer.update("first", "classic");
  ringer.update("first", "pulse");
  expect(stopped[0]).toHaveBeenCalledOnce();
  ringer.update("first", "silent");
  expect(stopped[1]).toHaveBeenCalledOnce();
  ringer.update("second", "silent");
  expect(play).toHaveBeenCalledTimes(2);
  ringer.stop();
});
it("bounds preview duration, cancels it on navigation and prioritizes an incoming call", async () => {
  const { ringer, play, stopped } = setup();
  const ended = vi.fn();
  expect(ringer.preview("chime", ended)).toBe(true);
  await vi.advanceTimersByTimeAsync(3000);
  expect(stopped[0]).toHaveBeenCalledOnce();
  expect(ended).toHaveBeenCalledOnce();
  ringer.preview("pulse", ended);
  ringer.cancelPreview();
  expect(stopped[1]).toHaveBeenCalledOnce();
  ringer.preview("classic", ended);
  ringer.update("incoming", "pulse");
  expect(stopped[2]).toHaveBeenCalledOnce();
  expect(ringer.preview("classic", ended)).toBe(false);
  expect(play).toHaveBeenCalledTimes(4);
  ringer.update(undefined, "classic", true);
  expect(ringer.preview("classic", ended)).toBe(false);
  ringer.stop();
  expect(ringer.preview("silent", ended)).toBe(false);
  expect(vi.getTimerCount()).toBe(0);
});
it("persists ringtone choices and safely defaults missing or unknown values", () => {
  let stored = "{}";
  vi.stubGlobal("localStorage", {
    getItem: () => stored,
    setItem: (_key: string, value: string) => {
      stored = value;
    },
  });
  expect(readPreferences().callRingtone).toBe("classic");
  savePreferences({ ...defaultPreferences, callRingtone: "silent" });
  expect(readPreferences().callRingtone).toBe("silent");
  stored = JSON.stringify({ callRingtone: "remote-file" });
  expect(readPreferences().callRingtone).toBe("classic");
});
