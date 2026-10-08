import { expect, it, vi } from "vitest";
import { CallAudioPlayback } from "./audioPlayback";

const blocked = () =>
  Object.assign(new Error("Autoplay denied"), { name: "NotAllowedError" });
const tick = async () => {
  await Promise.resolve();
  await Promise.resolve();
};
function element() {
  const target = new EventTarget();
  return Object.assign(target, {
    play: vi.fn<() => Promise<void>>(),
  }) as unknown as HTMLMediaElement & {
    play: ReturnType<typeof vi.fn<() => Promise<void>>>;
  };
}

it("retries all blocked tracks synchronously from one visible user gesture", async () => {
  const playback = new CallAudioPlayback();
  const a = element(),
    b = element();
  a.play.mockRejectedValueOnce(blocked()).mockResolvedValue(undefined);
  b.play.mockRejectedValueOnce(blocked()).mockResolvedValue(undefined);
  playback.attach(a);
  playback.attach(b);
  await tick();
  expect(playback.getSnapshot()).toBe(true);
  playback.retry();
  expect(a.play).toHaveBeenCalledTimes(2);
  expect(b.play).toHaveBeenCalledTimes(2);
  await tick();
  expect(playback.getSnapshot()).toBe(false);
});

it("ignores late rejection from a detached or replaced track", async () => {
  const playback = new CallAudioPlayback();
  const media = element();
  let reject!: (error: Error) => void;
  media.play
    .mockReturnValueOnce(
      new Promise<void>((_, fail) => {
        reject = fail;
      }),
    )
    .mockResolvedValue(undefined);
  const detach = playback.attach(media);
  detach();
  playback.attach(media);
  reject(blocked());
  await tick();
  expect(playback.getSnapshot()).toBe(false);
});

it("does not offer autoplay recovery for an aborted track replacement", async () => {
  const playback = new CallAudioPlayback();
  const media = element();
  media.play.mockRejectedValue(
    Object.assign(new Error("Detached"), { name: "AbortError" }),
  );
  playback.attach(media);
  await tick();
  expect(playback.getSnapshot()).toBe(false);
});

it("keeps recovery available after another denial and clears it when playback starts", async () => {
  const playback = new CallAudioPlayback();
  const media = element();
  media.play.mockRejectedValue(blocked());
  const detach = playback.attach(media);
  await tick();
  playback.retry();
  await tick();
  expect(playback.getSnapshot()).toBe(true);
  media.dispatchEvent(new Event("playing"));
  expect(playback.getSnapshot()).toBe(false);
  detach();
  expect(playback.getSnapshot()).toBe(false);
});
