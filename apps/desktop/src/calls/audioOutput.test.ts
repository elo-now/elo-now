import { expect, it, vi } from "vitest";
import { AudioOutputRequests, type AudioOutputs } from "./audioOutput";

const context = {
  identity: "profile",
  sessionId: "call",
  activation: "activation",
};
const receiver: AudioOutputs = {
  selected: "receiver",
  outputs: [{ id: "receiver", kind: "receiver" }],
};
const speaker: AudioOutputs = {
  selected: "speaker",
  outputs: [{ id: "speaker", kind: "speaker" }],
};

it("does not let an old read undo a route choice and binds every request to the active session", async () => {
  let finishRead!: (value: AudioOutputs) => void;
  const request = vi.fn(
    async (args: typeof context & { outputId?: string }) => {
      if (args.outputId) return speaker;
      return new Promise<AudioOutputs>((resolve) => {
        finishRead = resolve;
      });
    },
  );
  const changed = vi.fn();
  const routes = new AudioOutputRequests(context, changed, vi.fn(), request);
  const reading = routes.refresh();
  await routes.select("speaker");
  finishRead(receiver);
  await reading;
  expect(changed).toHaveBeenCalledExactlyOnceWith(speaker);
  expect(request).toHaveBeenLastCalledWith({ ...context, outputId: "speaker" });
});

it("keeps the current output and reports selection failure without ending the session", async () => {
  const request = vi.fn(
    async (args: typeof context & { outputId?: string }) => {
      if (args.outputId) throw new Error("accessory removed");
      return receiver;
    },
  );
  const changed = vi.fn();
  const failed = vi.fn();
  const routes = new AudioOutputRequests(context, changed, failed, request);
  await routes.refresh();
  await routes.select("bluetooth");
  expect(changed).toHaveBeenCalledExactlyOnceWith(receiver);
  expect(failed).toHaveBeenCalledOnce();
  await routes.refresh();
  expect(changed).toHaveBeenCalledTimes(2);
});

it("discards late replies and failures from a session that has ended", async () => {
  let finish!: (value: AudioOutputs) => void;
  const changed = vi.fn();
  const failed = vi.fn();
  const request = vi.fn(
    () =>
      new Promise<AudioOutputs>((resolve) => {
        finish = resolve;
      }),
  );
  const routes = new AudioOutputRequests(context, changed, failed, request);
  const read = routes.refresh();
  routes.dispose();
  finish(receiver);
  await read;
  await routes.select("speaker");
  expect(changed).not.toHaveBeenCalled();
  expect(failed).not.toHaveBeenCalled();
  expect(request).toHaveBeenCalledOnce();
});
