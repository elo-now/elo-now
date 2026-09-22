import { afterEach, expect, it, vi } from "vitest";
import type { View, Stream } from "../model";
import type { ActiveCall } from "./types";

const media = vi.hoisted(() => ({
  instances: [] as {
    resolve: () => void;
    reject: (e: Error) => void;
    stop: ReturnType<typeof vi.fn>;
    update: ReturnType<typeof vi.fn>;
  }[],
}));
vi.mock("./livekit", () => ({
  GroupMedia: class {
    resolve!: () => void;
    reject!: (e: Error) => void;
    stop = vi.fn(async () => {});
    update = vi.fn(async () => {});
    connect = vi.fn(
      () =>
        new Promise<void>((resolve, reject) => {
          this.resolve = resolve;
          this.reject = reject;
        }),
    );
    constructor() {
      media.instances.push(this);
    }
  },
}));
vi.mock("./control", () => ({
  operate: async () => ({ ciphertext: "sealed" }),
  requestContext: () => ({}),
  Control: class {},
}));
import { Calls } from "./controller";

const chat = {
  space_context: "host",
  space: "space",
  stream: "chat",
  head: "head",
  can_post: true,
  members: [
    { identity_id: "me", credential_ids: ["aaa"], capabilities: ["POST"] },
    { identity_id: "peer", credential_ids: ["bbb"], capabilities: ["POST"] },
  ],
} as unknown as Stream;
const call = (epoch: number): ActiveCall => ({
  call_id: "call",
  scope: {
    hosting_space_id: "host",
    conversation: { space_id: "space", stream_id: "chat" },
  },
  config_id: "head",
  key_epoch: epoch,
  kind: "group",
  initial_media: "video",
  ringing: false,
  started_by: "me",
  started_at: 1,
  participants: {
    me: {
      identity_id: "me",
      credential_id: "aaa",
      media: {
        audio_muted: false,
        video_published: true,
        screen_published: false,
      },
    },
    peer: {
      identity_id: "peer",
      credential_id: "bbb",
      media: {
        audio_muted: false,
        video_published: true,
        screen_published: false,
      },
    },
  },
});
function setup() {
  const calls = new Calls();
  const view = {
    identity: "me",
    credential: "aaa",
    streams: [chat],
    spaces: [{ id: "host", managed: true, status: "joined" }],
  } as unknown as View;
  Object.assign(calls, {
    view,
    capture: { getTracks: () => [] },
    command: async () => ({
      media: { epoch: calls.snapshot.active?.key_epoch },
    }),
  });
  calls.snapshot = { ...calls.snapshot, active: call(1), chat };
  const events = calls as unknown as {
    event(e: { type: string; call: ActiveCall }): Promise<void>;
  };
  return {
    calls,
    presence: (epoch: number) =>
      events.event({ type: "presence", call: call(epoch) }),
  };
}
afterEach(() => {
  media.instances = [];
  vi.useRealTimers();
});

it("processes a new membership epoch while the previous media handshake is pending", async () => {
  const { calls, presence } = setup();
  await presence(1);
  await vi.waitFor(() => expect(media.instances).toHaveLength(1));
  await presence(2);
  await vi.waitFor(() => expect(media.instances).toHaveLength(2));
  expect(media.instances[0].stop).toHaveBeenCalled();
  media.instances[0].reject(new Error("obsolete room removed"));
  media.instances[1].resolve();
  await vi.waitFor(() => expect(calls.snapshot.phase).toBe("connected"));
  expect(calls.snapshot.active?.key_epoch).toBe(2);
  expect(calls.snapshot.error).toBeUndefined();
  expect(media.instances[0].update).not.toHaveBeenCalled();
  calls.dispose();
});

it("does not resurrect a call when an obsolete connection succeeds after logout", async () => {
  const { calls, presence } = setup();
  await presence(1);
  await vi.waitFor(() => expect(media.instances).toHaveLength(1));
  calls.dispose();
  media.instances[0].resolve();
  await vi.waitFor(() => expect(media.instances[0].stop).toHaveBeenCalled());
  expect(calls.snapshot.phase).toBe("idle");
  expect(calls.snapshot.active).toBeUndefined();
  expect(media.instances[0].update).not.toHaveBeenCalled();
});

it("republishes the existing screen after a group membership rekey", async () => {
  const { calls, presence } = setup();
  const screen = { getTracks: () => [] } as unknown as MediaStream;
  Object.assign(calls, { screen });
  calls.snapshot.media.screen_published = true;
  await presence(1);
  await vi.waitFor(() => expect(media.instances).toHaveLength(1));
  media.instances[0].resolve();
  await vi.waitFor(() => expect(media.instances[0].update).toHaveBeenCalled());
  expect(media.instances[0].update.mock.calls[0][2]).toBe(screen);
  await presence(2);
  await vi.waitFor(() => expect(media.instances).toHaveLength(2));
  media.instances[1].resolve();
  await vi.waitFor(() => expect(media.instances[1].update).toHaveBeenCalled());
  expect(media.instances[1].update.mock.calls[0][2]).toBe(screen);
  calls.dispose();
});

it("reauthorizes and reconnects media after a control outage without restarting capture", async () => {
  const { calls, presence } = setup();
  await presence(1);
  await vi.waitFor(() => expect(media.instances).toHaveLength(1));
  media.instances[0].resolve();
  await vi.waitFor(() => expect(calls.snapshot.phase).toBe("connected"));
  const capture = calls.localCapture();
  const command = vi.fn(async (_chat: Stream, operation: { type: string }) =>
    operation.type === "heartbeat"
      ? { call: call(1) }
      : { media: { epoch: 1 } },
  );
  Object.assign(calls, { command });
  vi.useFakeTimers();
  (calls as unknown as { beginReconnect(): void }).beginReconnect();
  expect(calls.snapshot.phase).toBe("reconnecting");
  await vi.advanceTimersByTimeAsync(1500);
  expect(command.mock.calls[0][1].type).toBe("heartbeat");
  expect(media.instances).toHaveLength(2);
  expect(media.instances[0].stop).toHaveBeenCalled();
  media.instances[1].resolve();
  await vi.advanceTimersByTimeAsync(1);
  expect(calls.snapshot.phase).toBe("connected");
  expect(calls.localCapture()).toBe(capture);
  await vi.advanceTimersByTimeAsync(26000);
  expect(calls.snapshot.error).toBeUndefined();
  expect(calls.snapshot.active).toBeDefined();
  calls.dispose();
});
