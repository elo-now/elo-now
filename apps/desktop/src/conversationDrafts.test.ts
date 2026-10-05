import { expect, test, vi } from "vitest";
import {
  ConversationDrafts,
  flushConversationDrafts,
  type Draft,
  type DraftPersistence,
  type DraftScope,
} from "./conversationDrafts";
const scope: DraftScope = {
  identity: "alice",
  credential: "device-one",
  active_space: "space-a",
  space: "signed-space-a",
  stream: "general",
  thread: null,
};
const initial: Draft = {
  text: "",
  expiry: undefined,
  mentions: [],
  attachment: null,
};
function persistent() {
  const disk = new Map<string, Draft>();
  const adapter: DraftPersistence = {
    async load(scope) {
      return {
        session: "session",
        draft: structuredClone(disk.get(JSON.stringify(scope)) ?? initial),
      };
    },
    async save(scope, _session, value) {
      disk.set(JSON.stringify(scope), structuredClone(value));
    },
  };
  return { disk, adapter };
}
async function open(store: ConversationDrafts, key = "chat", context = scope) {
  store.reset("profile");
  store.open("profile", key, context);
  await Promise.resolve();
  await Promise.resolve();
}
test("text, expiry, mention spans and attachment survive lock and a new store without plaintext browser storage", async () => {
  const { adapter } = persistent();
  const discard = vi.fn();
  const first = new ConversationDrafts(discard, adapter);
  await open(first);
  first.setContent("profile", "chat", "Hello @Alice", [
    { identity_id: "alice", label: "Alice", start: 6, end: 12 },
  ]);
  first.update("profile", "chat", "expiry", 24);
  const attachment = {
    path: "native-handle",
    name: "photo.png",
    size_bytes: 12,
  };
  first.update("profile", "chat", "attachment", attachment);
  await flushConversationDrafts();
  first.reset();
  expect(first.read("profile", "chat")).toEqual(initial);
  const second = new ConversationDrafts(vi.fn(), adapter);
  await open(second);
  expect(second.read("profile", "chat")).toEqual({
    text: "Hello @Alice",
    expiry: 24,
    mentions: [{ identity_id: "alice", label: "Alice", start: 6, end: 12 }],
    attachment,
  });
  await Promise.resolve();
  expect(discard).toHaveBeenCalledExactlyOnceWith(attachment);
});
test("draft keys isolate device, Space, conversation and thread", async () => {
  const { adapter } = persistent();
  const first = new ConversationDrafts(vi.fn(), adapter);
  await open(first);
  first.update("profile", "chat", "text", "Only this chat");
  await flushConversationDrafts();
  const contexts = [
    { ...scope, credential: "device-two" },
    { ...scope, active_space: "space-b" },
    { ...scope, stream: "other" },
    { ...scope, thread: "reply-root" },
  ];
  for (const context of contexts) {
    const store = new ConversationDrafts(vi.fn(), adapter);
    await open(store, "chat", context);
    expect(store.read("profile", "chat").text).toBe("");
  }
});
test("a late load after profile lock cannot restore plaintext or cross into another profile", async () => {
  let finish!: (value: { session: string; draft: Draft }) => void;
  const discard = vi.fn();
  const adapter: DraftPersistence = {
    load: () => new Promise((resolve) => (finish = resolve)),
    save: vi.fn(),
  };
  const store = new ConversationDrafts(discard, adapter);
  store.reset("profile");
  store.open("profile", "chat", scope);
  store.reset("other");
  const attachment = { path: "late-handle", name: "late.jpg", size_bytes: 1 };
  finish({
    session: "old-session",
    draft: { ...initial, text: "Secret", attachment },
  });
  await Promise.resolve();
  expect(store.read("other", "chat")).toEqual(initial);
  expect(discard).toHaveBeenCalledExactlyOnceWith(attachment);
  store.update("profile", "chat", "text", "Late failure");
  expect(store.read("other", "chat")).toEqual(initial);
});
test("a late hydration does not overwrite typing and queued writes keep the final text", async () => {
  let finish!: (value: { session: string; draft: Draft }) => void;
  const saves: Draft[] = [];
  const adapter: DraftPersistence = {
    load: () => new Promise((resolve) => (finish = resolve)),
    async save(_scope, _session, draft) {
      saves.push(structuredClone(draft));
    },
  };
  const store = new ConversationDrafts(vi.fn(), adapter);
  store.reset("profile");
  store.open("profile", "chat", scope);
  store.update("profile", "chat", "text", "New input");
  finish({
    session: "session",
    draft: { ...initial, text: "Old disk text", expiry: 1 },
  });
  await flushConversationDrafts();
  expect(store.read("profile", "chat")).toMatchObject({
    text: "New input",
    expiry: 1,
  });
  expect(saves.at(-1)?.text).toBe("New input");
});
test("failed send preserves the draft; successful send clears it without a stale write resurrecting it", async () => {
  const { adapter, disk } = persistent();
  const store = new ConversationDrafts(vi.fn(), adapter);
  await open(store);
  store.update("profile", "chat", "text", "Unsent draft");
  const submitted = store.read("profile", "chat");
  await flushConversationDrafts();
  expect(disk.get(JSON.stringify(scope))?.text).toBe("Unsent draft");
  store.clearSubmitted("profile", "chat", submitted);
  await flushConversationDrafts();
  expect(disk.get(JSON.stringify(scope))?.text).toBe("");
  store.update("profile", "chat", "text", "A newer draft");
  store.clearSubmitted("profile", "chat", submitted);
  await flushConversationDrafts();
  expect(disk.get(JSON.stringify(scope))?.text).toBe("A newer draft");
});
test("staged attachment cleanup waits until its encrypted replacement is saved", async () => {
  const { adapter } = persistent();
  const discard = vi.fn();
  let finish!: () => void;
  const store = new ConversationDrafts(discard, adapter);
  await open(store);
  const attachment = { path: "file", name: "file.jpg", size_bytes: 1 };
  store.update("profile", "chat", "attachment", attachment);
  await flushConversationDrafts();
  adapter.save = () => new Promise<void>((resolve) => (finish = resolve));
  store.update("profile", "chat", "attachment", null);
  await Promise.resolve();
  await Promise.resolve();
  expect(discard).not.toHaveBeenCalled();
  finish();
  await flushConversationDrafts();
  await Promise.resolve();
  expect(discard).toHaveBeenCalledExactlyOnceWith(attachment);
});

test("burst typing keeps one in-flight save and only the latest pending revision", async () => {
  const { adapter } = persistent();
  const snapshots: string[] = [];
  let release!: () => void;
  adapter.save = async (_scope, _session, draft) => {
    snapshots.push(draft.text);
    if (snapshots.length === 1)
      await new Promise<void>((resolve) => (release = resolve));
  };
  const store = new ConversationDrafts(vi.fn(), adapter);
  await open(store);
  store.update("profile", "chat", "text", "First");
  await vi.waitFor(() => expect(snapshots).toEqual(["First"]));
  for (let index = 0; index < 300; index++)
    store.update("profile", "chat", "text", `Final ${index}`);
  expect(snapshots).toEqual(["First"]);
  release();
  await flushConversationDrafts();
  expect(snapshots).toEqual(["First", "Final 299"]);
});
test("failed persistence retains staged bytes and prevents a silent successful flush", async () => {
  const { adapter } = persistent();
  const discard = vi.fn();
  const error = new Error("Disk full");
  const report = vi.fn();
  const store = new ConversationDrafts(discard, adapter, report);
  await open(store);
  store.update("profile", "chat", "attachment", {
    path: "file",
    name: "notes.txt",
    size_bytes: 1,
  });
  await flushConversationDrafts();
  adapter.save = async () => {
    throw error;
  };
  store.update("profile", "chat", "attachment", null);
  await expect(flushConversationDrafts()).rejects.toThrow("Disk full");
  expect(discard).not.toHaveBeenCalled();
  expect(report).toHaveBeenCalledWith(error);
  adapter.save = async () => {};
  store.update("profile", "chat", "text", "Retry");
  await flushConversationDrafts();
  store.reset();
});

test("a transient load failure can retry in the same chat and keeps text typed before recovery", async () => {
  const { adapter, disk } = persistent();
  disk.set(JSON.stringify(scope), {
    ...initial,
    text: "Saved text",
    expiry: 24,
  });
  const originalLoad = adapter.load;
  adapter.load = vi
    .fn()
    .mockRejectedValueOnce(new Error("Temporary local failure"))
    .mockImplementation(originalLoad);
  const report = vi.fn();
  const store = new ConversationDrafts(vi.fn(), adapter, report);
  await open(store);
  await vi.waitFor(() => expect(report).toHaveBeenCalledTimes(1));
  expect(store.ready("profile", "chat")).toBe(false);
  store.update("profile", "chat", "text", "Typed before recovery");
  await flushConversationDrafts();
  expect(store.ready("profile", "chat")).toBe(true);
  expect(store.read("profile", "chat")).toMatchObject({
    text: "Typed before recovery",
    expiry: 24,
  });
  expect(disk.get(JSON.stringify(scope))?.text).toBe("Typed before recovery");
  store.reset();
});
test("reopening or foreground retry recovers a failed read without switching profiles", async () => {
  const { adapter } = persistent();
  const load = adapter.load;
  adapter.load = vi
    .fn()
    .mockRejectedValueOnce(new Error("Temporary local failure"))
    .mockImplementation(load);
  const store = new ConversationDrafts(vi.fn(), adapter);
  await open(store);
  await vi.waitFor(() => expect(adapter.load).toHaveBeenCalledTimes(1));
  await Promise.resolve();
  await Promise.resolve();
  store.open("profile", "chat", scope);
  await vi.waitFor(() => expect(store.ready("profile", "chat")).toBe(true));
  expect(adapter.load).toHaveBeenCalledTimes(2);
  store.reset();
});
test("unreadable encrypted data is not overwritten and typed text is retained after failed recovery", async () => {
  const error = new Error("Invalid conversation draft scope.");
  const save = vi.fn();
  const report = vi.fn();
  const adapter: DraftPersistence = {
    load: async () => {
      throw error;
    },
    save,
  };
  const store = new ConversationDrafts(vi.fn(), adapter, report);
  await open(store);
  store.update("profile", "chat", "text", "Keep my new typing");
  await expect(flushConversationDrafts()).rejects.toThrow(error.message);
  expect(save).not.toHaveBeenCalled();
  expect(store.read("profile", "chat").text).toBe("Keep my new typing");
  expect(store.ready("profile", "chat")).toBe(false);
  expect(report).toHaveBeenCalledTimes(1);
  store.reset();
});
test("Log out flush retries a transient failed write without requiring another edit", async () => {
  const { adapter, disk } = persistent();
  const save = adapter.save;
  adapter.save = vi
    .fn()
    .mockRejectedValueOnce(new Error("Temporary write failure"))
    .mockImplementation(save);
  const report = vi.fn();
  const store = new ConversationDrafts(vi.fn(), adapter, report);
  await open(store);
  store.update("profile", "chat", "text", "Save before locking");
  await flushConversationDrafts();
  expect(adapter.save).toHaveBeenCalledTimes(2);
  expect(disk.get(JSON.stringify(scope))?.text).toBe("Save before locking");
  store.reset();
});
test("a stale saved attachment capability is restored from ciphertext without rolling back current text", async () => {
  const attachment = {
    path: "old-capability",
    name: "image.jpg",
    size_bytes: 4,
  };
  const restored = { ...attachment, path: "restored-capability" };
  let loadCount = 0;
  const saves: Draft[] = [];
  const adapter: DraftPersistence = {
    async load() {
      return {
        session: "session",
        draft: {
          ...initial,
          text: "Old caption",
          attachment: ++loadCount === 1 ? attachment : restored,
        },
      };
    },
    async save(_scope, _session, draft) {
      if (draft.attachment?.path === "old-capability")
        throw new Error("Invalid exchange handle");
      saves.push(structuredClone(draft));
    },
  };
  const discard = vi.fn();
  const store = new ConversationDrafts(discard, adapter);
  await open(store);
  store.update("profile", "chat", "text", "Current caption");
  await flushConversationDrafts();
  expect(store.read("profile", "chat")).toMatchObject({
    text: "Current caption",
    attachment: restored,
  });
  expect(saves.at(-1)?.text).toBe("Current caption");
  expect(discard).toHaveBeenCalledWith(attachment);
  store.reset();
});
test("an unsaved attachment is never replaced with a different old attachment during recovery", async () => {
  const old = { path: "old", name: "image.jpg", size_bytes: 4 };
  const selected = { path: "new", name: "image.jpg", size_bytes: 4 };
  const adapter: DraftPersistence = {
    load: vi.fn(async () => ({
      session: "session",
      draft: { ...initial, attachment: old },
    })),
    async save(_scope, _session, draft) {
      if (draft.attachment) throw new Error("Invalid exchange handle");
    },
  };
  const store = new ConversationDrafts(vi.fn(), adapter);
  await open(store);
  store.update("profile", "chat", "attachment", selected);
  await expect(flushConversationDrafts()).rejects.toThrow(
    "Invalid exchange handle",
  );
  expect(adapter.load).toHaveBeenCalledTimes(1);
  expect(store.read("profile", "chat").attachment).toEqual(selected);
  store.update("profile", "chat", "attachment", null);
  await flushConversationDrafts();
  store.reset();
});

test("removing a stale attachment during an in-flight save commits the newer draft", async () => {
  const { adapter, disk } = persistent();
  const save = adapter.save;
  let reject!: (error: Error) => void;
  let started = false;
  adapter.save = async (scope, session, draft) => {
    if (draft.attachment) {
      started = true;
      await new Promise<void>((_resolve, no) => (reject = no));
    }
    await save(scope, session, draft);
  };
  const report = vi.fn();
  const store = new ConversationDrafts(vi.fn(), adapter, report);
  await open(store);
  store.update("profile", "chat", "attachment", {
    path: "stale",
    name: "image.jpg",
    size_bytes: 4,
  });
  await vi.waitFor(() => expect(started).toBe(true));
  store.update("profile", "chat", "attachment", null);
  reject(new Error("Invalid exchange handle"));
  await flushConversationDrafts();
  expect(disk.get(JSON.stringify(scope))?.attachment).toBeNull();
  expect(report).not.toHaveBeenCalled();
  store.reset();
});
test("attachment recovery completing after lock cannot leak into a new profile", async () => {
  const attachment = { path: "old", name: "image.jpg", size_bytes: 4 };
  let finish!: (value: { session: string; draft: Draft }) => void;
  let recovering = false;
  let loads = 0;
  const adapter: DraftPersistence = {
    load: async () => {
      if (++loads === 1)
        return { session: "session", draft: { ...initial, attachment } };
      recovering = true;
      return await new Promise((resolve) => (finish = resolve));
    },
    save: async () => {
      throw new Error("Invalid exchange handle");
    },
  };
  const discard = vi.fn();
  const store = new ConversationDrafts(discard, adapter);
  await open(store);
  store.update("profile", "chat", "text", "Private caption");
  await vi.waitFor(() => expect(recovering).toBe(true));
  store.reset("other");
  const restored = { ...attachment, path: "late-restored" };
  finish({ session: "session", draft: { ...initial, attachment: restored } });
  await flushConversationDrafts();
  expect(store.read("other", "chat")).toEqual(initial);
  expect(discard).toHaveBeenCalledWith(restored);
  store.reset();
});
