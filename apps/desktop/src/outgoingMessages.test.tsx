import { expect, test } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import {
  OutgoingMessages,
  withOutgoingMessages,
  type SendReceipt,
} from "./outgoingMessages";
import { MessageContent } from "./MessageContent";
import { findThread } from "./messageThreads";
import type { Stream, View } from "./model";

const draft = {
  scope: "profile/space/chat",
  identity: "me",
  credential: "device",
  text: "Hello",
  createdAt: "2026-09-25T12:00:00Z",
  logicalTime: 10,
};
const deferred = () => {
  let resolve!: (receipt: SendReceipt) => void;
  let reject!: (error: Error) => void;
  const promise = new Promise<SendReceipt>((yes, no) => {
    resolve = yes;
    reject = no;
  });
  return { promise, resolve, reject };
};

test("text appears before the native write completes and survives a delayed history refresh", async () => {
  const store = new OutgoingMessages();
  const write = deferred();
  const send = store.send(draft, () => write.promise);
  const rows = () => withOutgoingMessages([], store.snapshot(), draft.scope);
  expect(rows()[0].body.payload?.text).toBe("Hello");
  expect(rows()[0].local_echo).toBe("saving");
  expect(rows()[0].state).not.toBe("QUEUED");
  write.resolve({ id: "signed-message", logical_time: 25 });
  await send;
  expect(rows()[0]).toMatchObject({
    id: "signed-message",
    local_echo: "saved",
    body: { logical_time: 25 },
  });
  const canonical = { ...rows()[0], local_echo: undefined, state: "QUEUED" };
  expect(
    withOutgoingMessages([canonical], store.snapshot(), draft.scope),
  ).toEqual([canonical]);
  store.observe(draft.scope, [canonical]);
  expect(store.snapshot()).toEqual([]);
});

test("a failed write removes its echo and propagates the failure for draft restoration", async () => {
  const store = new OutgoingMessages();
  const write = deferred();
  const send = store.send(draft, () => write.promise);
  expect(store.snapshot()).toHaveLength(1);
  write.reject(new Error("Storage full"));
  await expect(send).rejects.toThrow("Storage full");
  expect(store.snapshot()).toEqual([]);
});

test("identical messages reconcile only by the record ID returned by the core", async () => {
  const store = new OutgoingMessages();
  await store.send(draft, async () => ({ id: "first", logical_time: 10 }));
  await store.send(draft, async () => ({ id: "second", logical_time: 11 }));
  const first = { ...store.snapshot()[0].row, local_echo: undefined };
  const rows = withOutgoingMessages([first], store.snapshot(), draft.scope);
  expect(rows.map((row) => row.id)).toEqual(["first", "second"]);
  store.observe("different-scope", [first]);
  expect(store.snapshot()).toHaveLength(2);
  store.observe(draft.scope, [first]);
  expect(store.snapshot().map((echo) => echo.row.id)).toEqual(["second"]);
});

test("echoes cannot enter another conversation or resurrect deleted content", async () => {
  const store = new OutgoingMessages();
  await store.send(draft, async () => ({ id: "first", logical_time: 10 }));
  expect(
    withOutgoingMessages([], store.snapshot(), "another-profile/space/chat"),
  ).toEqual([]);
  const deleted = {
    id: "tombstone",
    state: "STORED",
    body: {
      kind: "deleted",
      issuer_identity: "me",
      deleted_record_id: "first",
    },
  };
  expect(
    withOutgoingMessages([deleted], store.snapshot(), draft.scope),
  ).toEqual([deleted]);
  store.observe(draft.scope, [deleted]);
  expect(store.snapshot()).toEqual([]);
});

test("replies appear in their own thread immediately", async () => {
  const store = new OutgoingMessages();
  const write = deferred();
  const send = store.send({ ...draft, thread: "root" }, () => write.promise);
  const root = {
    id: "root",
    state: "STORED",
    body: {
      kind: "chat.message",
      issuer_identity: "me",
      payload: { text: "Root" },
    },
  };
  const rows = withOutgoingMessages([root], store.snapshot(), draft.scope);
  expect(findThread(rows, "root").replies[0].body.payload?.text).toBe("Hello");
  expect(findThread(rows, "another-root").replies).toEqual([]);
  write.resolve({ id: "reply", logical_time: 11 });
  await send;
});

test("pending messages have a noninteractive status and no record actions", () => {
  const html = renderToStaticMarkup(
    <MessageContent
      view={{ identity: "me", name: "Me" } as View}
      chat={{ rows: [], members: [] } as unknown as Stream}
      row={{
        id: "transient",
        state: "SENDING",
        local_echo: "saving",
        body: {
          kind: "chat.message",
          issuer_identity: "me",
          payload: { text: "Hello" },
        },
      }}
      hideAvatars
      onStatus={() => {}}
    >
      <p>Hello</p>
    </MessageContent>,
  );
  expect(html).toContain('aria-label="Sending…"');
  expect(html).not.toContain("<button");
  expect(html).not.toContain("Synced");
});
