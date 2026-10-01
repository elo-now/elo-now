import { expect, test, vi } from "vitest";
import { MessageEntrance } from "./messageEntrance";
import type { MessageRow } from "./messageThreads";

const opened = Date.parse("2026-10-01T12:00:00Z");
const scope = "profile/device/space/chat";
const row = (id: string, time = opened + 1_000): MessageRow => ({
  id,
  state: "ACCEPTED",
  body: {
    kind: "chat.message",
    issuer_identity: "other",
    created_at: new Date(time).toISOString(),
    payload: { text: id },
  },
});
const echo = (id: string): MessageRow => ({ ...row(id), local_echo: "saving" });

test("initial history and later pages never animate just because their IDs are new", () => {
  const motion = new MessageEntrance();
  motion.receive(scope, [row("initial")], ["initial"], opened);
  expect(
    motion.observe(scope, [row("initial"), echo("pending")], true, opened),
  ).toEqual([]);
  expect(
    motion.observe(
      scope,
      [row("older"), row("initial"), echo("pending"), row("synced")],
      true,
      opened + 2_000,
    ),
  ).toEqual([]);
});

test("a new local echo enters once without waiting for its durable receipt", () => {
  const motion = new MessageEntrance();
  motion.observe(scope, [], true, opened);
  expect(motion.observe(scope, [echo("draft")], true, opened + 1)).toEqual([
    "draft",
  ]);
  expect(motion.observe(scope, [echo("draft")], true, opened + 2)).toEqual([]);
  const saved = { ...row("record"), local_echo: "saved" as const };
  expect(motion.observe(scope, [saved], true, opened + 3)).toEqual([]);
  expect(
    motion.observe(
      scope,
      [{ ...saved, local_echo: undefined, state: "QUEUED" }],
      true,
      opened + 4,
    ),
  ).toEqual([]);
});

test("verified live IDs can wait for a page, without animating neighboring history", () => {
  const motion = new MessageEntrance();
  motion.observe(scope, [row("existing")], true, opened);
  motion.receive(
    scope,
    [row("first"), row("second"), row("history")],
    ["first", "second"],
    opened + 2_000,
  );
  expect(
    motion.observe(scope, [row("existing")], true, opened + 2_001),
  ).toEqual([]);
  expect(
    motion.observe(
      scope,
      [row("history"), row("existing"), row("first"), row("second")],
      true,
      opened + 2_100,
    ),
  ).toEqual(["first", "second"]);
});

test("duplicate receive signals, edits, read status and virtualization cannot replay an arrival", () => {
  const motion = new MessageEntrance();
  motion.observe(scope, [], true, opened);
  motion.receive(scope, [row("live")], ["live"], opened + 2_000);
  expect(motion.observe(scope, [row("live")], true, opened + 2_001)).toEqual([
    "live",
  ]);
  motion.observe(scope, [], true, opened + 2_002);
  motion.receive(scope, [row("live")], ["live"], opened + 2_003);
  const edited = row("live");
  edited.body.payload!.text = "Edited text";
  edited.unread = false;
  edited.reactions = [{ emoji: "👍", count: 1, mine: true, people: ["me"] }];
  expect(motion.observe(scope, [edited], true, opened + 2_004)).toEqual([]);
});

test.each([
  "other-profile",
  "other-device",
  "other-space",
  "other-chat",
  "thread",
  "search",
  "blocked",
])(
  "a scope change (%s) starts from a silent baseline and discards delayed arrivals",
  (next) => {
    const motion = new MessageEntrance();
    motion.observe(scope, [], true, opened);
    motion.receive(scope, [row("live")], ["live"], opened + 2_000);
    expect(
      motion.observe(
        next,
        [row("live"), echo("pending")],
        true,
        opened + 2_001,
      ),
    ).toEqual([]);
    motion.receive(scope, [row("late")], ["late"], opened + 2_002);
    expect(
      motion.observe(
        next,
        [row("live"), echo("pending"), row("late")],
        true,
        opened + 2_003,
      ),
    ).toEqual([]);
    expect(
      motion.observe(
        scope,
        [row("live"), echo("pending")],
        true,
        opened + 2_004,
      ),
    ).toEqual([]);
  },
);

test("loading, hidden views, reload and resume never animate their first frame", () => {
  const motion = new MessageEntrance();
  motion.observe(scope, [], false, opened);
  motion.receive(scope, [row("live")], ["live"], opened + 2_000);
  expect(
    motion.observe(scope, [row("live"), echo("pending")], true, opened + 2_001),
  ).toEqual([]);
  motion.pause();
  motion.receive(scope, [row("resume")], ["resume"], opened + 2_002);
  expect(
    motion.observe(
      scope,
      [row("resume"), echo("background")],
      true,
      opened + 2_003,
    ),
  ).toEqual([]);
  expect(
    new MessageEntrance().observe(
      scope,
      [row("resume"), echo("background")],
      true,
      opened + 2_004,
    ),
  ).toEqual([]);
});

test("backfilled, stale, future and undated received records appear without motion", () => {
  const motion = new MessageEntrance();
  motion.observe(scope, [], true, opened);
  const rows = [
    row("backfill", opened - 1),
    row("stale"),
    row("future", opened + 40_000),
    row("undated"),
  ];
  delete rows[3].body.created_at;
  motion.receive(
    scope,
    rows,
    rows.map((r) => r.id),
    opened + 35_000,
  );
  expect(motion.observe(scope, rows, true, opened + 35_001)).toEqual([]);
});

test("a slow history read expires pending motion without delaying or hiding the message", () => {
  const motion = new MessageEntrance();
  motion.observe(scope, [], true, opened);
  motion.receive(scope, [row("live")], ["live"], opened + 2_000);
  expect(motion.observe(scope, [row("live")], true, opened + 12_001)).toEqual(
    [],
  );
});

test("expiry and unavailable placeholders consume an ID without animating replacement content", () => {
  const motion = new MessageEntrance();
  motion.observe(scope, [], true, opened);
  const expired = {
    ...row("deletion"),
    body: {
      ...row("live").body,
      kind: "deleted",
      deleted_record_id: "live",
      expired: true,
    },
  };
  motion.receive(scope, [row("live")], ["live"], opened + 2_000);
  expect(motion.observe(scope, [expired], true, opened + 2_001)).toEqual([]);
  expect(motion.observe(scope, [row("live")], true, opened + 2_002)).toEqual(
    [],
  );
  const unavailable = {
    ...row("locator"),
    body: {
      ...row("missing").body,
      kind: "unavailable",
      locator: {
        message_record_id: "missing",
        body_object_id: "object",
        locator_nonce: "nonce",
      },
    },
  };
  motion.observe(scope, [unavailable], true, opened + 2_003);
  motion.receive(scope, [row("missing")], ["missing"], opened + 2_004);
  expect(motion.observe(scope, [row("missing")], true, opened + 2_005)).toEqual(
    [],
  );
});

test("unchanged rows and inactive lists do not revisit message contents", () => {
  const motion = new MessageEntrance();
  const message = row("existing");
  const read = vi.fn(() => "existing");
  Object.defineProperty(message, "id", { get: read });
  motion.observe(scope, [message], true, opened);
  read.mockClear();
  for (let i = 1; i <= 10; i++)
    expect(motion.observe(scope, [message], true, opened + i)).toEqual([]);
  expect(read).not.toHaveBeenCalled();
  for (let i = 1; i <= 10; i++)
    expect(motion.observe(scope, [message], false, opened + i)).toEqual([]);
  expect(read).not.toHaveBeenCalled();
  motion.observe(scope, [message], true, opened + 20);
  expect(read).toHaveBeenCalledOnce();
});

test("empty received batches skip rows and unrelated IDs skip timestamp parsing", () => {
  const motion = new MessageEntrance();
  motion.observe(scope, [], true, opened);
  const message = row("unrelated");
  const read = vi.fn(() => "unrelated");
  Object.defineProperty(message, "id", { get: read });
  motion.receive(scope, [message], [], opened + 2_000);
  expect(read).not.toHaveBeenCalled();
  const parse = vi.spyOn(Date, "parse");
  try {
    motion.receive(scope, [message], ["live"], opened + 2_000);
    expect(parse).not.toHaveBeenCalled();
  } finally {
    parse.mockRestore();
  }
});
