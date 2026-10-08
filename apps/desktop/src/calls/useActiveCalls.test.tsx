import { expect, it, vi } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { MobileNavigation } from "../MobileNavigation";
import type { Stream, View } from "../model";
import type { Calls } from "./controller";
import { useActiveCalls } from "./useActiveCalls";
import { callKey, muted, type ActiveCall, type Snapshot } from "./types";

vi.mock("react", async (importOriginal) => ({
  ...(await importOriginal<typeof import("react")>()),
  useSyncExternalStore: (_subscribe: unknown, getSnapshot: () => unknown) =>
    getSnapshot(),
}));

function fixture() {
  const call: ActiveCall = {
    call_id: "call",
    scope: {
      hosting_space_id: "host",
      conversation: { space_id: "space", stream_id: "chat" },
    },
    config_id: "head",
    key_epoch: 1,
    kind: "group",
    initial_media: "audio",
    started_by: "me",
    started_at: 1,
    ready: true,
    participants: {
      me: {
        identity_id: "me",
        credential_id: "device",
        media: muted,
        ready: true,
      },
    },
  };
  const chat = {
    name: "General",
    space_context: "host",
    space: "space",
    stream: "chat",
    head: "head",
    can_post: true,
  } as unknown as Stream;
  const view = {
    identity: "me",
    streams: [chat],
    spaces: [{ id: "host", name: "Team", status: "joined" }],
  } as unknown as View;
  const state: Snapshot = {
    phase: "idle",
    media: muted,
    tiles: [],
    available: { [callKey(call)]: call },
  };
  const calls = {
    subscribe: () => () => {},
    getSnapshot: () => state,
  } as unknown as Calls;
  return { call, view, state, calls };
}

it("keeps call attention for own, minimized and dismissed group sessions until they end", () => {
  const f = fixture();
  f.state.minimized = `host:space:chat:${f.call.call_id}`;
  f.state.dismissed = [f.state.minimized];
  expect(useActiveCalls(f.calls, f.view)).toBe(true);
  f.state.available = {};
  f.state.active = f.call;
  expect(useActiveCalls(f.calls, f.view)).toBe(true);
  f.state.active = undefined;
  expect(useActiveCalls(f.calls, f.view)).toBe(false);
  expect(useActiveCalls(f.calls, null)).toBe(false);
});

it("does not show remote call attention after access to its chat is lost", () => {
  const f = fixture();
  f.view.streams[0].can_post = false;
  expect(useActiveCalls(f.calls, f.view)).toBe(false);
});

it("marks Buzz for an active call without marking Messages or More as unread", () => {
  const html = renderToStaticMarkup(
    <MobileNavigation active="stream" hasActiveCalls onNavigate={vi.fn()} />,
  );
  expect(html).toContain('aria-label="Buzz, active calls"');
  expect(html.match(/class="new-indicator"/g)).toHaveLength(1);
  expect(html).toContain('aria-label="Active sessions"');
});

it("keeps message and notification dots when a call is active and clears only its dot on end", () => {
  const render = (
    hasActiveCalls: boolean,
    unreadMessages = 2,
    notifications = 1,
  ) =>
    renderToStaticMarkup(
      <MobileNavigation
        active="chats"
        hasActiveCalls={hasActiveCalls}
        unreadMessages={unreadMessages}
        notifications={notifications}
        onNavigate={vi.fn()}
      />,
    );
  expect(render(true)).toContain(
    'aria-label="Buzz, 2 unread messages and active calls"',
  );
  expect(render(true).match(/class="new-indicator"/g)).toHaveLength(3);
  expect(render(false).match(/class="new-indicator"/g)).toHaveLength(3);
  expect(render(false, 0, 0)).not.toContain('class="new-indicator"');
});
