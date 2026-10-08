import { expect, it, vi } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import type { ReactNode } from "react";
import type { Stream, View } from "../model";
import type { Calls } from "./controller";
import { CallSurface, IncomingCallWidget } from "./CallUI";
import { useIncomingRingtone } from "./useIncomingRingtone";
import { callKey, muted, type ActiveCall, type Snapshot } from "./types";
import { sessionKey } from "./attention";

const runtime = vi.hoisted(() => ({ autoplayBlocked: false }));

vi.mock("react", async (original) => ({
  ...(await original<typeof import("react")>()),
  useSyncExternalStore: (_subscribe: unknown, getSnapshot: () => unknown) => {
    const snapshot = getSnapshot();
    return typeof snapshot === "boolean" ? runtime.autoplayBlocked : snapshot;
  },
}));
vi.mock("./useIncomingRingtone", () => ({ useIncomingRingtone: vi.fn() }));
vi.mock("../PageSurface", () => ({ useDesktopLayout: () => false }));
vi.mock("./audioOutput", () => ({
  useAudioOutput: () => ({ outputs: [], supported: false, ready: false }),
}));
vi.mock("./FloatingCall", () => ({
  FloatingCall: (props: {
    title: ReactNode;
    children: ReactNode;
    hidden?: boolean;
  }) => (
    <section data-call-widget hidden={props.hidden}>
      {props.title}
      {props.children}
    </section>
  ),
}));

function setup() {
  const chat = {
    name: "Planning",
    space_context: "host",
    space: "space",
    stream: "planning",
    head: "head",
    can_post: true,
    member_names: { peer: "Alex" },
  } as unknown as Stream;
  const call: ActiveCall = {
    call_id: "call",
    scope: {
      hosting_space_id: "host",
      conversation: { space_id: "space", stream_id: "planning" },
    },
    config_id: "head",
    key_epoch: 1,
    kind: "group",
    initial_media: "audio",
    started_by: "peer",
    started_at: 1,
    ready: true,
    participants: {
      peer: {
        identity_id: "peer",
        credential_id: "device",
        media: muted,
        ready: true,
      },
    },
  };
  const state: Snapshot = {
    phase: "idle",
    media: muted,
    tiles: [],
    available: { [callKey(call)]: call },
  };
  const view = {
    identity: "me",
    streams: [chat],
    spaces: [{ id: "host", name: "Team", managed: true, status: "joined" }],
  } as unknown as View;
  const calls = {
    subscribe: () => () => {},
    getSnapshot: () => state,
    localCapture: () => undefined,
    localScreen: () => undefined,
    audioOutputContext: () => undefined,
    answer: vi.fn(),
    decline: vi.fn(),
    requestStart: vi.fn(),
  } as unknown as Calls;
  const render = (currentChat?: Stream) =>
    renderToStaticMarkup(
      <CallSurface
        calls={calls}
        view={view}
        currentChat={currentChat}
        onShowCalls={vi.fn()}
      />,
    );
  return { call, chat, state, view, render, calls };
}

it("keeps the minimized session hidden when another available chat is selected", () => {
  const f = setup();
  const otherChat = { ...f.chat, name: "Review", stream: "review" };
  const otherCall = {
    ...f.call,
    call_id: "other-call",
    scope: {
      ...f.call.scope,
      conversation: { space_id: "space", stream_id: "review" },
    },
  };
  f.view.streams.push(otherChat);
  f.state.available[callKey(otherCall)] = otherCall;
  f.state.minimized = sessionKey(f.call);
  const markup = f.render(otherChat);
  expect(markup).toContain('<section data-call-widget="true" hidden="">');
  expect(markup).toContain("Planning");
  expect(markup).not.toContain("Review");
  expect(markup).toContain('class="call-media call-media-collapsed"');
  expect(markup).not.toContain("call-widget-avatar");
});

it("keeps the media container while hiding an active call's controls", () => {
  const f = setup();
  f.state.active = f.call;
  f.state.chat = f.chat;
  f.state.phase = "connected";
  f.state.minimized = sessionKey(f.call);
  const markup = f.render();
  expect(markup).toContain('<section data-call-widget="true" hidden="">');
  expect(markup).toContain('class="call-media call-media-collapsed"');
  expect(markup).toContain('class="icon call-widget-hide"');
  expect(markup).toContain('aria-label="Hide call" title="Hide call"');
  expect(markup).toContain('class="call-widget-title call-widget-expand"');
  expect(markup).toContain("data-call-drag-toggle");
  expect(markup).not.toContain("call-widget-avatar");
});

it("places autoplay recovery in the visible widget controls, outside hidden tracks", () => {
  const f = setup();
  f.state.active = f.call;
  f.state.chat = f.chat;
  f.state.phase = "connected";
  runtime.autoplayBlocked = true;
  try {
    const markup = f.render();
    const widget = markup.slice(
      markup.indexOf("<section"),
      markup.indexOf("</section>"),
    );
    expect(widget).toContain('aria-label="Play audio"');
    const hidden = markup.slice(
      markup.indexOf('class="call-media call-media-collapsed"'),
    );
    expect(hidden).not.toContain('aria-label="Play audio"');
  } finally {
    runtime.autoplayBlocked = false;
  }
});

it("labels the icon Answer only for a current invitation to this profile", () => {
  const f = setup();
  f.call.kind = "direct";
  f.call.phase = "ringing";
  expect(f.render()).toContain('aria-label="Join" title="Join"');
  f.call.invitations = {
    me: {
      invitation_id: "attempt",
      invited_by: "peer",
      expires_at: Math.floor(Date.now() / 1000) + 60,
    },
  };
  const markup = f.render();
  expect(markup).toContain('aria-label="Answer" title="Answer"');
  expect(markup).not.toContain(">Answer<");
  expect(markup).not.toContain(">Join<");
});

function incomingFixture() {
  const f = setup();
  f.call.kind = "direct";
  f.call.phase = "ringing";
  f.call.invitations = {
    me: {
      invitation_id: "attempt",
      invited_by: "peer",
      expires_at: Math.floor(Date.now() / 1000) + 60,
    },
  };
  f.state.incoming = [f.call];
  return f;
}

it("prioritizes one incoming widget over another selected available conversation", () => {
  const f = incomingFixture();
  const otherChat = { ...f.chat, name: "Other chat", stream: "other" };
  const other = {
    ...f.call,
    call_id: "other",
    kind: "group" as const,
    invitations: {},
    scope: {
      ...f.call.scope,
      conversation: { space_id: "space", stream_id: "other" },
    },
  };
  f.view.streams.push(otherChat);
  f.state.available[callKey(other)] = other;
  const markup = f.render(otherChat);
  expect(markup.match(/data-call-widget=/g)).toHaveLength(1);
  expect(markup).toContain('aria-label="Answer"');
  expect(markup).toContain('aria-label="Decline"');
  expect(markup).toContain("Planning");
  expect(markup).toContain("Incoming call · Team");
  expect(markup).not.toContain("Other chat");
  expect(markup).not.toContain("<dialog");
});

it("hands the exact invitation to native UI without leaving an available duplicate or alert", () => {
  const f = incomingFixture();
  f.render();
  expect(vi.mocked(useIncomingRingtone).mock.lastCall![0].ringKey).toContain(
    ":attempt",
  );
  f.state.nativePresented = [{ call_id: f.call.call_id, invitation_id: "old" }];
  expect(f.render()).toContain('aria-label="Answer"');
  f.state.nativePresented = [
    { call_id: "other-call", invitation_id: "attempt" },
  ];
  expect(f.render()).toContain('aria-label="Answer"');
  f.state.nativePresented = [
    { call_id: f.call.call_id, invitation_id: "attempt" },
  ];
  expect(f.render()).not.toContain("data-call-widget");
  expect(
    vi.mocked(useIncomingRingtone).mock.lastCall![0].ringKey,
  ).toBeUndefined();
  f.state.nativePresented = [{ call_id: f.call.call_id, invitation_id: "old" }];
  expect(f.render()).toContain('aria-label="Answer"');
});

it("keeps the other connected call when native UI takes over a waiting invitation", () => {
  const f = incomingFixture();
  f.state.active = {
    ...f.call,
    call_id: "connected",
    invitations: {},
    phase: "active",
  };
  f.state.chat = { ...f.chat, name: "Current chat" };
  f.state.phase = "connected";
  const waiting = f.render();
  expect(waiting.match(/data-call-widget=/g)).toHaveLength(1);
  expect(waiting).toContain(
    "Answering will end your current call in Current chat.",
  );
  expect(waiting).toContain('aria-label="Decline"');
  expect(waiting).not.toContain("<dialog");
  f.state.nativePresented = [
    { call_id: f.call.call_id, invitation_id: "attempt" },
  ];
  const native = f.render();
  expect(native.match(/data-call-widget=/g)).toHaveLength(1);
  expect(native).toContain("Current chat");
  expect(native).toContain('aria-label="Leave session"');
  expect(native).not.toContain('aria-label="Decline"');
  expect(f.calls.answer).not.toHaveBeenCalled();
  expect(f.calls.decline).not.toHaveBeenCalled();
});

it("does not replay a ringtone from an available reconnect snapshot", () => {
  const f = incomingFixture();
  f.state.incoming = [];
  expect(f.render()).toContain('aria-label="Decline"');
  expect(
    vi.mocked(useIncomingRingtone).mock.lastCall![0].ringKey,
  ).toBeUndefined();
});

function incomingWidget(f: ReturnType<typeof incomingFixture>, overrides = {}) {
  return IncomingCallWidget({
    calls: f.calls,
    session: {
      call: f.call,
      chat: f.chat,
      spaceName: "Team",
      participantNames: ["Alex"],
      starterName: "Alex",
    },
    identity: "me",
    answering: false,
    hasCurrentCall: false,
    hidden: false,
    onOpen: vi.fn(),
    onHide: vi.fn(),
    ...overrides,
  });
}

it("answers the exact attempt from the widget and declines without ending another call", () => {
  const f = incomingFixture();
  const widget = incomingWidget(f);
  widget.props.children[0].props.onClick();
  expect(f.calls.answer).toHaveBeenCalledExactlyOnceWith(
    f.chat,
    f.call,
    false,
    "attempt",
  );
  widget.props.children[1].props.onClick();
  expect(f.calls.decline).toHaveBeenCalledExactlyOnceWith(f.call);
});

it("requires an explicit switch confirmation for the incoming widget during a call", () => {
  const f = incomingFixture();
  const widget = incomingWidget(f, {
    hasCurrentCall: true,
    currentCall: "Current chat",
  });
  widget.props.children[0].props.onClick();
  expect(f.calls.requestStart).toHaveBeenCalledExactlyOnceWith(f.chat, f.call);
  expect(f.calls.answer).not.toHaveBeenCalled();
  widget.props.children[1].props.onClick();
  expect(f.calls.decline).toHaveBeenCalledExactlyOnceWith(f.call);
});

it("disables incoming actions while answering and hiding does not answer or decline", () => {
  const f = incomingFixture();
  const widget = incomingWidget(f, { answering: true });
  for (const button of widget.props.children) {
    expect(button.props.disabled).toBe(true);
    button.props.onClick();
  }
  expect(f.calls.answer).not.toHaveBeenCalled();
  expect(f.calls.decline).not.toHaveBeenCalled();
  const hidden = incomingWidget(f, { hidden: true });
  expect(hidden.props.hidden).toBe(true);
  expect(f.calls.answer).not.toHaveBeenCalled();
  expect(f.calls.decline).not.toHaveBeenCalled();
});

it("shows a fresh incoming attempt after the previous session presentation was dismissed", () => {
  const f = incomingFixture();
  f.state.dismissed = [sessionKey(f.call)];
  f.call.invitations!.me.invitation_id = "fresh-attempt";
  expect(f.render()).toContain('aria-label="Decline"');
  expect(vi.mocked(useIncomingRingtone).mock.lastCall![0].ringKey).toContain(
    ":fresh-attempt",
  );
});
