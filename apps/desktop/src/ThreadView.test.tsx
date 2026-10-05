import type { ComponentProps } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { ThreadView } from "./ThreadView";
import { t } from "./i18n";
import type { Stream, View } from "./model";

const root = {
  id: "original",
  state: "ACCEPTED",
  body: {
    kind: "chat.message",
    issuer_identity: "me",
    payload: { text: "Original message" },
  },
};
const thread = { rootId: root.id, root, replies: [], unreadCount: 0 };
const chat = {
  stream: "chat",
  space: "space",
  can_post: true,
  forked: false,
  members: [],
  rows: [root],
} as unknown as Stream;
const view = { identity: "me", streams: [chat] } as unknown as View;
const noop = () => {};
const done = async () => {};

function render(
  mobile: boolean,
  overrides: Partial<ComponentProps<typeof ThreadView>> = {},
) {
  return renderToStaticMarkup(
    <ThreadView
      view={view}
      chat={chat}
      thread={thread}
      mobile={mobile}
      hideAvatars
      busy={false}
      savedDraft={{
        text: "A reply with its own deadline",
        expiry: undefined,
        mentions: [],
        attachment: null,
        ready: true,
        setExpiry: noop,
        setText: noop,
        setContent: noop,
        setAttachment: noop,
        clearSubmitted: noop,
        clear: noop,
      }}
      onFollow={done}
      onBack={noop}
      onRefresh={done}
      onRead={noop}
      onSend={async () => true}
      onStatus={noop}
      onFile={noop}
      onCancelAttachment={noop}
      composeRevision={0}
      onRequestMessage={done}
      onUnavailable={noop}
      {...overrides}
    />,
  );
}

describe.each([true, false])(
  "thread history messages (mobile=%s)",
  (mobile) => {
    it("shows an empty reply list only for a fully loaded original message", () => {
      expect(render(mobile)).toContain(t("thread.empty"));
    });

    it("does not claim there are no replies when the original is unavailable", () => {
      const html = render(mobile, { thread: { ...thread, root: undefined } });
      expect(html).toContain(t("thread.missingRoot"));
      expect(html).not.toContain(t("thread.empty"));
    });

    it("keeps loading separate from empty or unavailable history", () => {
      const html = render(mobile, {
        historyReady: false,
        historyLoading: true,
        thread: { ...thread, root: undefined },
      });
      expect(html).toContain(t("history.loading"));
      expect(html).not.toContain(t("thread.missingRoot"));
      expect(html).not.toContain(t("thread.empty"));
    });

    it("does not declare an empty thread while older or newer pages remain", () => {
      for (const paging of [{ hasOlder: true }, { hasNewer: true }]) {
        expect(render(mobile, paging)).not.toContain(t("thread.empty"));
      }
    });
    it("always offers a reply its own expiry even when the original has a deadline", () => {
      expect(render(mobile)).toContain('aria-label="Delete after:"');
      const expiring = {
        ...root,
        body: {
          ...root.body,
          payload: {
            ...root.body.payload,
            expires_at_ms: Date.now() + 3_600_000,
          },
        },
      };
      const html = render(mobile, { thread: { ...thread, root: expiring } });
      expect(html).toContain('aria-label="Delete after:"');
      expect(html).not.toContain(
        'placeholder="' + t("composer.unavailable") + '"',
      );
    });
    it("keeps reply controls available after a known original expires", () => {
      const expired = {
        ...root,
        body: {
          ...root.body,
          kind: "deleted",
          expired: true,
          payload: undefined,
        },
      };
      const html = render(mobile, {
        thread: { ...thread, root: expired },
      });
      expect(html).not.toContain(
        'placeholder="' + t("composer.unavailable") + '"',
      );
      expect(html).toContain('aria-label="Delete after:"');
      expect(html).not.toMatch(/<button[^>]*aria-label="Send"[^>]*disabled=""/);
    });
  },
);
