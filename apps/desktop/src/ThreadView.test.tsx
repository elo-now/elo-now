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
      draft=""
      onDraft={noop}
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
  },
);
