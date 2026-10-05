import { renderToStaticMarkup } from "react-dom/server";
import { expect, test } from "vitest";
import { MessageContent } from "./MessageContent";
import { expireMessageRows } from "./messageExpiry";
import { formatAttachmentExpiry, t } from "./i18n";
import type { Stream, View } from "./model";
import { MAX_TIMESTAMP_MS } from "./timestamps";

const deadline = Date.parse("2026-10-02T13:00:00Z");
const row: Stream["rows"][number] = {
  id: "text",
  state: "STORED",
  body: {
    kind: "chat.message",
    issuer_identity: "sender",
    created_at: "2026-10-01T13:00:00Z",
    payload: { text: "Message", expires_at_ms: deadline },
  },
};
const view = {
  identity: "sender",
  streams: [],
  contacts: [],
} as unknown as View;
const render = (message = row) =>
  renderToStaticMarkup(
    <MessageContent view={view} row={message} hideAvatars>
      <p>{message.body.payload?.text}</p>
    </MessageContent>,
  );

test("sent text and unavailable locators show their effective deadline in the shared message layout", () => {
  for (const kind of ["chat.message", "unavailable"]) {
    const html = render({ ...row, body: { ...row.body, kind } });
    expect(html).toContain(
      t("messageActions.expiresAt", { date: formatAttachmentExpiry(deadline) }),
    );
    expect(html).toContain('dateTime="2026-10-02T13:00:00.000Z"');
    expect(html).toContain('<div class="message-expiry">');
  }
});

test("cancelling expiry removes the caption and stops local expiry; a new deadline replaces the old one", () => {
  const cancelled = {
    ...row,
    body: {
      ...row.body,
      payload: { ...row.body.payload, expires_at_ms: null },
    },
  };
  expect(render(cancelled)).not.toContain('class="message-expiry"');
  expect(expireMessageRows([cancelled], deadline + 1)[0]).toBe(cancelled);
  const extended = {
    ...row,
    body: {
      ...row.body,
      payload: { ...row.body.payload, expires_at_ms: deadline + 3600000 },
    },
  };
  expect(expireMessageRows([extended], deadline)[0]).toBe(extended);
  expect(render(extended)).toContain(
    formatAttachmentExpiry(deadline + 3600000),
  );
  expect(
    render(expireMessageRows([extended], deadline + 3600000)[0]),
  ).not.toContain('class="message-expiry"');
});

test("invalid cached message and locator deadlines never crash the shared conversation layout", () => {
  for (const kind of ["chat.message", "unavailable"]) {
    for (const expires of [
      MAX_TIMESTAMP_MS + 1,
      Number.MAX_SAFE_INTEGER,
      Infinity,
      NaN,
      -1,
      0,
      1.5,
    ]) {
      const message = {
        ...row,
        body: {
          ...row.body,
          kind,
          payload: { text: "Preserved text", expires_at_ms: expires },
        },
      };
      const html = render(message);
      expect(html).toContain("Preserved text");
      expect(html).not.toContain('class="message-expiry"');
    }
    expect(
      render({
        ...row,
        body: {
          ...row.body,
          kind,
          payload: { expires_at_ms: MAX_TIMESTAMP_MS },
        },
      }),
    ).toContain('dateTime="+275760-09-13T00:00:00.000Z"');
  }
});

test("edited labels use the shared layout and disappear with expired content", () => {
  const edited = {
    ...row,
    body: {
      ...row.body,
      payload: { ...row.body.payload, edited_at_ms: deadline - 1000 },
    },
  };
  expect(render(edited)).toContain('class="message-edited"');
  expect(render(edited)).toContain(t("messageActions.edited"));
  expect(render(expireMessageRows([edited], deadline + 1)[0])).not.toContain(
    'class="message-edited"',
  );
  expect(
    render({ ...edited, body: { ...edited.body, kind: "unavailable" } }),
  ).not.toContain('class="message-edited"');
});
