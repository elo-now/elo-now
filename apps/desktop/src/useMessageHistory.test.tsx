import { expect, test } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import type { HistoryPage } from "./messageHistory";
import type { Stream, View } from "./model";
import { useMessageHistory } from "./useMessageHistory";

const chat = {
  space: "chat-space",
  stream: "chat",
  rows: [],
} as unknown as Stream;
const view = {
  identity: "me",
  active_space: "company",
  revision: 8,
  paged: true,
  streams: [chat],
} as View;
const prepared: HistoryPage = {
  identity: "me",
  space_context: "company",
  space: "chat-space",
  stream: "chat",
  revision: 7,
  rows: [
    {
      id: "target",
      body: { kind: "chat.message", payload: { text: "Ready message" } },
    },
  ] as Stream["rows"],
  context: [],
  next: "older",
  newer: null,
};
function FirstPaint({
  page = prepared,
  query = "",
  thread,
}: {
  page?: HistoryPage;
  query?: string;
  thread?: string;
}) {
  const history = useMessageHistory(
    view,
    chat,
    true,
    query,
    thread,
    "target",
    page,
  );
  return (
    <div data-ready={history.ready} data-loading={history.loading}>
      {history.rows.map((row) => (
        <p key={row.id}>{row.body.payload?.text}</p>
      ))}
    </div>
  );
}

test("a push destination renders its verified page before any effects or native fetch, even when a later status revision exists", () => {
  const html = renderToStaticMarkup(<FirstPaint />);
  expect(html).toContain('data-ready="true"');
  expect(html).toContain('data-loading="false"');
  expect(html).toContain("Ready message");
});

test("a prepared push page cannot appear in a different profile, Space, chat, thread or search", () => {
  for (const change of [
    { identity: "other" },
    { space_context: "other" },
    { space: "other" },
    { stream: "other" },
    { thread: "other" },
    { query: "other" },
    { rows: [] },
  ]) {
    const html = renderToStaticMarkup(
      <FirstPaint page={{ ...prepared, ...change }} />,
    );
    expect(html).toContain('data-ready="false"');
    expect(html).not.toContain("Ready message");
  }
  expect(renderToStaticMarkup(<FirstPaint query="search" />)).not.toContain(
    "Ready message",
  );
  expect(renderToStaticMarkup(<FirstPaint thread="root" />)).not.toContain(
    "Ready message",
  );
  expect(
    renderToStaticMarkup(
      <FirstPaint thread="root" page={{ ...prepared, thread: "root" }} />,
    ),
  ).toContain("Ready message");
});
