import { expect, test } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { AttachmentButton } from "./AttachmentButton";
import type { MessageRow } from "./messageThreads";

const attachment = {
  id: "file-record",
  state: "STORED",
  body: {
    kind: "file.shared",
    issuer_identity: "sender",
    filename: "holiday-photo.jpg",
    size_bytes: 1_153_434,
  },
} as MessageRow;

test("an available attachment shows only its name and compact size", () => {
  const html = renderToStaticMarkup(
    <AttachmentButton
      row={attachment}
      onDownload={() => {}}
      onCancel={() => {}}
    />,
  );
  expect(html).toContain("holiday-photo.jpg");
  expect(html).toContain("1.1 MB");
  expect(html).toContain(
    '<span class="attachment-name">holiday-photo.jpg</span>',
  );
  expect(html).not.toContain("download on demand");
});

test("an active attachment download shows progress and a subtle cancel action", () => {
  const html = renderToStaticMarkup(
    <AttachmentButton
      row={attachment}
      download={{ received: 576_717, total: 1_153_434, cancelling: false }}
      onDownload={() => {}}
      onCancel={() => {}}
    />,
  );
  expect(html).toContain("Downloading… 50%");
  expect(html).toContain('class="attachment-cancel"');
  expect(html).toContain(">Cancel</button>");
  expect(html).toContain('value="576717"');
});
