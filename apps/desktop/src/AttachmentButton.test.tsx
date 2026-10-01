import { expect, test } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { AttachmentButton, attachmentFailure } from "./AttachmentButton";
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

test("a deadline appears below the size and changes to Expired without renaming the file", () => {
  const row = (expires: number) => ({ ...attachment, body: { ...attachment.body,
    attachment: { name: "holiday-photo.jpg", plaintext_size: 1_153_434, expires_at_ms: expires },
  } }) as MessageRow;
  const render = (expires: number) => renderToStaticMarkup(
    <AttachmentButton row={row(expires)} onDownload={() => {}} onCancel={() => {}} />,
  );
  const html = render(Date.now() + 3_600_000);
  expect(html.indexOf("Expires:")).toBeGreaterThan(html.indexOf("1.1 MB"));
  expect(html).toContain("<time dateTime=");
  const expired = render(1);
  expect(expired).toContain(">Expired</small>");
  expect(expired).not.toContain("Expires:");
  expect(expired).toContain('disabled=""');
  expect(expired).toContain('class="attachment-name">holiday-photo.jpg</span>');
  expect(() => render(Number.MAX_SAFE_INTEGER)).not.toThrow();
});

test("manual removal is distinct from expiry and network failure", () => {
  expect(attachmentFailure("This attachment has expired on the server.")).toBe("expired");
  expect(attachmentFailure("This attachment was removed from the server.")).toBe("removed");
  expect(attachmentFailure("Space server timed out.")).toBeUndefined();
  expect(renderToStaticMarkup(<AttachmentButton row={attachment} serverState="removed" onDownload={() => {}} onCancel={() => {}} />)).toContain(">Removed</small>");
});
