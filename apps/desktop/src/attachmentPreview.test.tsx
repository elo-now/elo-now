import { beforeEach, expect, test, vi } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { invoke } from "@tauri-apps/api/core";
import { AttachmentButton } from "./AttachmentButton";
import {
  cachedAttachmentPreview,
  clearAttachmentPreviews,
  loadAttachmentPreview,
} from "./attachmentPreview";
import type { MessageRow } from "./messageThreads";

vi.mock("@tauri-apps/api/core", () => ({ invoke: vi.fn() }));
const native = vi.mocked(invoke);
const context = {
  expected_identity: "test-profile",
  expected_space: "test-space",
  space: "local-space",
  stream: "general",
};
const request = { ...context, record: "photo" };
const row = {
  id: "photo",
  state: "STORED",
  body: { kind: "file.shared", filename: "photo.jpg", size_bytes: 500 },
} as MessageRow;
const render = () =>
  renderToStaticMarkup(
    <AttachmentButton
      row={row}
      context={context}
      onDownload={() => {}}
      onCancel={() => {}}
    />,
  );

beforeEach(() => {
  clearAttachmentPreviews();
  native.mockReset();
});

test("the first frame does not advertise a download before checking the local copy", () => {
  const html = render();
  expect(html).toContain('aria-busy="true"');
  expect(html).not.toContain("<button");
});

test("returning to a chat renders a resolved local image in the first frame", async () => {
  native.mockResolvedValue("data:image/png;base64,test");
  await loadAttachmentPreview(request);
  expect(render()).toContain('src="data:image/png;base64,test"');
  expect(native).toHaveBeenCalledTimes(1);
  expect(
    cachedAttachmentPreview({
      ...request,
      expected_identity: "another-profile",
    }),
  ).toBeUndefined();
  expect(
    cachedAttachmentPreview({ ...request, expected_space: "another-space" }),
  ).toBeUndefined();
});

test("concurrent local lookups share work without downloading", async () => {
  native.mockResolvedValue(null);
  const first = loadAttachmentPreview(request);
  expect(loadAttachmentPreview(request)).toBe(first);
  await first;
  expect(native).toHaveBeenCalledExactlyOnceWith("attachment_preview", {
    request,
  });
});

test("late reads cannot restore a preview after the profile has been locked", async () => {
  let resolve!: (value: string) => void;
  native.mockReturnValue(
    new Promise<string>((done) => {
      resolve = done;
    }),
  );
  const pending = loadAttachmentPreview(request);
  clearAttachmentPreviews();
  resolve("data:image/png;base64,old-profile");
  await pending;
  expect(cachedAttachmentPreview(request)).toBeUndefined();
  expect(render()).not.toContain("old-profile");
});

test("a file cached after a miss becomes available on the next lookup", async () => {
  native
    .mockResolvedValueOnce(null)
    .mockResolvedValueOnce("data:image/png;base64,new");
  expect(await loadAttachmentPreview(request)).toBeNull();
  expect(await loadAttachmentPreview(request)).toContain("base64,new");
  expect(native).toHaveBeenCalledTimes(2);
});

test("failed local reads can be retried", async () => {
  native
    .mockRejectedValueOnce(new Error("temporary local read failure"))
    .mockResolvedValueOnce(null);
  await expect(loadAttachmentPreview(request)).rejects.toThrow(
    "temporary local read failure",
  );
  expect(await loadAttachmentPreview(request)).toBeNull();
});
