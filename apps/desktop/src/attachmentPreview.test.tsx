import { beforeEach, expect, test, vi } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { invoke } from "@tauri-apps/api/core";
import { AttachmentButton } from "./AttachmentButton";
import {
  cachedAttachmentPreview,
  cachedAttachmentPreviewState,
  clearAttachmentPreviews,
  loadAttachmentPreview,
  previewDimensions,
  rememberAttachmentPreviewDecoded,
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

// Only the fixed PNG header is needed to reserve a native thumbnail's geometry.
function pngHeader(width: number, height: number) {
  const header = new Uint8Array(24);
  header.set([137, 80, 78, 71, 13, 10, 26, 10, 0, 0, 0, 13, 73, 72, 68, 82]);
  const view = new DataView(header.buffer);
  view.setUint32(16, width);
  view.setUint32(20, height);
  return `data:image/png;base64,${btoa(String.fromCharCode(...header))}`;
}

test("the native PNG geometry reserves landscape and portrait space before decoding", async () => {
  const url = pngHeader(640, 480);
  native.mockResolvedValue(url);
  await loadAttachmentPreview(request);
  expect(cachedAttachmentPreviewState(request)?.dimensions).toEqual({
    width: 640,
    height: 480,
  });
  let html = render();
  expect(html).toContain('width="640" height="480"');
  expect(html).toContain("width:360px;aspect-ratio:640 / 480");
  expect(html).not.toContain('data-preview-ready="true"');

  native.mockResolvedValue(pngHeader(360, 640));
  await loadAttachmentPreview(request, true);
  html = render();
  expect(html).toContain('width="360" height="640"');
  expect(html).toContain("width:202.5px;aspect-ratio:360 / 640");
});

test("an already decoded photo is visible immediately on returning to the chat", async () => {
  const url = pngHeader(640, 480);
  native.mockResolvedValue(url);
  await loadAttachmentPreview(request);
  rememberAttachmentPreviewDecoded(request, url);
  const html = render();
  expect(html).toContain('data-preview-ready="true"');
  expect(html).not.toContain('aria-busy="true"');
  expect(html).not.toContain("attachment-preview-pending");
  expect(native).toHaveBeenCalledTimes(1);
});

test("geometry and decode readiness cannot leak across profiles or return after locking", async () => {
  const url = pngHeader(640, 480);
  native.mockResolvedValue(url);
  await loadAttachmentPreview(request);
  rememberAttachmentPreviewDecoded(
    { ...request, expected_identity: "other-profile" },
    url,
  );
  expect(cachedAttachmentPreviewState(request)?.decoded).toBe(false);
  rememberAttachmentPreviewDecoded(request, "data:image/png;base64,old");
  expect(cachedAttachmentPreviewState(request)?.decoded).toBe(false);
  clearAttachmentPreviews();
  rememberAttachmentPreviewDecoded(request, url);
  expect(cachedAttachmentPreviewState(request)).toBeUndefined();
});

test("unknown or invalid headers do not invent image geometry", () => {
  for (const url of [
    "data:image/jpeg;base64,test",
    "data:image/png;base64,invalid",
    pngHeader(0, 480),
    pngHeader(640, 641),
  ])
    expect(previewDimensions(url)).toBeUndefined();
  expect(previewDimensions(pngHeader(128, 96))).toEqual({
    width: 128,
    height: 96,
  });
});
