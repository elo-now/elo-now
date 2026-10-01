import { invoke } from "@tauri-apps/api/core";

export type AttachmentContext = {
  expected_identity: string;
  expected_space: string;
  space: string;
  stream: string;
};
export type AttachmentRequest = AttachmentContext & { record: string };
export type PreviewDimensions = { width: number; height: number };
type Preview = {
  pending: Promise<string | null>;
  url?: string;
  dimensions?: PreviewDimensions;
  decoded?: boolean;
};

/** Native previews are orientation-corrected PNGs bounded to 640 pixels.
 * Read only their fixed IHDR header so layout does not wait for bitmap decoding. */
export function previewDimensions(url: string): PreviewDimensions | undefined {
  const prefix = "data:image/png;base64,";
  if (!url.startsWith(prefix)) return;
  try {
    const header = atob(url.slice(prefix.length, prefix.length + 32));
    if (
      header.length !== 24 ||
      header.slice(0, 8) !== "\x89PNG\r\n\x1a\n" ||
      header.slice(8, 16) !== "\0\0\0\rIHDR"
    )
      return;
    const read = (offset: number) =>
      ((header.charCodeAt(offset) << 24) |
        (header.charCodeAt(offset + 1) << 16) |
        (header.charCodeAt(offset + 2) << 8) |
        header.charCodeAt(offset + 3)) >>>
      0;
    const width = read(16),
      height = read(20);
    if (width > 0 && width <= 640 && height > 0 && height <= 640)
      return { width, height };
  } catch {
    // Unknown dimensions retain the existing intrinsic image layout.
  }
}
const previews = new Map<string, Preview>();

export function clearAttachmentPreviews() {
  previews.clear();
}

/** Reuse a resolved preview on the first render after returning to a chat. */
export function cachedAttachmentPreview(request: AttachmentRequest) {
  return previews.get(JSON.stringify(request))?.url;
}

export function cachedAttachmentPreviewState(request: AttachmentRequest) {
  const entry = previews.get(JSON.stringify(request));
  return entry?.url
    ? {
        url: entry.url,
        dimensions: entry.dimensions,
        decoded: entry.decoded === true,
      }
    : undefined;
}

/** A late decode must not recreate profile data after locking or eviction. */
export function rememberAttachmentPreviewDecoded(
  request: AttachmentRequest,
  url: string,
) {
  const entry = previews.get(JSON.stringify(request));
  if (entry?.url === url) entry.decoded = true;
}

/** This command only reads authenticated local ciphertext; it never downloads. */
export function loadAttachmentPreview(
  request: AttachmentRequest,
  refresh = false,
) {
  const key = JSON.stringify(request);
  if (refresh) previews.delete(key);
  let entry = previews.get(key);
  if (!entry) {
    const result: Preview = {
      pending: invoke<string | null>("attachment_preview", { request }).then(
        (value) => value ?? null,
      ),
    };
    entry = result;
    previews.set(key, result);
    void result.pending.then(
      (value) => {
        // A late lookup must not repopulate the cache after locking the profile.
        if (previews.get(key) !== result) return;
        // Do not retain misses or errors: another transfer may cache the file.
        if (value) {
          result.url = value;
          result.dimensions = previewDimensions(value);
        } else previews.delete(key);
      },
      () => {
        if (previews.get(key) === result) previews.delete(key);
      },
    );
    while (previews.size > 24) previews.delete(previews.keys().next().value!);
  }
  return entry.pending;
}

export function shareAttachment(request: AttachmentRequest) {
  return invoke("share_cached_attachment", { request });
}
