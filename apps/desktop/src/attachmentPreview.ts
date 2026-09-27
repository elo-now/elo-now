import { invoke } from "@tauri-apps/api/core";

export type AttachmentContext = {
  expected_identity: string;
  expected_space: string;
  space: string;
  stream: string;
};
export type AttachmentRequest = AttachmentContext & { record: string };
type Preview = { pending: Promise<string | null>; url?: string };
const previews = new Map<string, Preview>();

export function clearAttachmentPreviews() {
  previews.clear();
}

/** Reuse a resolved preview on the first render after returning to a chat. */
export function cachedAttachmentPreview(request: AttachmentRequest) {
  return previews.get(JSON.stringify(request))?.url;
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
        if (value) result.url = value;
        else previews.delete(key);
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
