import { useState } from "react";
import { Icon } from "./Icon";
import { t } from "./i18n";
import type { Stream } from "./model";
import { followedThread } from "./streamFeed";

/** A private notification preference, never a membership or publishing action. */
export function ThreadFollowButton({
  chat,
  root,
  identity,
  busy,
  onFollow,
}: {
  chat: Stream;
  root: string;
  identity: string;
  busy: boolean;
  onFollow: (followed: boolean) => Promise<void>;
}) {
  const [saving, setSaving] = useState(false);
  const followed = followedThread(chat, root, identity);
  return (
    <button
      type="button"
      className="icon"
      disabled={busy || saving}
      aria-label={t(followed ? "thread.unfollow" : "thread.follow")}
      title={t(followed ? "thread.unfollow" : "thread.follow")}
      aria-pressed={followed}
      onClick={async () => {
        if (saving) return;
        setSaving(true);
        try {
          await onFollow(!followed);
        } finally {
          setSaving(false);
        }
      }}
    >
      <Icon name="bell" />
    </button>
  );
}
