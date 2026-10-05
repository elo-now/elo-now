import { useRef, useState } from "react";
import { ComposerInput } from "./ComposerInput";
import {
  mentionCandidates,
  mentionIdentities,
  restoredMentions,
} from "./composerMentions";
import { t } from "./i18n";
import type { Stream, View } from "./model";

/** Editing changes signed text only; it never changes the message's thread or expiry. */
export function MessageEditor({
  view,
  chat,
  row,
  busy,
  onCancel,
  onSave,
}: {
  view: View;
  chat: Stream;
  row: Stream["rows"][number];
  busy: boolean;
  onCancel: () => void;
  onSave: (text: string, mentions: string[]) => void;
}) {
  const original = row.body.payload?.text ?? "";
  const candidates = mentionCandidates(view, chat);
  const [text, setText] = useState(original);
  const [mentions, setMentions] = useState(() =>
    restoredMentions(original, row.body.payload?.mentions ?? [], candidates),
  );
  const input = useRef<HTMLTextAreaElement>(null);
  const selectedMentions = mentionIdentities(text, mentions);
  const changed =
    text !== original ||
    JSON.stringify(selectedMentions) !==
      JSON.stringify(row.body.payload?.mentions ?? []);
  const available =
    chat.can_post &&
    !chat.forked &&
    row.body.kind === "chat.message" &&
    row.body.issuer_identity === view.identity;
  return (
    <form
      className="message-editor"
      onSubmit={(event) => {
        event.preventDefault();
        if (!busy && available && changed && text.trim())
          onSave(text, selectedMentions);
      }}
    >
      <ComposerInput
        inputRef={input}
        value={text}
        autoFocus
        maxLength={16384}
        aria-label={t("messageActions.editText")}
        disabled={busy || !available}
        mentionCandidates={candidates}
        mentions={mentions}
        onDraftChange={(value, next) => {
          setText(value);
          setMentions(next);
        }}
      />
      <div className="dialog-buttons">
        <button
          type="button"
          className="secondary"
          disabled={busy}
          onClick={onCancel}
        >
          {t("dialog.cancel")}
        </button>
        <button
          type="submit"
          disabled={busy || !available || !text.trim() || !changed}
        >
          {t("messageActions.saveEdit")}
        </button>
      </div>
    </form>
  );
}
