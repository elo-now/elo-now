import { useEffect, useMemo, useRef, useState } from "react";
import { t } from "./i18n";
import { knownPeople } from "./directMessages";
import { ScreenHeader } from "./ScreenHeader";
import { PeoplePicker } from "./PeoplePicker";
import { useToast, useToastHost } from "./Toast";
import type { View, Stream } from "./model";
import "./newChat.css";

export function AddPeople({
  view,
  stream,
  hideAvatars,
  onClose,
  onAdd,
}: {
  view: View;
  stream: Stream;
  hideAvatars: boolean;
  onClose: () => void;
  onAdd: (request: Record<string, unknown>) => Promise<void>;
}) {
  const dialog = useRef<HTMLDialogElement>(null);
  const heading = useRef<HTMLHeadingElement>(null);
  useToastHost(dialog);
  const { reportError } = useToast();
  const [query, setQuery] = useState("");
  const [selected, setSelected] = useState<string[]>([]);
  const [busy, setBusy] = useState(false);
  const pending = useRef(false);
  const attempt = useRef({ key: "", id: "" });
  const people = useMemo(
    () =>
      knownPeople(view).filter(
        (p) => !stream.members.some((m) => m.identity_id === p.id),
      ),
    [view, stream],
  );
  const limit = Math.max(0, 1000 - stream.members.length);
  useEffect(() => {
    const node = dialog.current;
    node?.showModal();
    heading.current?.focus({ preventScroll: true });
    return () => node?.close();
  }, []);
  const add = async () => {
    if (pending.current || !selected.length) return;
    pending.current = true;
    setBusy(true);
    try {
      const ids = [...selected].sort();
      const key = JSON.stringify(ids);
      if (attempt.current.key !== key)
        attempt.current = { key, id: crypto.randomUUID().replaceAll("-", "") };
      await onAdd({
        op: "contact_add_members",
        expected_identity: view.identity,
        expected_space: view.active_space,
        space: stream.space,
        stream: stream.stream,
        people: ids,
        request_id: attempt.current.id,
      });
      onClose();
    } catch (error) {
      reportError(error);
    } finally {
      pending.current = false;
      setBusy(false);
    }
  };
  return (
    <dialog
      ref={dialog}
      className="dialog new-chat-dialog add-people-dialog"
      aria-label={t("members.addPeople")}
      onCancel={(e) => {
        e.preventDefault();
        if (!busy) onClose();
      }}
    >
      <ScreenHeader
        titleRef={heading}
        title={t("members.addPeople")}
        onBack={busy ? undefined : onClose}
      />
      <form
        onSubmit={(e) => {
          e.preventDefault();
          void add();
        }}
      >
        <PeoplePicker
          people={people}
          selected={selected}
          query={query}
          onQuery={setQuery}
          onToggle={(id) =>
            setSelected((current) =>
              current.includes(id)
                ? current.filter((v) => v !== id)
                : current.length < limit
                  ? [...current, id]
                  : current,
            )
          }
          hideAvatars={hideAvatars}
          disabled={busy}
          limit={limit}
        />
        <div className="new-chat-footer">
          <button
            disabled={
              busy ||
              !selected.length ||
              selected.length > limit ||
              selected.some((id) => !people.some((p) => p.id === id))
            }
          >
            {t("contacts.save")}
          </button>
        </div>
      </form>
    </dialog>
  );
}
