import { useEffect, useMemo, useRef, useState } from "react";
import { t } from "./i18n";
import { Icon } from "./Icon";
import { ScreenHeader } from "./ScreenHeader";
import { ChatGroupField } from "./ChatOrganization";
import { useToast, useToastHost } from "./Toast";
import { directName, knownPeople } from "./directMessages";
import type { ChatGroup, View } from "./model";
import "./newChat.css";
import { PeoplePicker } from "./PeoplePicker";

export function NewChat({
  view,
  initialKind,
  initialGroup,
  initialPeople = [],
  hideAvatars,
  onClose,
  onCreate,
  onCreateGroup,
}: {
  view: View;
  initialKind: "chat" | "direct";
  initialGroup: string;
  initialPeople?: string[];
  hideAvatars: boolean;
  onClose: () => void;
  onCreate: (
    request: Record<string, unknown>,
    invite: boolean,
  ) => Promise<void>;
  onCreateGroup: (name: string) => Promise<ChatGroup | undefined>;
}) {
  const dialog = useRef<HTMLDialogElement>(null);
  const heading = useRef<HTMLHeadingElement>(null);
  useToastHost(dialog);
  const { reportError } = useToast();
  const [kind, setKind] = useState(initialKind);
  const [name, setName] = useState("");
  const [group, setGroup] = useState(initialGroup);
  const [editingGroup, setEditingGroup] = useState(false);
  const [query, setQuery] = useState("");
  const [selected, setSelected] = useState<string[]>(initialPeople);
  const [busy, setBusy] = useState(false);
  const pending = useRef(false);
  const attempt = useRef({ key: "", id: "" });
  const people = useMemo(() => knownPeople(view), [view]);
  const chosen = people.filter((person) => selected.includes(person.id));
  useEffect(() => {
    const element = dialog.current;
    element?.showModal();
    heading.current?.focus({ preventScroll: true });
    return () => element?.close();
  }, []);
  const toggle = (id: string) =>
    setSelected((current) =>
      current.includes(id)
        ? current.filter((value) => value !== id)
        : current.length < 999
          ? [...current, id]
          : current,
    );
  const create = async () => {
    if (pending.current || editingGroup) return;
    pending.current = true;
    setBusy(true);
    try {
      if (chosen.length) {
        if (!chosen.length || chosen.length !== selected.length) return;
        const generated =
          kind === "direct" ? directName(view, chosen) : name.trim();
        const ids = chosen.map((person) => person.id).sort();
        const key = JSON.stringify([kind, group, generated, ids]);
        if (attempt.current.key !== key)
          attempt.current = {
            key,
            id: crypto.randomUUID().replaceAll("-", ""),
          };
        await onCreate(
          {
            expected_identity: view.identity,
            expected_space: view.active_space,
            op:
              kind === "direct" && chosen.length === 1
                ? "contact_open"
                : "contact_create_chat",
            identity: chosen[0].id,
            request_id: attempt.current.id,
            people: ids,
            chat_kind: kind,
            group: kind === "chat" ? group : "",
            name: generated,
          },
          false,
        );
      } else {
        await onCreate(
          {
            expected_identity: view.identity,
            expected_space: view.active_space,
            op: "create_chat",
            chat_kind: kind,
            name: name.trim(),
            ...(kind === "chat" ? { group } : {}),
          },
          false,
        );
      }
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
      className="dialog new-chat-dialog"
      aria-label={t(
        kind === "direct" ? "chat.newDirect" : "action.createSpace.title",
      )}
      onCancel={(event) => {
        event.preventDefault();
        if (!busy) onClose();
      }}
    >
      <ScreenHeader
        titleRef={heading}
        title={t(
          kind === "direct" ? "chat.newDirect" : "action.createSpace.title",
        )}
        onBack={busy ? undefined : onClose}
      />
      <form
        onSubmit={(event) => {
          event.preventDefault();
          void create();
        }}
      >
        <div
          className="new-chat-switch chat-kind-picker"
          role="group"
          aria-label={t("chat.kind")}
        >
          {(["direct", "chat"] as const).map((value) => (
            <button
              key={value}
              type="button"
              className="secondary"
              aria-pressed={kind === value}
              disabled={busy}
              onClick={() => {
                setKind(value);
                setEditingGroup(false);
              }}
            >
              <Icon name={value === "chat" ? "hash" : "person"} />
              {t(value === "chat" ? "chat.named" : "chat.direct")}
            </button>
          ))}
        </div>
        {kind === "chat" && (
          <div className="new-chat-fields">
            <label>
              {t("field.channelName")}
              <input
                value={name}
                onChange={(event) => setName(event.target.value)}
                disabled={busy}
                autoComplete="off"
                maxLength={120}
              />
            </label>
            <ChatGroupField
              groups={view.groups ?? []}
              showLabel
              value={group}
              disabled={busy}
              onChange={setGroup}
              onEditing={setEditingGroup}
              onCreate={onCreateGroup}
            />
          </div>
        )}
        <PeoplePicker
          people={people}
          selected={selected}
          query={query}
          onQuery={setQuery}
          onToggle={toggle}
          hideAvatars={hideAvatars}
          disabled={busy}
        />
        <div className="new-chat-footer">
          <button
            disabled={
              busy ||
              editingGroup ||
              (kind === "direct"
                ? !chosen.length || chosen.length !== selected.length
                : !name.trim())
            }
          >
            {busy ? t("dialog.verifying") : t("action.createSpace.submit")}
          </button>
        </div>
      </form>
    </dialog>
  );
}
