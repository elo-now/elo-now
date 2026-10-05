import { useEffect, useId, useLayoutEffect, useRef, useState } from "react";
import type { Stream, View } from "./model";
import { t } from "./i18n";
import { Icon } from "./Icon";

export function switchableChats(view: View, query = "") {
  const contexts = new Map(
    view.spaces
      ?.filter((space) => space.status === "joined")
      .map((space) => [space.id, space.name]),
  );
  const words = query.toLocaleLowerCase().trim().split(/\s+/);
  const unique = new Map<string, Stream>();
  for (const chat of view.all_streams ?? view.streams) {
    const context = chat.space_context ?? view.active_space ?? "";
    if (
      chat.forked ||
      (view.spaces?.length && !contexts.has(context)) ||
      !chat.members.some(
        (member) =>
          member.identity_id === view.identity &&
          member.capabilities.includes("READ"),
      )
    )
      continue;
    const label =
      `${chat.name} ${contexts.get(context) ?? ""}`.toLocaleLowerCase();
    if (words.every((word) => label.includes(word)))
      unique.set(`${context}:${chat.space}:${chat.stream}`, {
        ...chat,
        space_context: context,
      });
  }
  return [...unique.values()];
}

export function QuickSwitcher({
  view,
  onClose,
  onOpen,
}: {
  view: View;
  onClose: () => void;
  onOpen: (chat: Stream) => Promise<void>;
}) {
  const dialog = useRef<HTMLDialogElement>(null);
  const input = useRef<HTMLInputElement>(null);
  const [query, setQuery] = useState("");
  const [selected, setSelected] = useState(0);
  const [opening, setOpening] = useState(false);
  const id = useId();
  const chats = switchableChats(view, query).slice(0, 50);
  const index = Math.min(selected, Math.max(0, chats.length - 1));
  useLayoutEffect(() => {
    dialog.current?.showModal();
    input.current?.focus();
    return () => dialog.current?.close();
  }, []);
  useEffect(() => {
    document
      .getElementById(`${id}-${index}`)
      ?.scrollIntoView({ block: "nearest" });
  }, [id, index]);
  const open = async (chat: Stream) => {
    if (opening) return;
    setOpening(true);
    try {
      await onOpen(chat);
      onClose();
    } finally {
      setOpening(false);
    }
  };
  return (
    <dialog
      ref={dialog}
      className="dialog status-dialog quick-switcher"
      aria-label={t("shortcuts.switch")}
      onCancel={(event) => {
        event.preventDefault();
        if (!opening) onClose();
      }}
    >
      <header>
        <h2>{t("shortcuts.switch")}</h2>
        <button
          type="button"
          className="icon"
          onClick={onClose}
          disabled={opening}
          aria-label={t("dialog.close")}
        >
          <Icon name="close" />
        </button>
      </header>
      <input
        ref={input}
        type="search"
        value={query}
        disabled={opening}
        placeholder={t("shortcuts.findConversation")}
        aria-label={t("shortcuts.findConversation")}
        role="combobox"
        aria-expanded="true"
        aria-controls={id}
        aria-autocomplete="list"
        aria-activedescendant={chats.length ? `${id}-${index}` : undefined}
        onChange={(event) => {
          setQuery(event.target.value);
          setSelected(0);
        }}
        onKeyDown={(event) => {
          if (event.nativeEvent.isComposing) return;
          if (["ArrowDown", "ArrowUp"].includes(event.key) && chats.length) {
            event.preventDefault();
            setSelected(
              (index + (event.key === "ArrowDown" ? 1 : -1) + chats.length) %
                chats.length,
            );
          } else if (event.key === "Enter" && chats[index]) {
            event.preventDefault();
            void open(chats[index]);
          }
        }}
      />
      <div
        className="quick-switcher-list"
        id={id}
        role="listbox"
        aria-label={t("shortcuts.switch")}
      >
        {chats.map((chat, row) => (
          <button
            key={`${chat.space_context}:${chat.space}:${chat.stream}`}
            id={`${id}-${row}`}
            type="button"
            role="option"
            aria-selected={row === index}
            disabled={opening}
            tabIndex={-1}
            onClick={() => void open(chat)}
          >
            <span>{chat.name}</span>
            <small>
              {
                view.spaces?.find((space) => space.id === chat.space_context)
                  ?.name
              }
            </small>
          </button>
        ))}
        {!chats.length && <p>{t("shortcuts.noConversations")}</p>}
      </div>
    </dialog>
  );
}

export function KeyboardHelp({
  mac,
  onClose,
}: {
  mac: boolean;
  onClose: () => void;
}) {
  const dialog = useRef<HTMLDialogElement>(null);
  const mod = mac ? "⌘" : "Ctrl";
  useLayoutEffect(() => {
    dialog.current?.showModal();
    return () => dialog.current?.close();
  }, []);
  const rows = [
    ["shortcuts.switch", `${mod} K`],
    ["shortcuts.search", `${mod} F`],
    ["shortcuts.compose", `${mod} N`],
    ["shortcuts.attach", `${mod} O`],
    ["shortcuts.preferences", `${mod} ,`],
    ["shortcuts.nextPrevious", `${mac ? "Option" : "Alt"} ↑ / ↓`],
    ["shortcuts.nextUnread", `${mac ? "Option" : "Alt"} Shift ↑ / ↓`],
    ["shortcuts.send", "Enter"],
    ["shortcuts.newline", "Shift Enter"],
    ["shortcuts.editLatest", "↑"],
    ["shortcuts.close", "Esc"],
    ["shortcuts.help", `${mod} /`],
  ] as const;
  return (
    <dialog
      ref={dialog}
      className="dialog status-dialog keyboard-help"
      aria-label={t("shortcuts.help")}
      onCancel={(event) => {
        event.preventDefault();
        onClose();
      }}
    >
      <header>
        <h2>{t("shortcuts.help")}</h2>
        <button
          type="button"
          className="icon"
          aria-label={t("dialog.close")}
          onClick={onClose}
        >
          <Icon name="close" />
        </button>
      </header>
      <dl>
        {rows.map(([key, shortcut]) => (
          <div key={key}>
            <dt>{t(key)}</dt>
            <dd>
              <kbd>{shortcut}</kbd>
            </dd>
          </div>
        ))}
      </dl>
    </dialog>
  );
}
