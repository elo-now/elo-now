import { useEffect, useRef, useState } from "react";
import { Icon } from "./Icon";
import { EmptyState } from "./EmptyState";
import { t } from "./i18n";
import { chatSections, chatIconName } from "./chatGroups";
import type { ChatGroup, Stream, View } from "./model";

export function ChatGroupsBar({
  view,
  groups,
  selected,
  onSelect,
}: {
  view: View;
  groups: ChatGroup[];
  selected: string;
  onSelect: (id: string) => void;
}) {
  return (
    <div className="chat-groups" role="group" aria-label={t("groups.label")}>
      {[
        { id: "overview", name: t("groups.overview") },
        { id: "dms", name: t("groups.dms") },
        ...groups,
      ].map((group) => (
        <button
          key={group.id}
          type="button"
          aria-pressed={selected === group.id}
          aria-label={group.name}
          title={group.name}
          onClick={(event) => {
            onSelect(group.id);
            event.currentTarget.scrollIntoView({
              block: "nearest",
              inline: "nearest",
            });
          }}
        >
          {group.id === "overview" ? <Icon name="conversations" /> : group.name}
          {chatSections(view, group.id).some((section) =>
            section.chats.some((chat) => (chat.unread_count ?? 0) > 0),
          ) && <span className="unread-dot" aria-label={t("unread.group")} />}
        </button>
      ))}
    </div>
  );
}

export function ChatList({
  view,
  filter,
  query = "",
  selected,
  onOpen,
}: {
  view: View;
  filter: string;
  query?: string;
  selected?: string;
  onOpen: (chat: Stream) => void;
}) {
  const sections = chatSections(view, filter, query);
  const empty = sections.every((section) => section.chats.length === 0);
  return (
    <>
      {sections.map((section, index) => (
        <section
          className="chat-list-section"
          data-first={index === 0}
          key={section.id}
        >
          {section.title && (
            <h3 className="chat-section-heading">{t(section.title)}</h3>
          )}
          <nav
            className="channel-list"
            aria-label={section.title ? t(section.title) : t("channel.heading")}
          >
            {section.chats.map((chat) => (
              <button
                key={chat.stream}
                className={selected === chat.stream ? "active" : ""}
                onClick={() => onOpen(chat)}
              >
                <ChatGlyph chat={chat} identity={view.identity} />
                <span className="channel-list-copy">
                  <strong>
                    {chat.name}
                    {chat.forked ? " !" : ""}
                  </strong>
                  <small className="mobile-only">
                    {chat.rows.length
                      ? chat.rows.at(-1)?.body.kind === "chat.message"
                        ? chat.rows.at(-1)?.body.payload?.text
                        : t("channel.attachment")
                      : t("channel.noMessages")}
                  </small>
                </span>
                {chat.muted && (
                  <span
                    className="channel-muted"
                    role="img"
                    aria-label={t("channel.muted")}
                  >
                    <Icon name="muted" />
                  </span>
                )}
                {(chat.unread_count ?? 0) > 0 && (
                  <span
                    className="mobile-only unread-count"
                    aria-label={t("unread.count", {
                      count: chat.unread_count ?? 0,
                    })}
                  >
                    {chat.unread_count}
                  </span>
                )}
                <span className="mobile-only channel-next">
                  <Icon name="next" />
                </span>
              </button>
            ))}
          </nav>
        </section>
      ))}
      {empty && (
        <EmptyState
          message={t(
            query.trim()
              ? "chat.noMatches"
              : filter === "dms"
                ? "groups.noDms"
                : "groups.empty",
          )}
        />
      )}
    </>
  );
}

function ChatGlyph({ chat, identity }: { chat: Stream; identity: string }) {
  const icon = chatIconName(chat, identity);
  return (
    <span
      className="channel-glyph"
      role="img"
      aria-label={t(
        icon === "people"
          ? "chat.groupDirect"
          : icon === "person"
            ? "chat.direct"
            : "chat.named",
      )}
    >
      <Icon name={icon} />
    </span>
  );
}

export function ChatGroupField({
  groups,
  value,
  disabled,
  onChange,
  onCreate,
  onEditing,
  showLabel = true,
}: {
  groups: ChatGroup[];
  value: string;
  disabled: boolean;
  onChange: (id: string) => void;
  onCreate: (name: string) => Promise<ChatGroup | undefined>;
  onEditing: (editing: boolean) => void;
  showLabel?: boolean;
}) {
  const [creating, setCreating] = useState(false);
  const [name, setName] = useState("");
  const input = useRef<HTMLInputElement>(null);
  const edit = (active: boolean) => {
    setCreating(active);
    onEditing(active);
  };
  useEffect(() => {
    if (creating) input.current?.focus();
  }, [creating]);
  const create = async () => {
    if (disabled || !name.trim()) return;
    const group = await onCreate(name);
    if (group) {
      onChange(group.id);
      setName("");
      edit(false);
    }
  };
  return (
    <div className="chat-group-field">
      {creating ? (
        <>
          <label htmlFor="new-group-name">{t("groups.new")}</label>
          <div className="chat-group-row">
            <input
              ref={input}
              id="new-group-name"
              value={name}
              disabled={disabled}
              placeholder={t("field.channelName")}
              autoComplete="off"
              onChange={(event) => setName(event.target.value)}
              onKeyDown={(event) => {
                if (event.key === "Enter") {
                  event.preventDefault();
                  void create();
                }
                if (event.key === "Escape") {
                  event.preventDefault();
                  edit(false);
                }
              }}
            />
            <button
              type="button"
              disabled={disabled || !name.trim()}
              onClick={() => void create()}
            >
              {t("action.createSpace.submit")}
            </button>
            <button
              type="button"
              className="secondary group-cancel"
              disabled={disabled}
              aria-label={t("dialog.close")}
              onClick={() => edit(false)}
            >
              <Icon name="close" />
            </button>
          </div>
        </>
      ) : (
        <>
          {showLabel && <label htmlFor="chat-group">{t("groups.field")}</label>}
          <div className="chat-group-row">
            <select
              id="chat-group"
              aria-label={showLabel ? undefined : t("groups.field")}
              value={value}
              disabled={disabled}
              onChange={(event) => onChange(event.target.value)}
            >
              <option value="">{t("groups.none")}</option>
              {groups.map((group) => (
                <option key={group.id} value={group.id}>
                  {group.name}
                </option>
              ))}
            </select>
            <button
              type="button"
              className="secondary"
              disabled={disabled}
              aria-label={t("groups.new")}
              onClick={() => edit(true)}
            >
              <Icon name="plus" />
            </button>
          </div>
        </>
      )}
    </div>
  );
}
