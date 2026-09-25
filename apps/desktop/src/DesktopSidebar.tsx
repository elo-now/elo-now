import {
  useEffect,
  useMemo,
  useRef,
  useState,
  useSyncExternalStore,
} from "react";
import { Phone } from "lucide-react";
import { Icon, NewIndicator } from "./Icon";
import { SearchField } from "./Search";
import { chatActivity, isDirectChat } from "./chatGroups";
import {
  invitationCount,
  notificationCount,
  profileName,
  type Stream,
  type View,
} from "./model";
import type { SettingsPage } from "./UserSettings";
import type { Calls } from "./calls/controller";
import { scopeKey } from "./calls/types";
import { t } from "./i18n";
import { ProfileAvatar } from "./ProfileEditor";

type Props = {
  view: View;
  calls: Calls;
  selected?: string;
  query: string;
  busy: boolean;
  current: "stream" | "contacts" | "chats" | "settings";
  onQuery: (value: string) => void;
  onOpen: (chat: Stream) => void;
  onHome: (page: "stream" | "chats" | "contacts") => void;
  onNewChat: (kind: "chat" | "direct") => void;
  onSettings: (page: SettingsPage) => void;
  onEditProfile: () => void;
  onNavigate: () => void;
  onReminders: () => void;
  onNotifications: () => void;
  onInvitations: () => void;
  onCode: () => void;
  onLock: () => void;
};

function initials(value: string) {
  const words = value.trim().split(/\s+/u).filter(Boolean);
  return (
    (words.length > 1
      ? `${words[0][0]}${words.at(-1)![0]}`
      : words[0]?.slice(0, 2)
    )?.toLocaleUpperCase() || "?"
  );
}

function ChatRow({
  chat,
  identity,
  selected,
  onOpen,
}: {
  chat: Stream;
  identity: string;
  selected?: string;
  onOpen: (chat: Stream) => void;
}) {
  const direct = isDirectChat(chat, identity);
  return (
    <button
      type="button"
      className="desktop-nav-item"
      data-active={selected === chat.stream || undefined}
      onClick={() => onOpen(chat)}
    >
      {direct ? (
        <span className="desktop-dm-avatar" aria-hidden="true">
          {initials(chat.name)}
        </span>
      ) : (
        <Icon name="hash" />
      )}
      <span className="desktop-nav-label">{chat.name}</span>
      {chat.muted && <Icon name="muted" />}
      {(chat.unread_count ?? 0) > 0 && (
        <span
          className="desktop-unread"
          aria-label={t("unread.count", { count: chat.unread_count ?? 0 })}
        >
          {chat.unread_count}
        </span>
      )}
    </button>
  );
}

function MenuButton({
  icon,
  label,
  hasNew = false,
  danger = false,
  onClick,
}: {
  icon: Parameters<typeof Icon>[0]["name"];
  label: string;
  hasNew?: boolean;
  danger?: boolean;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      className="desktop-workspace-menu-item"
      data-danger={danger || undefined}
      onClick={onClick}
    >
      <Icon name={icon} />
      <span>{label}</span>
      {hasNew && <NewIndicator />}
    </button>
  );
}

export function DesktopSidebar({
  view,
  calls,
  selected,
  query,
  busy,
  current,
  onQuery,
  onOpen,
  onHome,
  onNewChat,
  onSettings,
  onEditProfile,
  onNavigate,
  onReminders,
  onNotifications,
  onInvitations,
  onCode,
  onLock,
}: Props) {
  const [menuOpen, setMenuOpen] = useState(false);
  const menu = useRef<HTMLDivElement>(null);
  const callState = useSyncExternalStore(calls.subscribe, calls.getSnapshot);
  const activeSpace = view.spaces?.find(
    (space) => space.id === view.active_space,
  );
  const name = profileName(view) || t("profile.yourProfile");
  const memberCount = new Set(
    view.streams.flatMap((chat) =>
      chat.members.map((member) => member.identity_id),
    ),
  ).size;
  const memberCountLabel = t(
    memberCount === 1 ? "desktop.spaceMember" : "desktop.spaceMembers",
    { count: memberCount },
  );
  const chats = useMemo(
    () =>
      [...view.streams]
        .filter((chat) => !isDirectChat(chat, view.identity))
        .sort((left, right) =>
          left.is_general === right.is_general
            ? chatActivity(right) - chatActivity(left)
            : left.is_general
              ? -1
              : 1,
        ),
    [view],
  );
  const direct = useMemo(
    () =>
      [...view.streams]
        .filter((chat) => isDirectChat(chat, view.identity))
        .sort((left, right) => chatActivity(right) - chatActivity(left)),
    [view],
  );
  const normalized = query.trim().toLocaleLowerCase();
  const matches = (chat: Stream) =>
    !normalized || chat.name.toLocaleLowerCase().includes(normalized);
  const visibleChats = chats.filter(matches);
  const visibleDirect = direct.filter(matches);
  const activeCalls = view.streams.filter(
    (chat) => !!callState.available[scopeKey(chat)],
  );
  const groups = useMemo(() => {
    const output: { id: string; title?: string; chats: Stream[] }[] = [];
    const general = visibleChats.filter((chat) => chat.is_general);
    if (general.length) output.push({ id: "general", chats: general });
    for (const group of view.groups ?? []) {
      const entries = visibleChats.filter(
        (chat) => !chat.is_general && chat.group === group.id,
      );
      if (entries.length)
        output.push({ id: group.id, title: group.name, chats: entries });
    }
    const remaining = visibleChats.filter(
      (chat) =>
        !chat.is_general &&
        !(view.groups ?? []).some((group) => group.id === chat.group),
    );
    if (remaining.length) output.push({ id: "chats", chats: remaining });
    return output;
  }, [visibleChats, view.groups]);

  useEffect(() => {
    if (!menuOpen) return;
    const close = (event: MouseEvent) => {
      if (!menu.current?.contains(event.target as Node)) setMenuOpen(false);
    };
    const escape = (event: KeyboardEvent) => {
      if (event.key === "Escape") setMenuOpen(false);
    };
    document.addEventListener("mousedown", close);
    document.addEventListener("keydown", escape);
    return () => {
      document.removeEventListener("mousedown", close);
      document.removeEventListener("keydown", escape);
    };
  }, [menuOpen]);

  const navigate = (action: () => void) => {
    onNavigate();
    action();
  };
  const act = (action: () => void) => {
    setMenuOpen(false);
    navigate(action);
  };
  return (
    <aside className="desktop-sidebar" aria-label={t("nav.primary")}>
      <div className="desktop-workspace" ref={menu}>
        <button
          type="button"
          className="desktop-workspace-trigger"
          aria-haspopup="menu"
          aria-expanded={menuOpen}
          onClick={() => setMenuOpen((open) => !open)}
        >
          <span>
            <strong>{activeSpace?.name ?? t("spaces.noCurrent")}</strong>
            <small>
              {activeSpace ? memberCountLabel : t("spaces.noCurrent")}
            </small>
          </span>
          <Icon name="more" />
        </button>
        {menuOpen && (
          <div
            className="desktop-workspace-menu"
            aria-label={t("settings.title")}
            onKeyDown={(event) => {
              if (!["ArrowDown", "ArrowUp", "Home", "End"].includes(event.key))
                return;
              event.preventDefault();
              const items = [
                ...event.currentTarget.querySelectorAll<HTMLButtonElement>(
                  "button:not(:disabled)",
                ),
              ];
              const index = items.indexOf(
                document.activeElement as HTMLButtonElement,
              );
              const next =
                event.key === "Home"
                  ? 0
                  : event.key === "End"
                    ? items.length - 1
                    : (index +
                        (event.key === "ArrowDown" ? 1 : -1) +
                        items.length) %
                      items.length;
              items[next]?.focus();
            }}
          >
            <div className="desktop-current-space">
              <Icon name="spaces" />
              <span>
                <strong>{activeSpace?.name ?? t("spaces.noCurrent")}</strong>
                <small>
                  {memberCount > 0 ? memberCountLabel : t("spaces.current")}
                </small>
              </span>
              <button
                type="button"
                className="icon desktop-menu-context-action"
                aria-label={t("spaces.manage")}
                title={t("spaces.manage")}
                onClick={() => act(() => onSettings("spaces"))}
              >
                <Icon name="spaceSwitch" />
              </button>
            </div>
            <div className="desktop-menu-separator" />
            <div className="desktop-workspace-profile">
              <ProfileAvatar name={name} avatar={view.avatar ?? null} />
              <strong>{name}</strong>
              <button
                type="button"
                className="icon desktop-menu-context-action"
                aria-label={t("profile.edit")}
                title={t("profile.edit")}
                disabled={busy}
                onClick={() => {
                  setMenuOpen(false);
                  onEditProfile();
                }}
              >
                <Icon name="edit" />
              </button>
            </div>
            <MenuButton
              icon="qr"
              label={t("invite.myCode")}
              onClick={() => act(onCode)}
            />
            <MenuButton
              icon="clock"
              label={t("reminders.title")}
              onClick={() => act(onReminders)}
            />
            <MenuButton
              icon="bell"
              label={t("invite.page.notifications")}
              hasNew={notificationCount(view) > 0}
              onClick={() => act(onNotifications)}
            />
            <MenuButton
              icon="inbox"
              label={t("invite.page.activity")}
              hasNew={invitationCount(view) > 0}
              onClick={() => act(onInvitations)}
            />
            <MenuButton
              icon="rejected"
              label={t("blocking.title")}
              onClick={() => act(() => onSettings("blocked-users"))}
            />
            <div className="desktop-menu-separator" />
            <MenuButton
              icon="palette"
              label={t("settings.appearance")}
              onClick={() => act(() => onSettings("appearance"))}
            />
            <MenuButton
              icon="settings"
              label={t("settings.title")}
              onClick={() => act(() => onSettings("settings"))}
            />
            <MenuButton
              icon="device"
              label={t("devices.title")}
              onClick={() => act(() => onSettings("devices"))}
            />
            <MenuButton
              icon="lock"
              label={t("recover.settingsTitle")}
              onClick={() => act(() => onSettings("recovery"))}
            />
            <MenuButton
              icon="file"
              label={t("legal.title")}
              onClick={() => act(() => onSettings("licenses"))}
            />
            <div className="desktop-menu-separator" />
            <MenuButton
              icon="power"
              label={t("profile.lock")}
              danger
              onClick={() => act(onLock)}
            />
          </div>
        )}
      </div>

      <div className="desktop-sidebar-search">
        <SearchField
          label={t("chat.search")}
          value={query}
          onChange={onQuery}
        />
      </div>
      <div className="desktop-sidebar-scroll">
        <nav className="desktop-nav-main">
          <button
            type="button"
            className="desktop-nav-item"
            data-active={current === "stream" || undefined}
            onClick={() => navigate(() => onHome("stream"))}
          >
            <Icon
              name="buzz"
              attention={view.streams.some(
                (chat) => (chat.unread_count ?? 0) > 0,
              )}
            />
            <span className="desktop-nav-label">{t("nav.stream")}</span>
          </button>
          <button
            type="button"
            className="desktop-nav-item"
            data-active={current === "contacts" || undefined}
            onClick={() => navigate(() => onHome("contacts"))}
          >
            <Icon name="people" />
            <span className="desktop-nav-label">{t("nav.contacts")}</span>
          </button>
        </nav>

        {activeCalls.length > 0 && (
          <section className="desktop-nav-section">
            <h2>{t("desktop.calls")}</h2>
            {activeCalls.map((chat) => (
              <button
                type="button"
                className="desktop-nav-item"
                key={chat.stream}
                onClick={() => navigate(() => onOpen(chat))}
              >
                <Phone size={17} />
                <span className="desktop-nav-label">{chat.name}</span>
                <span
                  className="desktop-call-live"
                  aria-label={t("desktop.callAvailable")}
                />
              </button>
            ))}
          </section>
        )}

        {
          <section className="desktop-nav-section desktop-chats-heading">
            <div className="desktop-nav-heading">
              <h2>{t("desktop.channels")}</h2>
              <button
                type="button"
                className="icon"
                disabled={busy}
                aria-label={t("channel.new")}
                onClick={() => navigate(() => onNewChat("chat"))}
              >
                <Icon name="plus" />
              </button>
            </div>
          </section>
        }
        {groups.map((section) => (
          <section className="desktop-nav-section" key={section.id}>
            {section.title && <h2>{section.title}</h2>}
            {section.chats.map((chat) => (
              <ChatRow
                key={chat.stream}
                chat={chat}
                identity={view.identity}
                selected={selected}
                onOpen={(chat) => navigate(() => onOpen(chat))}
              />
            ))}
          </section>
        ))}

        <section className="desktop-nav-section">
          <div className="desktop-nav-heading">
            <h2>{t("groups.dms")}</h2>
            <button
              type="button"
              className="icon"
              disabled={busy}
              aria-label={t("chat.newDirect")}
              onClick={() => navigate(() => onNewChat("direct"))}
            >
              <Icon name="plus" />
            </button>
          </div>
          {visibleDirect.map((chat) => (
            <ChatRow
              key={chat.stream}
              chat={chat}
              identity={view.identity}
              selected={selected}
              onOpen={(chat) => navigate(() => onOpen(chat))}
            />
          ))}
        </section>
        {normalized && groups.length === 0 && visibleDirect.length === 0 && (
          <p className="desktop-sidebar-empty">{t("chat.noMatches")}</p>
        )}
      </div>
    </aside>
  );
}
