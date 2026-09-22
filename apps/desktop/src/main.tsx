import { RefreshButton } from "./RefreshButton";
import { canReadVisibleMessages } from "./messageReadVisibility";
import { PageSurface, useDesktopLayout } from "./PageSurface";
import { ProfileEditor, type ProfilePresentation } from "./ProfileEditor";
import { useCalls, CallButton, CallSurface } from "./calls/CallUI";
import { t, messageDayKey, formatMessageDay, formatFileSize } from "./i18n";
import React, { useEffect, useRef, useState } from "react";
import { createRoot } from "react-dom/client";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import {
  recordTimestamp,
  profileName,
  notificationCount,
  invitationCount,
  senderName,
  isNewMessage,
  messageCreatedAt,
  beginsNewMessageSection,
  markVisibleMessagesRead,
  type View,
  type ChatGroup,
} from "./model";
import { ChatGroupsBar, ChatList, ChatGroupField } from "./ChatOrganization";
import { isDirectChat } from "./chatGroups";
import { NewChat } from "./NewChat";
import { Contacts } from "./Contacts";
import { applyTheme, readTheme, type Theme } from "./theme";
import "./style.css";
import { Spaces, CurrentSpace, SpaceSetup } from "./Spaces";
import "./mobile.css";
import "./messageStream.css";
import "./messageThreads.css";
import "./desktop.css";
import { Icon, NewIndicator } from "./Icon";
import { ActionDialog } from "./ActionDialog";
import { FloatingSearch, SearchField } from "./Search";
import { ConversationTools } from "./ConversationTools";
import { EmptyState } from "./EmptyState";
import { ProfileGate } from "./ProfileGate";
import { BlockedUsers } from "./BlockedUsers";
import { ServiceRequests } from "./ServiceRequests";
import { ToastProvider, useToast } from "./Toast";
import { AccountDeletionNotice } from "./AccountDeletion";
import { MobileNavigation } from "./MobileNavigation";
import type { Stream } from "./model";
import {
  MessageActionsProvider,
  type MessageCollection,
} from "./MessageActions";
import { MessageContent } from "./MessageContent";
import { reminderProfileMatches, watchReminderActions } from "./reminders";
import { ComposerInput } from "./ComposerInput";
import { ThreadView } from "./ThreadView";
import { MessageBubble, ThreadLink } from "./MessageBubble";
import { UnavailableMessage } from "./UnavailableMessage";
import { AttachmentButton, type AttachmentProgress } from "./AttachmentButton";
import {
  chatTimeline,
  findThread,
  replyRoot,
  type MessageRow,
} from "./messageThreads";
import { MessageStream } from "./MessageStream";
import { unreadStreamEntries, type StreamEntry } from "./streamFeed";
import { ScreenHeader } from "./ScreenHeader";
import { Members } from "./Members";
import { DesktopSidebar } from "./DesktopSidebar";
import { WindowChrome } from "./WindowChrome";
import { AddPeople } from "./AddPeople";
import { InvitationFlow, type InvitationRoute } from "./InvitationFlow";
import { useMessageHistory } from "./useMessageHistory";
import type { HistoryPage } from "./messageHistory";
import { useLiveSync } from "./useLiveSync";
import { usePushNotifications } from "./usePushNotifications";
import { acceptView, type SyncResult } from "./liveSync";
import { incomingMessages, newMessageInChat } from "./messageNotifications";
import { getCurrent, onOpenUrl } from "@tauri-apps/plugin-deep-link";
import { EXCHANGE_PREFIX } from "./invitationTransport";
import { PullToRefresh } from "./PullToRefresh";
import {
  MessageStatusDialog,
  type MessageStatusSelection,
} from "./MessageStatus";
import { readViewMode, saveViewMode, type ViewMode } from "./viewMode";
import { useViewport } from "./useViewport";
import { useInputModality } from "./useInputModality";
import { useSystemBack } from "./useSystemBack";
import { UserSettings, type SettingsPage } from "./UserSettings";
import {
  applyVisualPreferences,
  readPreferences,
  savePreferences,
  type UserPreferences,
} from "./preferences";
import { readSystemTextScale } from "./systemScale";
import {
  biometricName,
  enableBiometricUnlock,
  markBiometricOfferHandled,
  readBiometricState,
  shouldOfferBiometricUnlock,
  type BiometricProfile,
} from "./biometric";

type SelectedAttachment = {
  path: string;
  name: string;
  size_bytes: number;
};

type AttachmentTransferState = AttachmentProgress & {
  transferId: string;
  kind: "upload" | "download";
  record?: string;
};

const ATTACHMENT_TRANSFER_CANCELLED = "Attachment transfer cancelled.";

const initialTheme = readTheme();
const initialPreferences = readPreferences();
applyTheme(initialTheme);
applyVisualPreferences(initialPreferences, initialTheme);

function LogoutDialog({
  open,
  busy,
  onCancel,
  onConfirm,
}: {
  open: boolean;
  busy: boolean;
  onCancel: () => void;
  onConfirm: () => void;
}) {
  const dialog = useRef<HTMLDialogElement>(null);
  useEffect(() => {
    if (open) dialog.current?.showModal();
    else dialog.current?.close();
  }, [open]);
  if (!open) return null;
  return (
    <dialog
      ref={dialog}
      className="dialog logout-dialog"
      aria-labelledby="logout-dialog-title"
      onCancel={(event) => {
        event.preventDefault();
        onCancel();
      }}
    >
      <button
        className="icon close"
        type="button"
        aria-label={t("dialog.close")}
        onClick={onCancel}
      >
        <Icon name="close" />
      </button>
      <h2 id="logout-dialog-title">{t("profile.logoutTitle")}</h2>
      <p>{t("profile.logoutHelp")}</p>
      <div className="dialog-buttons">
        <button className="secondary" type="button" onClick={onCancel}>
          {t("dialog.cancel")}
        </button>
        <button
          className="danger-action"
          type="button"
          disabled={busy}
          onClick={onConfirm}
        >
          {t("profile.lock")}
        </button>
      </div>
    </dialog>
  );
}

function BiometricOfferDialog({
  name,
  busy,
  onDecline,
  onAccept,
}: {
  name: string;
  busy: boolean;
  onDecline: () => void;
  onAccept: () => void;
}) {
  const dialog = useRef<HTMLDialogElement>(null);
  useEffect(() => {
    dialog.current?.showModal();
    return () => dialog.current?.close();
  }, []);
  return (
    <dialog
      ref={dialog}
      className="dialog biometric-offer-dialog"
      aria-labelledby="biometric-offer-title"
      onCancel={(event) => {
        event.preventDefault();
        if (!busy) onDecline();
      }}
    >
      <h2 id="biometric-offer-title">{t("biometric.offerTitle", { name })}</h2>
      <p>{t("biometric.offerHelp", { name })}</p>
      <div className="dialog-buttons">
        <button
          className="secondary"
          type="button"
          disabled={busy}
          onClick={onDecline}
        >
          {t("biometric.notNow")}
        </button>
        <button type="button" disabled={busy} onClick={onAccept}>
          {t("biometric.use", { name })}
        </button>
      </div>
    </dialog>
  );
}

function Appearance({
  theme,
  onChange,
  compact = false,
}: {
  theme: Theme;
  onChange: (theme: Theme) => void;
  compact?: boolean;
}) {
  if (compact) {
    const label = t(
      theme === "light" ? "theme.switchToDark" : "theme.switchToLight",
    );
    return (
      <button
        className="icon theme-toggle"
        type="button"
        aria-label={label}
        title={label}
        onClick={() => onChange(theme === "light" ? "dark" : "light")}
      >
        <Icon name={theme === "light" ? "moon" : "sun"} />
      </button>
    );
  }
  return (
    <div className="appearance" role="group" aria-label={t("theme.label")}>
      {(["light", "dark"] as const).map((value) => (
        <button
          key={value}
          type="button"
          aria-pressed={theme === value}
          onClick={() => onChange(value)}
        >
          {t(value === "light" ? "theme.light" : "theme.dark")}
        </button>
      ))}
    </div>
  );
}
type Field = { key: string; label: string };
type Action = {
  id: string;
  title: string;
  description: string;
  global?: boolean;
  fields: Field[];
};
const f = (key: string, label: string): Field => ({ key, label });
const actions: Action[] = [
  {
    id: "create_chat",
    title: t("action.createSpace.title"),
    global: true,
    description: t("action.createSpace.description"),
    fields: [f("name", t("field.channelName"))],
  },
  {
    id: "remove_member",
    title: t("action.removeMember.title"),
    description: t("action.removeMember.description"),
    fields: [f("fingerprint", t("field.removedIdentity"))],
  },
  {
    id: "create_group",
    title: t("groups.add"),
    description: "",
    global: true,
    fields: [f("name", t("field.channelName"))],
  },
  {
    id: "set_chat_group",
    title: t("groups.change"),
    description: "",
    fields: [],
  },
];
function App() {
  useViewport();
  useInputModality();
  useSystemBack();
  const {
    showError: setError,
    reportError,
    onInvalid,
    showMessage,
    clearMessages,
    notify,
  } = useToast();
  const [mode, setMode] = useState<ViewMode>(readViewMode);
  const [mobile, setMobile] = useState(false);
  useEffect(() => {
    let alive = true;
    void invoke<{ mobile: boolean }>("profile_environment")
      .then((value) => {
        if (alive) setMobile(value.mobile);
      })
      .catch(() => {});
    return () => {
      alive = false;
    };
  }, []);
  // Native desktop windows cannot be narrower than 820 px. Using the window
  // width keeps the shell deterministic even when a WebView reports a mobile
  // compatible user agent.
  const desktopLayout = useDesktopLayout();
  const [activeDemoProfile, setActiveDemoProfile] = useState<string>();
  const [homeTab, setHomeTab] = useState<"stream" | "chats" | "contacts">(
    "chats",
  );
  const [messageTarget, setMessageTarget] = useState<{
    id: string;
    key: number;
  }>();
  const messageTargetSerial = useRef(0);
  const [newMessage, setNewMessage] = useState<{
    scope: string;
    id: string;
    key: number;
  }>();
  const [preparedHistory, setPreparedHistory] = useState<HistoryPage>();
  const [conversationOpen, setConversationOpen] = useState(false);
  const [threadRoot, setThreadRoot] = useState<string>();
  const [threadTarget, setThreadTarget] = useState<{
    id: string;
    key: number;
  }>();
  const [threadComposeRevision, setThreadComposeRevision] = useState(0);
  const [threadDrafts, setThreadDrafts] = useState<Record<string, string>>({});
  const [membersOpen, setMembersOpen] = useState(false);
  const [addPeopleOpen, setAddPeopleOpen] = useState(false);
  const [newChat, setNewChat] = useState<{
    kind: "chat" | "direct";
    group: string;
    people?: string[];
  } | null>(null);
  const [invitationRoute, setInvitationRoute] =
    useState<InvitationRoute | null>(null);
  useEffect(() => {
    let alive = true;
    let dispose: (() => void) | undefined;
    const accept = (urls: string[]) => {
      const link = urls.find(
        (url) =>
          url.startsWith(EXCHANGE_PREFIX) && url.length <= 2 * 1024 * 1024,
      );
      if (alive && link)
        setInvitationRoute({ page: "scan", link, unscoped: true });
    };
    void onOpenUrl(accept)
      .then((fn) => {
        if (alive) dispose = fn;
        else fn();
      })
      .catch(reportError);
    void getCurrent()
      .then((urls) => {
        if (urls) accept(urls);
      })
      .catch(reportError);
    return () => {
      alive = false;
      dispose?.();
    };
  }, []);
  const [ownSendRevision, setOwnSendRevision] = useState(0);
  const [sessionUnread, setSessionUnread] = useState<Set<string>>(
    () => new Set(),
  );
  const [logoutOpen, setLogoutOpen] = useState(false);
  const [messageUnavailableOpen, setMessageUnavailableOpen] = useState(false);
  const [biometricOfferName, setBiometricOfferName] = useState("");
  const [biometricOfferPending, setBiometricOfferPending] = useState(false);
  const authenticationEpoch = useRef(0);
  const biometricOfferCredential = useRef<{
    password: string;
    demoProfile?: string;
    profile?: BiometricProfile;
  }>({
    password: "",
    demoProfile: undefined as string | undefined,
  });
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [desktopProfileEditing, setDesktopProfileEditing] = useState(false);
  const [headerMenu, setHeaderMenu] = useState<{
    anchor: DOMRect;
    conversation: boolean;
  } | null>(null);
  const [identifiersOpen, setIdentifiersOpen] = useState(false);
  const [settingsPage, setSettingsPage] = useState<SettingsPage>("actions");
  const openSettings = (page: SettingsPage = "actions") => {
    setCollection(null);
    setAddPeopleOpen(false);
    setAction(null);
    setHeaderMenu(null);
    setInvitationRoute(null);
    setNewChat(null);
    setMembersOpen(false);
    setThreadRoot(undefined);
    setSettingsPage(page);
    setSettingsOpen(true);
  };
  const [pendingAttachment, setPendingAttachment] =
    useState<SelectedAttachment | null>(null);
  const [attachmentTransfer, setAttachmentTransfer] =
    useState<AttachmentTransferState>();
  const uploadingAttachment = attachmentTransfer?.kind === "upload";
  const downloadingAttachment =
    attachmentTransfer?.kind === "download"
      ? attachmentTransfer.record
      : undefined;
  useEffect(() => {
    let disposed = false;
    let unlisten: (() => void) | undefined;
    void listen<{
      transfer_id: string;
      received: number;
      total: number;
    }>("attachment-transfer-progress", ({ payload }) => {
      setAttachmentTransfer((current) =>
        current?.transferId === payload.transfer_id
          ? {
              ...current,
              received: payload.received,
              total: payload.total,
            }
          : current,
      );
    })
      .then((stop) => {
        if (disposed) stop();
        else unlisten = stop;
      })
      .catch(reportError);
    return () => {
      disposed = true;
      unlisten?.();
    };
  }, []);
  const [attachmentMenu, setAttachmentMenu] = useState<DOMRect | null>(null);
  const mediaPicker = useRef<HTMLInputElement>(null);
  const cameraPicker = useRef<HTMLInputElement>(null);
  const [collection, setCollection] = useState<MessageCollection | null>(null);
  const manuallyUnread = useRef(new Set<string>());
  const [reminderClock, setReminderClock] = useState(Date.now());
  useEffect(() => {
    const timer = setInterval(() => setReminderClock(Date.now()), 30_000);
    return () => clearInterval(timer);
  }, []);
  const [messageStatus, setMessageStatus] =
    useState<MessageStatusSelection | null>(null);
  const settingsRef = useRef<HTMLElement>(null);
  const moreRef = useRef<HTMLButtonElement>(null);
  const changeMode = (value: ViewMode) => {
    saveViewMode(value);
    setMode(value);
  };
  useEffect(() => {
    if (settingsOpen) settingsRef.current?.focus();
    const key = (e: KeyboardEvent) => {
      if (
        e.key === "Escape" &&
        settingsOpen &&
        !desktopProfileEditing &&
        !document.querySelector("dialog[open]")
      ) {
        if (!["actions", "profile"].includes(settingsPage)) {
          setSettingsPage("profile");
        } else {
          setSettingsOpen(false);
          moreRef.current?.focus();
        }
      }
    };
    document.addEventListener("keydown", key);
    return () => document.removeEventListener("keydown", key);
  }, [settingsOpen, settingsPage, desktopProfileEditing]);
  const [theme, setTheme] = useState<Theme>(initialTheme);
  const [preferences, setPreferences] =
    useState<UserPreferences>(initialPreferences);
  const [systemScale, setSystemScale] = useState(1);
  const [, setEnvironmentRevision] = useState(0);
  const changePreferences = (value: UserPreferences) => {
    savePreferences(value);
    applyVisualPreferences(value, theme, systemScale);
    setPreferences(value);
  };
  const changeTheme = (value: Theme) => {
    applyTheme(value);
    applyVisualPreferences(preferences, value, systemScale);
    setTheme(value);
  };
  useEffect(() => {
    const update = () =>
      void readSystemTextScale().then((value) => {
        setSystemScale(value);
        setEnvironmentRevision((revision) => revision + 1);
        applyVisualPreferences(preferences, theme, value);
      });
    update();
    window.addEventListener("focus", update);
    document.addEventListener("visibilitychange", update);
    return () => {
      window.removeEventListener("focus", update);
      document.removeEventListener("visibilitychange", update);
    };
  }, [preferences, theme]);
  const [view, storeView] = useState<View | null>(null),
    [selected, setSelected] = useState(""),
    [busy, setBusy] = useState(false),
    [syncSummary, setSyncSummary] = useState(""),
    [text, setText] = useState(""),
    [action, setAction] = useState<Action | null>(null),
    [values, setValues] = useState<Record<string, string | boolean>>({});
  const setView: React.Dispatch<React.SetStateAction<View | null>> = (next) =>
    storeView((current) =>
      typeof next === "function"
        ? next(current)
        : next
          ? acceptView(current, next)
          : null,
    );
  const currentView = useRef(view);
  currentView.current = view;
  useEffect(() => {
    setDesktopProfileEditing(false);
  }, [view?.identity, view?.active_space, desktopLayout]);
  const saveProfile = async ({ name, avatar }: ProfilePresentation) => {
    setBusy(true);
    try {
      const result = await invoke<{ view: View }>("operate", {
        request: { op: "set_profile_details", name, avatar },
      });
      setView(result.view);
    } finally {
      setBusy(false);
    }
  };
  useEffect(() => {
    setText("");
    setThreadDrafts({});
    setAction(null);

    setNewChat(null);
    setAddPeopleOpen(false);
  }, [view?.active_space]);
  const [reminderProfile, setReminderProfile] = useState<string>();
  useEffect(() => {
    if (!mobile) return;
    let alive = true;
    let dispose: (() => void) | undefined;
    void watchReminderActions((profile) => {
      if (alive) setReminderProfile(profile);
    })
      .then((stop) => {
        if (alive) dispose = stop;
        else stop();
      })
      .catch(reportError);
    return () => {
      alive = false;
      dispose?.();
    };
  }, [mobile]);
  useEffect(() => {
    if (!view || !reminderProfile) return;
    let alive = true;
    void reminderProfileMatches(reminderProfile, view.identity).then(
      (matches) => {
        if (!alive || !matches) return;
        setReminderProfile(undefined);
        setInvitationRoute(null);
        setNewChat(null);
        setMembersOpen(false);
        setThreadRoot(undefined);
        setConversationOpen(false);
        setSettingsPage("profile");
        setSettingsOpen(true);
        setCollection({ kind: "reminders" });
      },
    );
    return () => {
      alive = false;
    };
  }, [reminderProfile, view?.identity]);
  const [chatFilter, setChatFilter] = useState("overview");
  const [chatQuery, setChatQuery] = useState("");
  const [messageQuery, setMessageQuery] = useState("");
  useEffect(() => {
    setThreadRoot(undefined);
    setThreadDrafts({});
  }, [view?.identity]);
  const threadActive =
    !!threadRoot &&
    !settingsOpen &&
    !membersOpen &&
    !invitationRoute &&
    !newChat &&
    !(desktopLayout && (collection || addPeopleOpen || action));
  const streamActive =
    homeTab === "stream" &&
    !conversationOpen &&
    !settingsOpen &&
    !membersOpen &&
    !invitationRoute &&
    !newChat &&
    !(desktopLayout && (collection || addPeopleOpen || action));
  const chatsActive =
    homeTab === "chats" &&
    !conversationOpen &&
    !settingsOpen &&
    !invitationRoute &&
    !newChat &&
    !(desktopLayout && (collection || addPeopleOpen || action));
  const contactsActive =
    homeTab === "contacts" &&
    !conversationOpen &&
    !settingsOpen &&
    !invitationRoute &&
    !newChat &&
    !(desktopLayout && (collection || addPeopleOpen || action));
  const messagesActive =
    (conversationOpen || (!mobile && homeTab === "chats")) &&
    !threadActive &&
    !settingsOpen &&
    !membersOpen &&
    !invitationRoute &&
    !newChat &&
    !(desktopLayout && (collection || addPeopleOpen || action));
  useEffect(() => {
    setMessageQuery("");
  }, [view?.identity, selected, conversationOpen]);
  useEffect(() => {
    if (!desktopLayout) return;
    const shortcut = (event: KeyboardEvent) => {
      if (
        !(event.metaKey || event.ctrlKey) ||
        event.altKey ||
        document.querySelector("dialog[open]")
      )
        return;
      const selector =
        event.key.toLowerCase() === "k"
          ? ".desktop-sidebar .search-input"
          : event.key.toLowerCase() === "f" &&
              messagesActive &&
              !desktopProfileEditing
            ? ".conversation .search-input"
            : undefined;
      const field = selector
        ? document.querySelector<HTMLInputElement>(selector)
        : null;
      if (field) {
        event.preventDefault();
        field.focus();
        field.select();
      }
    };
    document.addEventListener("keydown", shortcut);
    return () => document.removeEventListener("keydown", shortcut);
  }, [desktopLayout, messagesActive, desktopProfileEditing]);
  const [groupDraft, setGroupDraft] = useState(false);
  const streamSummary =
    view?.streams.find((s) => s.stream === selected) ?? view?.streams[0];
  const history = useMessageHistory(
    view,
    streamSummary,
    messagesActive || threadActive,
    messageQuery,
    undefined,
    messageTarget?.id,
    preparedHistory,
  );
  // A thread has its own history window. Opening it must not replace the
  // conversation's loaded pages, search results or scroll position.
  const threadHistory = useMessageHistory(
    view,
    streamSummary,
    threadActive,
    "",
    threadRoot,
    threadTarget?.id,
    preparedHistory,
  );
  const visibleHistory = threadActive ? threadHistory : history;
  const conversationScope = JSON.stringify([
    view?.identity,
    view?.active_space,
    streamSummary?.space,
    streamSummary?.stream,
  ]);
  const messageScope = JSON.stringify([
    view?.identity,
    view?.active_space,
    streamSummary?.space,
    streamSummary?.stream,
    messagesActive,
    threadActive ? threadRoot : undefined,
  ]);
  const arrival = newMessage?.scope === messageScope ? newMessage : undefined;
  const stream =
    streamSummary && history.enabled
      ? {
          ...streamSummary,
          rows: history.rows.filter(
            (row) =>
              !view?.blocked_users?.some(
                (p) => p.identity === row.body.issuer_identity,
              ),
          ),
        }
      : streamSummary;
  const calls = useCalls(view, preferences.callRingtone);
  const personalDM =
    stream?.chat_kind === "direct" && stream.members.length === 2;
  const awaitingDirect =
    !!stream?.direct_invitation &&
    !stream.members.some((member) => member.identity_id !== view?.identity);
  const timeline = chatTimeline(stream?.rows ?? [], messageQuery);
  const messageRows = timeline.map((entry) => entry.row);
  const firstMessageIndex = timeline.findIndex((entry) => !entry.placeholder);
  const selectedThread =
    threadRoot && stream
      ? findThread(
          threadHistory.rows.filter(
            (row) =>
              !view?.blocked_users?.some(
                (person) => person.identity === row.body.issuer_identity,
              ),
          ),
          threadRoot,
        )
      : undefined;
  const threadDraftKey = `${stream?.space}:${stream?.stream}:${threadRoot}`;
  const perform = async (fn: () => Promise<void>) => {
    setBusy(true);
    setError("");
    setSyncSummary("");
    try {
      await fn();
    } catch (e) {
      reportError(e);
    } finally {
      setBusy(false);
    }
  };
  useEffect(() => {
    manuallyUnread.current.clear();
  }, [selected, conversationOpen, view?.identity]);
  const markUnread = async (chat: Stream, row: Stream["rows"][number]) => {
    manuallyUnread.current.add(row.id);
    try {
      await call({
        op: "mark_unread",
        space: chat.space,
        stream: chat.stream,
        records: [row.id],
      });
      setSessionUnread((previous) => new Set([...previous, row.id]));
    } catch (error) {
      manuallyUnread.current.delete(row.id);
      throw error;
    }
  };
  const call = async (request: Record<string, unknown>) => {
    const r = await invoke<{ view?: View; result?: unknown; stream?: string }>(
      "operate",
      {
        request: {
          ...request,
          expected_identity: view?.identity,
          expected_space: view?.active_space,
        },
      },
    );
    if (request.op === "sync" || request.op === "sync_live")
      receiveSync(r as SyncResult);
    else if (r.view) setView(r.view);
    if (
      request.op === "send" ||
      request.op === "message_action" ||
      request.op === "attachment_upload"
    )
      requestSync();
    if (request.op === "remove_member") requestSync(true);
    if (request.op === "set_user_blocked") {
      // A push/search target may now be hidden. Reopen the visible history
      // instead of repeatedly requesting a page around the blocked record.
      setMessageTarget(undefined);
      setThreadTarget(undefined);
      setNewMessage(undefined);
      setPreparedHistory(undefined);
      clearMessages();
      requestSync(true);
    }
    return r;
  };
  const chooseAttachment = () =>
    void perform(async () => {
      const selected = await invoke<SelectedAttachment | null>(
        "choose_attachment",
      );
      if (!selected) return;
      if (pendingAttachment)
        await invoke("discard_exchange", { path: pendingAttachment.path });
      setPendingAttachment(selected);
    });
  const stageMediaAttachment = (file: File | undefined) => {
    if (!file) return;
    void perform(async () => {
      if (file.size > 5 * 1024 * 1024)
        throw new Error("Attachment files cannot exceed 5 MB.");
      const dataUrl = await new Promise<string>((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = () => resolve(String(reader.result));
        reader.onerror = () =>
          reject(new Error("Could not safely open this attachment."));
        reader.readAsDataURL(file);
      });
      const separator = dataUrl.indexOf(",");
      if (separator < 0)
        throw new Error("Could not safely open this attachment.");
      const selected = await invoke<SelectedAttachment>("stage_attachment", {
        name: file.name || "attachment.bin",
        data: dataUrl.slice(separator + 1),
      });
      if (pendingAttachment)
        await invoke("discard_exchange", { path: pendingAttachment.path });
      setPendingAttachment(selected);
    });
  };
  const discardAttachment = () => {
    const selected = pendingAttachment;
    setPendingAttachment(null);
    if (selected)
      void invoke("discard_exchange", { path: selected.path }).catch(
        reportError,
      );
  };
  const cancelAttachmentTransfer = () => {
    const transfer = attachmentTransfer;
    if (!transfer || transfer.cancelling) return;
    setAttachmentTransfer((current) =>
      current?.transferId === transfer.transferId
        ? { ...current, cancelling: true }
        : current,
    );
    void invoke("cancel_attachment_transfer", {
      transferId: transfer.transferId,
    }).catch(reportError);
  };
  const downloadAttachment = (row: MessageRow) => {
    if (downloadingAttachment) return;
    if (!stream) return;
    const transferId = crypto.randomUUID();
    setBusy(true);
    setError("");
    setSyncSummary("");
    void (async () => {
      const output = await invoke<string>("prepare_export", {
        kind: "file_download",
      });
      setAttachmentTransfer({
        transferId,
        kind: "download",
        record: row.id,
        received: 0,
        total: row.body.attachment?.encrypted_size ?? 0,
        cancelling: false,
      });
      try {
        await invoke("attachment_transfer", {
          transferId,
          request: {
            op: "attachment_download",
            space: stream.space,
            stream: stream.stream,
            record: row.id,
            output,
            expected_identity: view?.identity,
            expected_space: view?.active_space,
          },
        });
        const filename =
          row.body.attachment?.name ?? row.body.filename ?? "attachment.bin";
        if (await invoke<boolean>("save_export", { path: output, filename })) {
          await invoke("discard_exchange", { path: output });
          notify(t("file.exportSaved"));
        } else {
          // Closing the system picker cancels this download. The attachment
          // remains in the conversation and can be downloaded again.
          await invoke("discard_exchange", { path: output });
        }
      } catch (error) {
        await invoke("discard_exchange", { path: output }).catch(() => {});
        if (!String(error).includes(ATTACHMENT_TRANSFER_CANCELLED)) {
          reportError(error);
        }
      }
    })()
      .catch(reportError)
      .finally(() => {
        setBusy(false);
        setAttachmentTransfer((current) =>
          current?.transferId === transferId ? undefined : current,
        );
      });
  };
  const refresh = () =>
    perform(async () => {
      // Keep a manual refresh bounded; the foreground worker drains the rest.
      const result = await call({ op: "sync_live" });
      requestSync(true);
      setSyncSummary(
        t("sync.summary", result.result as Record<string, number>),
      );
    });
  const openHome = (tab: "stream" | "chats" | "contacts") => {
    setCollection(null);
    setNewChat(null);
    setAddPeopleOpen(false);
    setAction(null);
    setHeaderMenu(null);
    setThreadRoot(undefined);
    setHomeTab(tab);
    setSettingsOpen(false);
    setConversationOpen(false);
    setMembersOpen(false);
    setInvitationRoute(null);
    setMessageTarget(undefined);
  };
  const openThread = (row: MessageRow, compose: boolean, chat = stream) => {
    if (!chat) return;
    const rootId = replyRoot(row) ?? row.id;
    if (threadRoot !== rootId || stream?.stream !== chat.stream) {
      setThreadTarget(
        replyRoot(row)
          ? { id: row.id, key: ++messageTargetSerial.current }
          : undefined,
      );
      setThreadComposeRevision(compose ? 1 : 0);
    } else if (compose) setThreadComposeRevision((value) => value + 1);
    setSelected(chat.stream);
    setConversationOpen(true);
    setThreadRoot(rootId);
  };
  const closeThread = () => {
    setThreadRoot(undefined);
  };
  const openStreamMessage = async (entry: StreamEntry) => {
    const identity = view?.identity;
    if (
      entry.chat.space_context &&
      entry.chat.space_context !== view?.active_space
    ) {
      try {
        const result = await invoke<{ view: View }>("operate", {
          request: {
            op: "space_select",
            id: entry.chat.space_context,
            expected_identity: view?.identity,
          },
        });
        if (
          currentView.current?.identity !== identity ||
          result.view.identity !== identity
        )
          return false;
        setView(result.view);
        navigateToMessage(entry);
        return true;
      } catch (error) {
        reportError(error);
        return false;
      }
    }
    navigateToMessage(entry);
    return true;
  };
  const navigateToMessage = (entry: StreamEntry) => {
    setPreparedHistory(entry.history);
    setThreadRoot(undefined);
    setHomeTab("chats");
    setSettingsOpen(false);
    setMembersOpen(false);
    setSelected(entry.chat.stream);
    setMessageQuery("");
    setSessionUnread(new Set());
    setMessageTarget({ id: entry.row.id, key: ++messageTargetSerial.current });
    setConversationOpen(true);
    if (replyRoot(entry.row)) {
      openThread(entry.row, false, entry.chat);
      setThreadTarget({ id: entry.row.id, key: ++messageTargetSerial.current });
    }
  };
  const readStreamMessage = async (entry: StreamEntry): Promise<boolean> => {
    setError("");
    const identity = view?.identity;
    try {
      await invoke("operate", {
        request: {
          op: "mark_read",
          expected_identity: identity,
          expected_space: entry.chat.space_context ?? view?.active_space,
          space: entry.chat.space,
          stream: entry.chat.stream,
          records: [entry.row.id],
        },
      });
      // Patch only the committed marker: a stale response must not replace a
      // newer view, drop a just-arrived message or affect another profile.
      setView((current) =>
        current && current.identity === identity
          ? {
              ...current,
              streams: current.streams.map((chat) =>
                chat.space === entry.chat.space &&
                chat.stream === entry.chat.stream
                  ? markVisibleMessagesRead(chat, [entry.row.id])
                  : chat,
              ),
            }
          : current,
      );
      return true;
    } catch (error) {
      reportError(error);
      return false;
    }
  };
  const markVisibleRead = (records: string[]) => {
    if (
      !stream ||
      desktopProfileEditing ||
      isOpeningPush() ||
      !canReadVisibleMessages()
    )
      return;
    const identity = view?.identity;
    const currentChat = stream;
    const unseen = records.filter(
      (id) =>
        !manuallyUnread.current.has(id) &&
        visibleHistory.rows.some((row) => row.id === id && row.unread),
    );
    if (!unseen.length) return;
    history.markRead(unseen);
    threadHistory.markRead(unseen);
    setSessionUnread((current) => new Set([...current, ...unseen]));
    setView((current) =>
      current && current.identity === identity
        ? {
            ...current,
            streams: current.streams.map((chat) =>
              chat.space === currentChat.space &&
              chat.stream === currentChat.stream
                ? markVisibleMessagesRead(chat, unseen)
                : chat,
            ),
          }
        : current,
    );
    void invoke("operate", {
      request: {
        op: "mark_read",
        expected_identity: identity,
        expected_space: currentChat.space_context ?? view?.active_space,
        space: currentChat.space,
        stream: currentChat.stream,
        records: unseen,
      },
    }).catch((error) => {
      void refresh();
      reportError(error);
    });
  };
  const storageNotices = useRef(new Map<string, number>());
  useEffect(() => {
    storageNotices.current.clear();
  }, [view?.identity]);
  function receiveSync(result: SyncResult) {
    const full = [...(result.result?.storage_full_spaces ?? [])];
    if ((result.result?.quota_exceeded ?? 0) > 0 && !full.length)
      full.push({ id: view?.active_space ?? "", name: "" });
    const fresh = full.filter(
      ({ id }) => Date.now() - (storageNotices.current.get(id) ?? 0) > 60_000,
    );
    for (const space of fresh) storageNotices.current.set(space.id, Date.now());
    if (fresh.length)
      setError(
        fresh.some((space) => !space.name)
          ? t("error.replicaFull")
          : t("spaces.storage.full", {
              names: fresh.map((space) => space.name).join(", "),
            }),
      );
    if (!result.view || acceptView(view, result.view) === view) return;
    setView(result.view);
    if (stream && (messagesActive || threadActive) && !isOpeningPush()) {
      const row = newMessageInChat(
        result.view,
        result.result?.received_messages ?? [],
        stream,
        threadActive ? threadRoot : undefined,
      );
      if (row)
        setNewMessage({
          scope: messageScope,
          id: row.id,
          key: ++messageTargetSerial.current,
        });
    }
    if (
      fresh.length > 0 ||
      document.visibilityState !== "visible" ||
      isOpeningPush() ||
      document.querySelector("dialog[open]")
    )
      return;
    const location =
      stream && (messagesActive || threadActive)
        ? {
            stream: stream.stream,
            thread: threadActive ? threadRoot : undefined,
          }
        : null;
    const entries = incomingMessages(
      result.view,
      result.result?.received_messages ?? [],
      location,
    );
    if (!entries.length) {
      const invites = invitationCount(result.view) > invitationCount(view!);
      const notifications =
        notificationCount(result.view) > notificationCount(view!);
      const page = invites ? "activity" : "notifications";
      if ((invites || notifications) && invitationRoute?.page !== page) {
        showMessage(
          t(invites ? "notifications.invitation" : "notifications.membership"),
          () => {
            setCollection(null);
            setNewChat(null);
            setMembersOpen(false);
            setSettingsOpen(false);
            setInvitationRoute({ page, unscoped: true });
          },
        );
      }
      return;
    }
    const entry = entries.at(-1)!;
    const label =
      entries.length > 1
        ? t("notifications.messages", { count: entries.length })
        : t(
            entry.chat.chat_kind === "direct" && entry.chat.members.length === 2
              ? "notifications.directMessage"
              : "notifications.message",
            {
              name: senderName(
                result.view,
                entry.row.body.issuer_identity,
                entry.chat,
              ),
              chat: entry.chat.name,
              message: (entry.row.body.payload?.text ?? "")
                .slice(0, 160)
                .replace(/\s+/g, " "),
            },
          );
    showMessage(label, () => {
      setCollection(null);
      setInvitationRoute(null);
      setNewChat(null);
      setMembersOpen(false);
      if (
        entries.length > 1 &&
        entries.every((item) => item.chat.space_context === view?.active_space)
      )
        openHome("stream");
      else openStreamMessage(entry);
    });
  }
  const { request: requestSync, progress: syncProgress } = useLiveSync(
    view,
    messagesActive || threadActive,
    busy,
    receiveSync,
    () => isOpeningPush() || (visibleHistory.enabled && !visibleHistory.ready),
  );
  const requestUnavailableMessage = async (row: MessageRow) => {
    if (!stream || !row.body.locator)
      throw new Error("Message locator missing.");
    await call({
      op: "request_message",
      space: stream.space,
      stream: stream.stream,
      locator: row.id,
    });
    requestSync(true);
  };
  const {
    settings: pushSettings,
    offer: notificationOffer,
    isOpening: isOpeningPush,
    showOpening: notificationOpening,
  } = usePushNotifications(
    view,
    busy,
    requestSync,
    receiveSync,
    (entry, page) => {
      clearMessages();
      setCollection(null);
      setNewChat(null);
      setMembersOpen(false);
      setInvitationRoute(null);
      if (entry) return openStreamMessage(entry);
      else if (page) {
        setSettingsOpen(false);
        setInvitationRoute({ page, unscoped: true });
      } else openHome("chats");
      return true;
    },
    reportError,
    mobile &&
      !view?.space_setup &&
      !biometricOfferPending &&
      !biometricOfferName,
    () => visibleHistory.enabled && !visibleHistory.ready,
  );
  useEffect(() => {
    clearMessages();
    const hide = () => {
      if (document.visibilityState !== "visible") clearMessages();
    };
    document.addEventListener("visibilitychange", hide);
    return () => document.removeEventListener("visibilitychange", hide);
  }, [view?.identity]);
  const createGroup = async (name: string) => {
    let group: ChatGroup | undefined;
    await perform(async () => {
      const response = await call({ op: "create_group", name });
      group = response.view?.groups?.at(-1);
    });
    return group;
  };
  const begin = (a: Action, initial: Record<string, string | boolean> = {}) => {
    setHeaderMenu(null);
    setCollection(null);
    setInvitationRoute(null);
    setNewChat(null);
    setAddPeopleOpen(false);
    setSettingsOpen(false);
    if (a.id === "create_chat") {
      setNewChat({
        kind: initial.chat_kind === "chat" ? "chat" : "direct",
        group: view?.groups?.some((g) => g.id === chatFilter) ? chatFilter : "",
      });
      setError("");
      return;
    }
    setAction(a);
    setGroupDraft(false);
    setValues({
      ...(a.id === "set_chat_group" ? { group: stream?.group ?? "" } : {}),
      ...initial,
    });
    setError("");
  };
  const submit = () =>
    perform(async () => {
      if (!action) return;
      const request = {
        space: stream?.space,
        stream: stream?.stream,
        ...values,
        op: action.id,
      };
      await call(request);
      setAction(null);

      setValues({});
      if (action.id !== "remove_member") notify(t("notice.confirmed"));
    });
  const clearProfileSession = () => {
    setView(null);
    setThreadDrafts({});
    setChatQuery("");
    setMessageQuery("");
    setInvitationRoute(null);
    setMembersOpen(false);
    setNewChat(null);
    setMessageStatus(null);
    setHeaderMenu(null);
    setIdentifiersOpen(false);
    setCollection(null);
    setText("");

    setAction(null);
    setValues({});

    setPendingAttachment(null);

    setLogoutOpen(false);
    setActiveDemoProfile(undefined);
    setBiometricOfferName("");
    authenticationEpoch.current += 1;
    setBiometricOfferPending(false);
    biometricOfferCredential.current = {
      password: "",
      demoProfile: undefined,
    };
    setAttachmentTransfer(undefined);
    clearMessages();
  };
  const lockProfile = () =>
    void perform(async () => {
      await invoke("lock");
      clearProfileSession();
    });
  const dismissBiometricOffer = () => {
    if (biometricOfferCredential.current.profile)
      markBiometricOfferHandled(biometricOfferCredential.current.profile);
    biometricOfferCredential.current = {
      password: "",
      demoProfile: undefined,
    };
    setBiometricOfferName("");
  };
  const acceptBiometricOffer = () =>
    void perform(async () => {
      if (!biometricOfferCredential.current.profile)
        throw new Error("dataNeedsReenrollment");
      await enableBiometricUnlock(
        biometricOfferCredential.current.password,
        biometricOfferCredential.current.demoProfile,
        biometricOfferCredential.current.profile,
      );
      dismissBiometricOffer();
    });
  if (!view)
    return (
      <ProfileGate
        appearance={<Appearance theme={theme} onChange={changeTheme} compact />}
        theme={theme}
        onTheme={changeTheme}
        onOpen={(value, isMobile, verifiedPassword, demoProfile) => {
          const epoch = ++authenticationEpoch.current;
          setBiometricOfferPending(false);
          storeView(value);
          setMobile(isMobile);
          setActiveDemoProfile(demoProfile);
          setConversationOpen(false);
          setMembersOpen(false);
          setSettingsOpen(false);
          setChatFilter("overview");
          setHomeTab("chats");
          setMessageTarget(undefined);
          if (isMobile && (verifiedPassword || demoProfile)) {
            setBiometricOfferPending(true);
            biometricOfferCredential.current = {
              password: verifiedPassword ?? "",
              demoProfile,
            };
            void readBiometricState(value.identity)
              .then((state) => {
                if (authenticationEpoch.current !== epoch) return;
                if (
                  state.available &&
                  !state.enabled &&
                  state.profile &&
                  shouldOfferBiometricUnlock(state.profile)
                ) {
                  biometricOfferCredential.current.profile = state.profile;
                  setBiometricOfferName(biometricName(state.type));
                } else
                  biometricOfferCredential.current = {
                    password: "",
                    demoProfile: undefined,
                  };
              })
              .catch(() => {
                if (authenticationEpoch.current !== epoch) return;
                biometricOfferCredential.current = {
                  password: "",
                  demoProfile: undefined,
                };
              })
              .finally(() => {
                if (authenticationEpoch.current === epoch)
                  setBiometricOfferPending(false);
              });
          }
        }}
      />
    );
  if (view.space_setup)
    return (
      <SpaceSetup
        view={view}
        mobile={mobile}
        onView={setView}
        onLock={lockProfile}
      />
    );
  const actionButton = (a: Action) => (
    <button
      className="action-link"
      disabled={busy}
      key={a.id}
      onClick={() => begin(a)}
    >
      {a.title}
      <Icon name="next" />
    </button>
  );
  const scopedActions = (conversation: boolean) =>
    actions.filter((action) =>
      conversation
        ? !!stream && action.id === "set_chat_group"
        : action.id === "create_group",
    );
  const chatIdentifiers = stream && (
    <>
      {(
        [
          ["channel.space", stream.space],
          ["channel.stream", stream.stream],
          ["channel.head", stream.head],
          ["channel.controller", stream.controller],
          ["channel.recovery", stream.recovery],
        ] as const
      ).map(
        ([key, value]) =>
          value && (
            <label key={key}>
              {t(key)}
              <code>{value}</code>
            </label>
          ),
      )}
    </>
  );
  return (
    <MessageActionsProvider
      key={view.identity}
      view={view}
      expert={mode === "expert"}
      hideAvatars={preferences.hideAvatars}
      mobile={mobile}
      collection={collection}
      onCollection={setCollection}
      onChange={call}
      onUnread={markUnread}
      onOpen={openStreamMessage}
    >
      <div
        className="shell"
        inert={notificationOpening}
        data-mobile={!desktopLayout}
        data-desktop-pane={
          invitationRoute
            ? "invitations"
            : settingsOpen
              ? "settings"
              : membersOpen
                ? "members"
                : threadActive
                  ? "thread"
                  : contactsActive
                    ? "contacts"
                    : streamActive
                      ? "stream"
                      : "conversation"
        }
        data-mode={mode}
        data-stream={streamActive}
        data-contacts={
          homeTab === "contacts" &&
          !conversationOpen &&
          !settingsOpen &&
          !invitationRoute
        }
        data-thread={threadActive}
        data-conversation={conversationOpen}
        data-settings={settingsOpen}
        data-settings-page={settingsPage}
        data-members={membersOpen}
        data-invitations={Boolean(invitationRoute)}
      >
        {contactsActive && (
          <Contacts
            mobile={mobile}
            view={view}
            hideAvatars={preferences.hideAvatars}
            onMessages={() => openHome("chats")}
            busy={busy}
            onPerson={(id, name) => {
              if (busy) return;
              void perform(async () => {
                const response = await call({
                  op: "contact_open",
                  identity: id,
                  name,
                });
                if (!response.stream) return;
                setSelected(response.stream);
                setHomeTab("chats");
                setMessageTarget(undefined);
                setThreadRoot(undefined);
                setConversationOpen(true);
                setMembersOpen(false);
                setSettingsOpen(false);
              });
            }}
            onScan={() => setInvitationRoute({ page: "scan", contacts: true })}
            onCode={() =>
              setInvitationRoute({ page: "contact", contacts: true })
            }
          />
        )}
        <MessageStream
          key={view.identity}
          view={view}
          active={streamActive}
          mobile={mobile}
          busy={busy}
          hideAvatars={preferences.hideAvatars}
          onRefresh={refresh}
          onRead={readStreamMessage}
          onOpen={openStreamMessage}
          onChats={() => openHome("chats")}
          onYou={() => openSettings("profile")}
        />
        {threadActive && stream && selectedThread && (
          <ThreadView
            key={`${view.identity}:${stream.stream}:${selectedThread.rootId}`}
            view={view}
            chat={stream}
            thread={selectedThread}
            hideAvatars={preferences.hideAvatars}
            mobile={mobile}
            busy={busy}
            draft={threadDrafts[threadDraftKey] ?? ""}
            onDraft={(value) =>
              setThreadDrafts((current) => ({
                ...current,
                [threadDraftKey]: value,
              }))
            }
            onBack={closeThread}
            onRefresh={refresh}
            onRead={markVisibleRead}
            onStatus={setMessageStatus}
            onFile={downloadAttachment}
            downloadingAttachment={downloadingAttachment}
            attachmentProgress={
              attachmentTransfer?.kind === "download"
                ? attachmentTransfer
                : undefined
            }
            onCancelAttachment={cancelAttachmentTransfer}
            onRequestMessage={requestUnavailableMessage}
            onUnavailable={() => setMessageUnavailableOpen(true)}
            composeRevision={threadComposeRevision}
            target={threadTarget}
            newMessage={arrival}
            onJumpToLatest={(id) =>
              setThreadTarget({ id, key: ++messageTargetSerial.current })
            }
            historyLoading={threadHistory.loading}
            historyReady={threadHistory.ready}
            hasOlder={threadHistory.hasMore}
            hasNewer={threadHistory.hasNewer}
            onNewer={threadHistory.loadNewer}
            onRetry={threadHistory.retry}
            onOlder={threadHistory.loadMore}
            onSend={async (text) => {
              let sent = false;
              await perform(async () => {
                await call({
                  op: "send",
                  space: stream.space,
                  stream: stream.stream,
                  reply_to: selectedThread.rootId,
                  text,
                  created_at: recordTimestamp(),
                });
                sent = true;
              });
              return sent;
            }}
          />
        )}
        {!desktopLayout ? (
          <aside className="mobile-sidebar">
            <button
              className="secondary desktop-only"
              onClick={() => openHome("contacts")}
            >
              <Icon name="people" />
              {t("nav.contacts")}
            </button>
            <button
              className="secondary desktop-only stream-sidebar-link"
              onClick={() => openHome("stream")}
            >
              <Icon
                name="buzz"
                attention={unreadStreamEntries(view).length > 0}
              />
              {t("nav.stream")}
            </button>
            <ScreenHeader
              title={t("nav.chats")}
              actions={
                <>
                  <button
                    type="button"
                    className="icon"
                    aria-label={t("channel.new")}
                    disabled={busy}
                    onClick={() => begin(actions[0])}
                  >
                    <Icon name="plus" />
                  </button>
                  <button
                    type="button"
                    className="icon mobile-only"
                    aria-label={t("nav.more")}
                    aria-haspopup="menu"
                    aria-expanded={headerMenu?.conversation === false}
                    onClick={(event) =>
                      setHeaderMenu({
                        anchor: event.currentTarget.getBoundingClientRect(),
                        conversation: false,
                      })
                    }
                  >
                    <Icon name="more" />
                  </button>
                </>
              }
            />
            {!mobile && (
              <SearchField
                label={t("chat.search")}
                value={chatQuery}
                onChange={setChatQuery}
              />
            )}
            <ChatGroupsBar
              view={view}
              groups={view.groups ?? []}
              selected={chatFilter}
              onSelect={setChatFilter}
            />
            <div className="searchable-list">
              <PullToRefresh
                className="channel-scroll"
                enabled={mobile && chatsActive}
                disabled={busy}
                onRefresh={refresh}
                resetKey={
                  String(settingsOpen) +
                  String(conversationOpen) +
                  chatFilter +
                  chatQuery
                }
              >
                <div className="identity">
                  <span className="avatar">{t("profile.avatar")}</span>
                  <div>
                    {profileName(view) || t("profile.yourProfile")}
                    <small
                      title={mode === "expert" ? view.identity : undefined}
                    >
                      {mode === "expert"
                        ? view.identity.slice(0, 18) + "…"
                        : t("profile.local")}
                    </small>
                  </div>
                </div>
                <details className="expert-only">
                  <summary>{t("profile.identifiers")}</summary>
                  <label>
                    {t("profile.identityId")}
                    <code>{view.identity}</code>
                  </label>
                  <label>
                    {t("profile.credentialId")}
                    <code>{view.credential}</code>
                  </label>
                </details>
                {syncProgress && (
                  <div
                    className="sync-progress"
                    role="status"
                    aria-live="polite"
                  >
                    <span>
                      {t(
                        syncProgress.phase === "waiting"
                          ? "sync.progressWaiting"
                          : "sync.progressReceiving",
                      )}
                    </span>
                    <small>
                      {syncProgress.received > 0
                        ? t("sync.progressReceived", {
                            count: syncProgress.received,
                          })
                        : t("sync.progressResumes")}
                    </small>
                  </div>
                )}
                <ChatList
                  view={view}
                  filter={chatFilter}
                  query={chatQuery}
                  selected={stream?.stream}
                  onOpen={(chat) => {
                    setSelected(chat.stream);
                    setHomeTab("chats");
                    setMessageTarget(undefined);
                    setSessionUnread(new Set());
                    setConversationOpen(true);
                  }}
                />
                <div className="sidebar-bottom">
                  <button
                    className="secondary"
                    onClick={() => openSettings("profile")}
                  >
                    {t("nav.moreTab")}
                    {invitationCount(view) + notificationCount(view) > 0 && (
                      <NewIndicator />
                    )}
                  </button>
                  <button
                    className="danger-outline"
                    disabled={busy}
                    onClick={() => setLogoutOpen(true)}
                  >
                    {t("profile.lock")}
                  </button>
                </div>
              </PullToRefresh>
              {mobile && chatsActive && (
                <FloatingSearch
                  label={t("chat.search")}
                  value={chatQuery}
                  onChange={setChatQuery}
                />
              )}
            </div>
          </aside>
        ) : (
          <DesktopSidebar
            view={view}
            calls={calls}
            selected={messagesActive ? stream?.stream : undefined}
            query={chatQuery}
            busy={busy}
            current={
              settingsOpen
                ? "settings"
                : contactsActive
                  ? "contacts"
                  : streamActive
                    ? "stream"
                    : "chats"
            }
            onQuery={setChatQuery}
            onOpen={(chat) => {
              setCollection(null);
              setNewChat(null);
              setAddPeopleOpen(false);
              setAction(null);
              setHeaderMenu(null);
              setSelected(chat.stream);
              setHomeTab("chats");
              setMessageTarget(undefined);
              setSessionUnread(new Set());
              setThreadRoot(undefined);
              setSettingsOpen(false);
              setMembersOpen(false);
              setInvitationRoute(null);
              setConversationOpen(true);
            }}
            onHome={openHome}
            onNewChat={(kind) => begin(actions[0], { chat_kind: kind })}
            onSettings={openSettings}
            onEditProfile={() => setDesktopProfileEditing(true)}
            onNavigate={() => setDesktopProfileEditing(false)}
            onReminders={() => {
              setNewChat(null);
              setAddPeopleOpen(false);
              setAction(null);
              setCollection(null);
              setHeaderMenu(null);
              setSettingsOpen(false);
              setInvitationRoute(null);
              setCollection({ kind: "reminders" });
            }}
            onNotifications={() => {
              setNewChat(null);
              setAddPeopleOpen(false);
              setAction(null);
              setCollection(null);
              setHeaderMenu(null);
              setSettingsOpen(false);
              setCollection(null);
              setInvitationRoute({ page: "notifications", unscoped: true });
            }}
            onInvitations={() => {
              setNewChat(null);
              setAddPeopleOpen(false);
              setAction(null);
              setCollection(null);
              setHeaderMenu(null);
              setSettingsOpen(false);
              setCollection(null);
              setInvitationRoute({ page: "activity", unscoped: true });
            }}
            onCode={() => {
              setNewChat(null);
              setAddPeopleOpen(false);
              setAction(null);
              setCollection(null);
              setHeaderMenu(null);
              setSettingsOpen(false);
              setInvitationRoute({ page: "contact" });
            }}
            onLock={() => setLogoutOpen(true)}
          />
        )}
        <div id="desktop-page-outlet" />
        <main className="conversation content-pane">
          <ScreenHeader
            title={stream?.name ?? t("channel.start")}
            participants={
              stream && isDirectChat(stream, view.identity) && !personalDM
                ? stream.members
                    .filter((member) => member.identity_id !== view.identity)
                    .map((member) =>
                      senderName(view, member.identity_id, stream),
                    )
                    .sort((left, right) => left.localeCompare(right))
                : undefined
            }
            onBack={mobile ? () => setConversationOpen(false) : undefined}
            backLabel={t(
              homeTab === "stream" ? "nav.backToStream" : "nav.backToChats",
            )}
            actions={
              <>
                {desktopLayout && !mobile && (
                  <RefreshButton onRefresh={refresh} />
                )}
                {stream &&
                  view.spaces?.some(
                    (space) => space.id === view.active_space && space.managed,
                  ) && (
                    <span className="desktop-only">
                      <CallButton
                        calls={calls}
                        chat={{
                          ...stream,
                          space_context:
                            stream.space_context ??
                            view.active_space ??
                            undefined,
                        }}
                      />
                    </span>
                  )}
                <button
                  ref={moreRef}
                  type="button"
                  className="icon"
                  aria-label={t("nav.more")}
                  aria-haspopup="menu"
                  aria-expanded={headerMenu?.conversation === true}
                  onClick={(event) =>
                    setHeaderMenu({
                      anchor: event.currentTarget.getBoundingClientRect(),
                      conversation: true,
                    })
                  }
                >
                  <Icon name="more" />
                </button>
              </>
            }
          />
          {stream?.forked && <p className="error">{t("warning.forked")}</p>}
          {mode === "expert" && syncSummary && (
            <p className="notice" role="status">
              {syncSummary}
            </p>
          )}
          {desktopLayout && (
            <div className="desktop-message-search">
              <SearchField
                label={t("search.messages")}
                value={messageQuery}
                onChange={setMessageQuery}
              />
            </div>
          )}
          <div className="searchable-list">
            <PullToRefresh
              className="messages"
              enabled={mobile && messagesActive}
              disabled={busy}
              onRefresh={refresh}
              resetKey={conversationScope + String(settingsOpen)}
              active={messagesActive}
              newMessage={arrival}
              onJumpToLatest={(id) =>
                setMessageTarget({ id, key: ++messageTargetSerial.current })
              }
              showNewMessageButton={messagesActive && !messageQuery.trim()}
              scrollToEndKey={
                !messageTarget && !messageQuery.trim()
                  ? `${view.identity}:${stream?.stream}:${ownSendRevision}:${stream?.rows.filter((row) => row.body.issuer_identity === view.identity).at(-1)?.id ?? ""}`
                  : undefined
              }
              scrollToRecord={messageTarget}
              onVisibleUnread={messagesActive ? markVisibleRead : undefined}
              onLoadOlder={history.hasMore ? history.loadMore : undefined}
              loadingOlder={history.loading}
              historyReady={history.ready}
              followLatest={
                messagesActive && !messageQuery.trim() && !history.hasNewer
              }
            >
              {history.loading && !history.ready && (
                <p className="history-loading" role="status">
                  {t("history.loading")}
                </p>
              )}
              {!history.ready && !history.loading && (
                <button
                  className="history-more secondary"
                  onClick={() => void history.retry()}
                >
                  {t("history.retry")}
                </button>
              )}
              {history.hasMore && (
                <button
                  className="history-more secondary"
                  disabled={history.loading}
                  onClick={() => void history.loadMore()}
                >
                  {t(
                    messageQuery.trim()
                      ? "history.searchMore"
                      : "history.older",
                  )}
                </button>
              )}
              {messageTarget && history.hasNewer && (
                <button
                  className="history-more secondary"
                  onClick={() => setMessageTarget(undefined)}
                >
                  {t("history.latest")}
                </button>
              )}
              {messageRows.map((r, index) => {
                const entry = timeline[index];
                const isNew = isNewMessage(messageRows, index, sessionUnread);
                const attachmentExpired =
                  r.body.kind === "file.shared" &&
                  r.body.attachment?.expires_at_ms != null &&
                  r.body.attachment.expires_at_ms <= Date.now();
                if (entry.placeholder && entry.thread)
                  return (
                    <article
                      className="message thread-placeholder"
                      key={r.id}
                      data-record-id={r.id}
                      tabIndex={-1}
                    >
                      <div className="avatar" aria-hidden="true">
                        <Icon name="chats" />
                      </div>
                      <div className="message-content">
                        <strong>{t("thread.title")}</strong>
                        <p>{t("thread.missingRoot")}</p>
                        <ThreadLink
                          thread={entry.thread}
                          onOpen={() => openThread(r, false)}
                        />
                      </div>
                    </article>
                  );
                return (
                  <React.Fragment key={r.id}>
                    {index > firstMessageIndex &&
                      messageDayKey(messageCreatedAt(r)) !==
                        messageDayKey(
                          messageCreatedAt(messageRows[index - 1]),
                        ) && (
                        <h3 className="message-day">
                          <span>{formatMessageDay(messageCreatedAt(r))}</span>
                        </h3>
                      )}
                    {beginsNewMessageSection(
                      messageRows,
                      index,
                      sessionUnread,
                    ) && (
                      <div className="unread-separator" role="separator">
                        <span>{t("unread.new")}</span>
                      </div>
                    )}
                    <article
                      className="message"
                      data-record-id={r.id}
                      tabIndex={-1}
                      data-hide-avatars={preferences.hideAvatars || undefined}
                      data-new={isNew || undefined}
                      data-unread-id={r.unread ? r.id : undefined}
                      data-own={r.body.issuer_identity === view.identity}
                    >
                      <MessageContent
                        view={view}
                        chat={stream}
                        row={r}
                        showDate={index === firstMessageIndex}
                        hideAvatars={preferences.hideAvatars}
                        onStatus={
                          r.body.kind === "unavailable"
                            ? undefined
                            : setMessageStatus
                        }
                      >
                        {r.body.kind === "deleted" ? (
                          <p className="deleted-message">
                            {t("messageActions.deleted")}
                          </p>
                        ) : r.body.kind === "unavailable" ? (
                          <UnavailableMessage
                            disabled={busy}
                            onRequest={() => requestUnavailableMessage(r)}
                            onUnavailable={() =>
                              setMessageUnavailableOpen(true)
                            }
                          />
                        ) : r.body.kind === "chat.message" ? (
                          <MessageBubble
                            key={`${view.identity}:${stream?.stream}:${r.id}`}
                            text={r.body.payload?.text ?? ""}
                            thread={entry.thread}
                            canReply={!!stream?.can_post && !stream.forked}
                            onOpen={() => openThread(r, !entry.thread)}
                          />
                        ) : (
                          <AttachmentButton
                            row={r}
                            disabled={busy}
                            expired={attachmentExpired}
                            download={
                              downloadingAttachment === r.id
                                ? attachmentTransfer
                                : undefined
                            }
                            onDownload={() => downloadAttachment(r)}
                            onCancel={cancelAttachmentTransfer}
                          />
                        )}
                        {entry.thread && r.body.kind !== "chat.message" && (
                          <ThreadLink
                            thread={entry.thread}
                            onOpen={() => openThread(r, false)}
                          />
                        )}
                      </MessageContent>
                    </article>
                  </React.Fragment>
                );
              })}
              {history.hasNewer && (
                <button
                  className="history-more secondary"
                  disabled={history.loading}
                  onClick={() => void history.loadNewer()}
                >
                  {t("history.newer")}
                </button>
              )}
              {history.ready &&
                !history.hasMore &&
                !!messageQuery.trim() &&
                !messageRows.length && (
                  <EmptyState message={t("search.noMessages")} />
                )}
              {history.ready &&
                !messageQuery.trim() &&
                !stream?.rows.length && (
                  <EmptyState
                    message={
                      awaitingDirect
                        ? t("dm.waiting")
                        : stream
                          ? t("channel.historyStarts")
                          : t("channel.welcome")
                    }
                  >
                    <p
                      className={
                        stream
                          ? "empty-state-help expert-only"
                          : "empty-state-help"
                      }
                    >
                      {stream
                        ? t("channel.noPastHistory")
                        : t("channel.emptyHelp")}
                    </p>
                  </EmptyState>
                )}
            </PullToRefresh>
            {mobile && messagesActive && (
              <ConversationTools
                searchKey={stream?.stream}
                label={t("search.messages")}
                value={messageQuery}
                onChange={setMessageQuery}
                call={
                  stream &&
                  view.spaces?.some(
                    (space) => space.id === view.active_space && space.managed,
                  ) && (
                    <div className="floating-call">
                      <CallButton
                        calls={calls}
                        chat={{
                          ...stream,
                          space_context:
                            stream.space_context ??
                            view.active_space ??
                            undefined,
                        }}
                      />
                    </div>
                  )
                }
              />
            )}
          </div>
          <form
            className="composer"
            onSubmit={(e) => {
              e.preventDefault();
              if (stream && !awaitingDirect && (text || pendingAttachment))
                void perform(async () => {
                  let committed = false;
                  if (text) {
                    await call({
                      op: "send",
                      space: stream.space,
                      stream: stream.stream,
                      text,
                      created_at: recordTimestamp(),
                    });
                    // The text message has committed even if a subsequent
                    // attachment upload fails. Clear it now to prevent a retry
                    // from sending the same text twice.
                    setText("");
                    committed = true;
                  }
                  if (pendingAttachment) {
                    const selected = pendingAttachment;
                    const transferId = crypto.randomUUID();
                    let cancelled = false;
                    setAttachmentTransfer({
                      transferId,
                      kind: "upload",
                      received: 0,
                      total: selected.size_bytes,
                      cancelling: false,
                    });
                    try {
                      const uploaded = await invoke<{ view?: View }>(
                        "attachment_transfer",
                        {
                          transferId,
                          request: {
                            op: "attachment_upload",
                            space: stream.space,
                            stream: stream.stream,
                            path: selected.path,
                            name: selected.name,
                            expected_identity: view?.identity,
                            expected_space: view?.active_space,
                          },
                        },
                      );
                      committed = true;
                      if (uploaded.view) setView(uploaded.view);
                      setPendingAttachment(null);
                      requestSync();
                      // The message is committed at this point. Temporary-file
                      // cleanup must not delay the chat or turn a successful
                      // send into an error when it queues behind background work.
                      void invoke("discard_exchange", {
                        path: selected.path,
                      }).catch(() => {});
                    } catch (error) {
                      if (
                        String(error).includes(ATTACHMENT_TRANSFER_CANCELLED)
                      ) {
                        cancelled = true;
                      } else {
                        throw error;
                      }
                    } finally {
                      setAttachmentTransfer((current) =>
                        current?.transferId === transferId
                          ? undefined
                          : current,
                      );
                    }
                    if (cancelled && !committed) return;
                  }
                  setText("");
                  if (committed) {
                    setMessageTarget(undefined);
                    setOwnSendRevision((revision) => revision + 1);
                  }
                });
            }}
          >
            <input
              ref={mediaPicker}
              type="file"
              accept="image/*,video/*"
              hidden
              aria-label={t("file.photoVideo")}
              onChange={(event) => {
                const file = event.currentTarget.files?.[0];
                event.currentTarget.value = "";
                stageMediaAttachment(file);
              }}
            />
            {mobile && (
              <input
                ref={cameraPicker}
                type="file"
                accept="image/*,video/*"
                capture="environment"
                hidden
                aria-label={t("file.camera")}
                onChange={(event) => {
                  const file = event.currentTarget.files?.[0];
                  event.currentTarget.value = "";
                  stageMediaAttachment(file);
                }}
              />
            )}
            {pendingAttachment && (
              <div
                className={`composer-attachment${uploadingAttachment ? " composer-attachment-uploading" : ""}`}
                role="status"
              >
                <span>
                  {!uploadingAttachment && <Icon name="attachment" />}
                  <span className="composer-attachment-details">
                    <span className="composer-attachment-name">
                      {pendingAttachment.name}
                    </span>
                    <small>
                      {t("file.size", {
                        size: formatFileSize(pendingAttachment.size_bytes),
                      })}
                    </small>
                    {uploadingAttachment && (
                      <span className="composer-upload-progress" role="status">
                        <span className="composer-upload-label">
                          <span>
                            {attachmentTransfer?.cancelling
                              ? t("file.cancelling")
                              : attachmentTransfer &&
                                  attachmentTransfer.total > 0
                                ? t("file.uploadingPercent", {
                                    percent: Math.min(
                                      100,
                                      Math.round(
                                        (attachmentTransfer.received /
                                          attachmentTransfer.total) *
                                          100,
                                      ),
                                    ),
                                  })
                                : t("file.uploading")}
                          </span>
                          <button
                            type="button"
                            className="attachment-cancel"
                            disabled={attachmentTransfer?.cancelling}
                            onClick={cancelAttachmentTransfer}
                          >
                            {t("file.cancelTransfer")}
                          </button>
                        </span>
                        <progress
                          aria-label={t("file.uploadProgress", {
                            filename: pendingAttachment.name,
                          })}
                          value={
                            attachmentTransfer && attachmentTransfer.total > 0
                              ? attachmentTransfer.received
                              : undefined
                          }
                          max={
                            attachmentTransfer && attachmentTransfer.total > 0
                              ? attachmentTransfer.total
                              : undefined
                          }
                        />
                      </span>
                    )}
                  </span>
                </span>
                {!uploadingAttachment && (
                  <button
                    type="button"
                    className="icon secondary"
                    aria-label={t("file.remove")}
                    title={t("file.remove")}
                    disabled={busy}
                    onClick={discardAttachment}
                  >
                    <Icon name="close" />
                  </button>
                )}
              </div>
            )}
            <ComposerInput
              aria-label={t("composer.label")}
              value={text}
              onChange={(e) => setText(e.target.value)}
              placeholder={
                stream?.can_post && !awaitingDirect
                  ? t("composer.placeholder")
                  : t("composer.unavailable")
              }
              disabled={
                !stream?.can_post || stream.forked || awaitingDirect || busy
              }
              maxLength={16384}
            />
            <div>
              <button
                type="button"
                className="composer-attach"
                aria-label={t("file.attach")}
                title={t("file.attach")}
                disabled={
                  !stream?.can_post || stream.forked || awaitingDirect || busy
                }
                onClick={(event) =>
                  setAttachmentMenu(event.currentTarget.getBoundingClientRect())
                }
              >
                <Icon name="plus" />
              </button>
              <button
                aria-label={t("composer.send")}
                title={t("composer.send")}
                disabled={
                  (!text && !pendingAttachment) ||
                  !stream?.can_post ||
                  stream.forked ||
                  awaitingDirect ||
                  busy
                }
              >
                <span className="desktop-only">{t("composer.send")}</span>
                <span className="mobile-only">
                  <Icon name="up" />
                </span>
              </button>
            </div>
          </form>
        </main>
        <section
          className="details content-pane"
          ref={settingsRef}
          tabIndex={-1}
          aria-label={t("settings.title")}
        >
          {settingsPage === "actions" ? (
            <>
              <ScreenHeader
                title={t("nav.actions")}
                onBack={() => {
                  setSettingsOpen(false);
                  moreRef.current?.focus();
                }}
                backLabel={
                  conversationOpen ? t("nav.close") : t("nav.backToChats")
                }
              />
              <div className="channel-settings">
                {conversationOpen && stream && (
                  <button
                    className="action-link"
                    onClick={() =>
                      setCollection({ kind: "pins", stream: stream.stream })
                    }
                  >
                    {t("messageActions.pins")}
                    <Icon name="pin" />
                  </button>
                )}
                {scopedActions(conversationOpen).map(actionButton)}
                {conversationOpen && stream && (
                  <details className="expert-only">
                    <summary>{t("channel.anchors")}</summary>
                    {chatIdentifiers}
                  </details>
                )}
              </div>
            </>
          ) : (
            <UserSettings
              blockedUsersPage={<BlockedUsers view={view} />}
              serviceRequests={<ServiceRequests view={view} mobile={mobile} />}
              spaceContext={
                <CurrentSpace
                  view={view}
                  onManage={() => setSettingsPage("spaces")}
                />
              }
              spacesPage={
                <Spaces
                  view={view}
                  mobile={mobile}
                  hideAvatars={preferences.hideAvatars}
                  onView={setView}
                  onBack={() => setSettingsPage("profile")}
                />
              }
              page={settingsPage}
              name={profileName(view)}
              avatar={view.avatar ?? null}
              notifications={notificationCount(view)}
              invitations={invitationCount(view)}
              remindersDue={(view.all_reminders ?? view.reminders ?? []).some(
                (reminder) => reminder.due_at <= reminderClock,
              )}
              onReminders={() => setCollection({ kind: "reminders" })}
              theme={theme}
              mode={mode}
              preferences={preferences}
              identity={view.identity}
              credential={view.credential}
              busy={busy}
              mobile={mobile}
              demoProfile={activeDemoProfile}
              onPage={setSettingsPage}
              onClose={() => setSettingsOpen(false)}
              onTheme={changeTheme}
              onMode={changeMode}
              onPreferences={changePreferences}
              onLock={() => setLogoutOpen(true)}
              onProfile={saveProfile}
              onInvitations={() =>
                setInvitationRoute({ page: "activity", unscoped: true })
              }
              onNotifications={() =>
                setInvitationRoute({ page: "notifications", unscoped: true })
              }
              onCode={() => setInvitationRoute({ page: "contact" })}
              notificationSettings={pushSettings}
            />
          )}
        </section>
        {membersOpen && stream && (
          <Members
            key={stream.stream}
            view={view}
            stream={stream}
            busy={busy}
            hideAvatars={preferences.hideAvatars}
            expert={mode === "expert"}
            onBack={() => {
              setMembersOpen(false);
              requestAnimationFrame(() => moreRef.current?.focus());
            }}
            onAdd={() => setAddPeopleOpen(true)}
            onRemove={(member) =>
              begin(
                {
                  ...actions.find((a) => a.id === "remove_member")!,
                  title: t("members.removeTitle", {
                    name: senderName(view, member.identity_id, stream),
                  }),
                  fields: [],
                },
                { fingerprint: member.identity_id },
              )
            }
          />
        )}
        {addPeopleOpen && stream && (
          <AddPeople
            view={view}
            stream={stream}
            hideAvatars={preferences.hideAvatars}
            onClose={() => setAddPeopleOpen(false)}
            onAdd={async (request) => {
              const result = await invoke<{ view: View }>("operate", {
                request,
              });
              setView(result.view);
            }}
          />
        )}
        {invitationRoute && (
          <InvitationFlow
            active={!desktopProfileEditing}
            onSpaces={() => {
              setInvitationRoute(null);
              setSettingsOpen(true);
              setSettingsPage("spaces");
            }}
            key={JSON.stringify(invitationRoute) + view.active_space}
            route={invitationRoute}
            stream={
              invitationRoute.contacts || invitationRoute.unscoped
                ? undefined
                : stream
            }
            view={view}
            mobile={mobile}
            onClose={() => setInvitationRoute(null)}
            onView={setView}
            onJoined={(id) => {
              setSelected(id);
              setHomeTab("chats");
              setMessageTarget(undefined);
              setConversationOpen(true);
              setSettingsOpen(false);
            }}
          />
        )}
        <CallSurface calls={calls} view={view} />
        <LogoutDialog
          open={logoutOpen}
          busy={busy}
          onCancel={() => setLogoutOpen(false)}
          onConfirm={lockProfile}
        />
        {biometricOfferName && (
          <BiometricOfferDialog
            name={biometricOfferName}
            busy={busy}
            onDecline={dismissBiometricOffer}
            onAccept={acceptBiometricOffer}
          />
        )}
        {notificationOffer}
        {messageUnavailableOpen && (
          <ActionDialog
            title={t("messageUnavailable.title")}
            onClose={() => setMessageUnavailableOpen(false)}
          >
            <p>{t("messageUnavailable.body")}</p>
            <div className="space-choice">
              <button onClick={() => setMessageUnavailableOpen(false)}>
                {t("dialog.ok")}
              </button>
            </div>
          </ActionDialog>
        )}
        {attachmentMenu && (
          <ActionDialog
            title={t("file.attachOptions")}
            anchor={attachmentMenu}
            menu
            onClose={() => setAttachmentMenu(null)}
          >
            <button
              type="button"
              role="menuitem"
              onClick={() => {
                mediaPicker.current?.click();
                setAttachmentMenu(null);
              }}
            >
              <Icon name="image" />
              <span>{t("file.photoVideo")}</span>
            </button>
            {mobile && (
              <button
                type="button"
                role="menuitem"
                onClick={() => {
                  cameraPicker.current?.click();
                  setAttachmentMenu(null);
                }}
              >
                <Icon name="camera" />
                <span>{t("file.camera")}</span>
              </button>
            )}
            <button
              type="button"
              role="menuitem"
              onClick={() => {
                setAttachmentMenu(null);
                chooseAttachment();
              }}
            >
              <Icon name="file" />
              <span>{t("file.file")}</span>
            </button>
          </ActionDialog>
        )}
        <MobileNavigation
          notifications={notificationCount(view) + invitationCount(view)}
          unreadMessages={unreadStreamEntries(view).length}
          active={
            settingsOpen && settingsPage !== "actions" ? "profile" : homeTab
          }
          onNavigate={(tab) => {
            if (tab === "profile") openSettings("profile");
            else openHome(tab);
          }}
        />
        {headerMenu && (
          <ActionDialog
            title={t("nav.actions")}
            anchor={headerMenu.anchor}
            menu
            onClose={() => setHeaderMenu(null)}
          >
            {headerMenu.conversation && stream && !personalDM && (
              <button
                type="button"
                role="menuitem"
                onClick={() => {
                  setHeaderMenu(null);
                  setSettingsOpen(false);
                  setMembersOpen(true);
                }}
              >
                <span>{t("members.heading")}</span>
              </button>
            )}
            {headerMenu.conversation && stream && (
              <button
                type="button"
                role="menuitem"
                disabled={busy}
                onClick={() => {
                  setHeaderMenu(null);
                  setCollection({ kind: "pins", stream: stream.stream });
                }}
              >
                <span>{t("messageActions.pins")}</span>
              </button>
            )}
            {scopedActions(headerMenu.conversation).map((a) => (
              <button
                type="button"
                role="menuitem"
                key={a.id}
                disabled={busy}
                onClick={() => begin(a)}
              >
                <span>{a.title}</span>
              </button>
            ))}
            {headerMenu.conversation && stream && (
              <button
                type="button"
                role="menuitem"
                disabled={busy}
                onClick={() => {
                  const muted = !stream.muted;
                  setHeaderMenu(null);
                  void perform(async () => {
                    const result = await call({
                      op: "set_chat_muted",
                      space: stream.space,
                      stream: stream.stream,
                      muted,
                    });
                    clearMessages();
                    if (
                      (result as { notification_pending?: boolean })
                        .notification_pending
                    )
                      setError(t("notifications.mutePending"));
                    else
                      notify(
                        t(
                          muted
                            ? "channel.mutedNotice"
                            : "channel.unmutedNotice",
                        ),
                      );
                  });
                }}
              >
                <span>
                  {t(stream.muted ? "channel.unmute" : "channel.mute")}
                </span>
              </button>
            )}
            {headerMenu.conversation && stream && mode === "expert" && (
              <button
                type="button"
                role="menuitem"
                onClick={() => {
                  setHeaderMenu(null);
                  setIdentifiersOpen(true);
                }}
              >
                <span>{t("channel.anchors")}</span>
              </button>
            )}
          </ActionDialog>
        )}
        {identifiersOpen && stream && mode === "expert" && (
          <ActionDialog
            title={t("channel.anchors")}
            onClose={() => setIdentifiersOpen(false)}
          >
            {chatIdentifiers}
          </ActionDialog>
        )}
        {messageStatus && (
          <MessageStatusDialog
            selection={messageStatus}
            expert={mode === "expert"}
            onClose={() => setMessageStatus(null)}
          />
        )}
        {newChat && (
          <NewChat
            view={view}
            initialKind={newChat.kind}
            initialGroup={newChat.group}
            initialPeople={newChat.people}
            hideAvatars={preferences.hideAvatars}
            onClose={() => setNewChat(null)}
            onCreateGroup={createGroup}
            onCreate={async (request, invite) => {
              const response = await call(request);
              const created =
                response.view?.streams.find(
                  (chat) => chat.stream === response.stream,
                ) ?? response.view?.streams.at(-1);
              if (created) {
                setSelected(created.stream);
                setHomeTab("chats");
                setMessageTarget(undefined);
                setConversationOpen(true);
                setMembersOpen(false);
                setNewChat(null);
                if (invite) setInvitationRoute({ page: "invite" });
              }
            }}
          />
        )}
        {action && (
          <ActionDialog
            page={action.id !== "remove_member"}
            title={action.title}
            className="desktop-action-page"
            onClose={() => {
              if (!busy) setAction(null);
            }}
          >
            {action.description && <p>{action.description}</p>}
            <form
              onInvalid={onInvalid}
              onSubmit={(e) => {
                e.preventDefault();
                void submit();
              }}
            >
              {action.id === "remove_member" && mode === "expert" && (
                <label>
                  {t("profile.identityId")}
                  <code>{String(values.fingerprint ?? "")}</code>
                </label>
              )}
              {action.fields.map((field) => (
                <label key={field.key}>
                  {field.label}
                  <input
                    required
                    value={String(values[field.key] ?? "")}
                    autoComplete="off"
                    onChange={(event) =>
                      setValues({ ...values, [field.key]: event.target.value })
                    }
                  />
                </label>
              ))}
              {action.id === "set_chat_group" && (
                <ChatGroupField
                  key={action.id}
                  groups={view.groups ?? []}
                  showLabel={false}
                  value={String(values.group ?? "")}
                  disabled={busy}
                  onChange={(group) =>
                    setValues((current) => ({ ...current, group }))
                  }
                  onEditing={setGroupDraft}
                  onCreate={createGroup}
                />
              )}
              <button
                disabled={
                  busy ||
                  groupDraft ||
                  action.fields.some((field) => !values[field.key])
                }
              >
                {busy
                  ? t("dialog.verifying")
                  : action.id === "set_chat_group"
                    ? t("groups.save")
                    : action.id === "create_group"
                      ? t("contacts.save")
                      : action.id === "remove_member"
                        ? t("members.remove")
                        : t("dialog.execute")}
              </button>
            </form>
          </ActionDialog>
        )}
        {desktopLayout && desktopProfileEditing && (
          <PageSurface
            title={t("profile.edit")}
            className="desktop-profile-editor"
            onClose={() => {
              if (!busy) setDesktopProfileEditing(false);
            }}
          >
            <ScreenHeader
              title={t("profile.edit")}
              onBack={() => {
                if (!busy) setDesktopProfileEditing(false);
              }}
            />
            <ProfileEditor
              name={profileName(view)}
              avatar={view.avatar ?? null}
              mobile={false}
              busy={busy}
              onSave={async (profile) => {
                await saveProfile(profile);
                setDesktopProfileEditing(false);
              }}
            />
          </PageSurface>
        )}
      </div>
      {notificationOpening && (
        <div className="notification-opening" role="status" aria-live="polite">
          <span className="invitation-qr-loader" aria-hidden="true" />
          <p>{t("notifications.opening")}</p>
        </div>
      )}
    </MessageActionsProvider>
  );
}
createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <ToastProvider>
      <WindowChrome />
      <AccountDeletionNotice />
      <App />
    </ToastProvider>
  </React.StrictMode>,
);
