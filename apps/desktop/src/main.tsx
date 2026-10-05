import { RefreshButton } from "./RefreshButton";
import { UpdateGate } from "./UpdateGate";
import { canReadVisibleMessages } from "./messageReadVisibility";
import { PageSurface, useDesktopLayout } from "./PageSurface";
import { ProfileEditor, type ProfilePresentation } from "./ProfileEditor";
import {
  useCalls,
  CallButton,
  CallSurface,
  ActiveSessions,
  ActiveSessionJoin,
  useSessionStarted,
} from "./calls/CallUI";
import { activeSessions } from "./calls/sessionPresence";
import {
  useActivityNotifications,
  appHasAttention,
} from "./useActivityNotifications";
import { leaveBeforeLock } from "./calls/leaveBeforeLock";
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
  messageLogicalTime,
  beginsNewMessageSection,
  markVisibleMessagesRead,
  type View,
  type ChatGroup,
} from "./model";
import { ChatGroupsBar, ChatList, ChatGroupField } from "./ChatOrganization";
import { isDirectChat } from "./chatGroups";
import { NewChat } from "./NewChat";
import { Contacts } from "./Contacts";
import {
  applyTheme,
  readTheme,
  watchSystemTheme,
  type Theme,
  type ThemePreference,
} from "./theme";
import "./style.css";
import { Spaces, CurrentSpace, SpaceSetup } from "./Spaces";
import "./mobile.css";
import "./messageStream.css";
import "./messageThreads.css";
import "./desktop.css";
import "./update.css";
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
import {
  useConversationDraft,
  flushConversationDrafts,
  retryConversationDrafts,
} from "./conversationDrafts";
import {
  mentionCandidates,
  mentionIdentities,
  type ComposerMention,
} from "./composerMentions";
import { useAttachmentDrop } from "./useAttachmentDrop";
import { desktopShortcut } from "./desktopShortcuts";
import { KeyboardHelp, QuickSwitcher, switchableChats } from "./QuickSwitcher";
import { ComposerExpiry } from "./ComposerExpiry";
import type { MessageExpiryHours } from "./messageExpiry";
import { useExpiringView } from "./useMessageExpiry";
import { ThreadView } from "./ThreadView";
import { MessageBubble, ThreadLink } from "./MessageBubble";
import { UnavailableMessage } from "./UnavailableMessage";
import {
  AttachmentButton,
  attachmentFailure,
  type AttachmentProgress,
  type AttachmentUnavailable,
} from "./AttachmentButton";
import {
  clearAttachmentPreviews,
  loadAttachmentPreview,
} from "./attachmentPreview";
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
import { useOutgoingMessages } from "./useOutgoingMessages";
import { useMessageEntrance } from "./useMessageEntrance";
import type { SendReceipt } from "./outgoingMessages";
import type { HistoryPage } from "./messageHistory";
import { useLiveSync } from "./useLiveSync";
import {
  useRealtime,
  RealtimeProvider,
  RemoteUploads,
  TypingIndicator,
  OnlineIndicator,
} from "./useRealtime";
import { pendingRemoteUploads } from "./realtime";
import { usePushNotifications } from "./usePushNotifications";
import { acceptView, type SyncResult } from "./liveSync";
import { incomingMessages, newMessageInChat } from "./messageNotifications";
import { getCurrent, onOpenUrl } from "@tauri-apps/plugin-deep-link";
import { normalizeInvitationLink } from "./invitationTransport";
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

const initialThemePreference = readTheme();
const initialTheme = applyTheme(initialThemePreference);
const initialPreferences = readPreferences();
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
  const [biometricSupported, setBiometricSupported] = useState(false);
  useEffect(() => {
    let alive = true;
    void invoke<{ mobile: boolean; biometric_supported: boolean }>(
      "profile_environment",
    )
      .then((value) => {
        if (alive) {
          setMobile(value.mobile);
          setBiometricSupported(value.biometric_supported);
        }
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
  const [membersOpen, setMembersOpen] = useState(false);
  const [addPeopleOpen, setAddPeopleOpen] = useState(false);
  const [newChat, setNewChat] = useState<{
    kind: "chat" | "direct";
    group: string;
    people?: string[];
  } | null>(null);
  const [invitationRoute, setInvitationRoute] =
    useState<InvitationRoute | null>(null);
  const [spaceInvitation, setSpaceInvitation] = useState<{
    id: number;
    link: string;
  } | null>(null);
  const spaceInvitationSerial = useRef(0);
  const openSpaceInvitation = (link: string) => {
    setSpaceInvitation({ id: ++spaceInvitationSerial.current, link });
  };
  useEffect(() => {
    let alive = true;
    let dispose: (() => void) | undefined;
    const accept = (urls: string[]) => {
      const invitation = urls
        .map(normalizeInvitationLink)
        .find((item) => item !== null);
      if (!alive || !invitation) return;
      if (invitation.kind === "space") openSpaceInvitation(invitation.link);
      else {
        setSpaceInvitation(null);
        setInvitationRoute({
          page: "scan",
          link: invitation.link,
          unscoped: true,
        });
      }
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
  const [keyboardPanel, setKeyboardPanel] = useState<"switch" | "help" | null>(
    null,
  );
  const macKeyboard = /Mac|iPhone|iPad/.test(navigator.platform);
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
  const [attachmentTransfer, setAttachmentTransfer] =
    useState<AttachmentTransferState>();
  const [attachmentStates, setAttachmentStates] = useState<
    Record<string, AttachmentUnavailable>
  >({});
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
  const [themePreference, setThemePreference] = useState<ThemePreference>(
    initialThemePreference,
  );
  const [preferences, setPreferences] =
    useState<UserPreferences>(initialPreferences);
  const [systemScale, setSystemScale] = useState(1);
  const [, setEnvironmentRevision] = useState(0);
  const changePreferences = (value: UserPreferences) => {
    savePreferences(value);
    applyVisualPreferences(value, theme, systemScale);
    setPreferences(value);
  };
  const changeTheme = (value: ThemePreference) => {
    const resolved = applyTheme(value);
    applyVisualPreferences(preferences, resolved, systemScale);
    setThemePreference(value);
    setTheme(resolved);
  };
  useEffect(() => {
    if (themePreference !== "auto") return;
    const update = () => {
      const resolved = applyTheme("auto");
      applyVisualPreferences(preferences, resolved, systemScale);
      setTheme(resolved);
    };
    update();
    return watchSystemTheme(update);
  }, [themePreference, preferences, systemScale]);
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
  const [storedView, storeView] = useState<View | null>(null),
    [selected, setSelected] = useState(""),
    [busy, setBusy] = useState(false),
    [syncSummary, setSyncSummary] = useState(""),
    [action, setAction] = useState<Action | null>(null),
    [values, setValues] = useState<Record<string, string | boolean>>({});
  const view = useExpiringView(storedView);
  const previousUnlockIdentity = useRef<string | undefined>(undefined);
  useEffect(() => {
    const identity = view?.identity;
    const firstOpen =
      previousUnlockIdentity.current === undefined && !!identity;
    previousUnlockIdentity.current = identity;
    // Diagnostic-only marker after the unlocked shell has had a paint opportunity.
    // Normal builds do not expose this bridge or schedule these animation frames.
    if (!firstOpen || !window.eloAppearance?.recordUnlockFrame) return;
    let frame = requestAnimationFrame(() => {
      frame = requestAnimationFrame(() => {
        try {
          window.eloAppearance?.recordUnlockFrame?.();
        } catch {
          // Timing collection must never affect access to the unlocked profile.
        }
      });
    });
    return () => cancelAnimationFrame(frame);
  }, [view?.identity]);
  useEffect(() => {
    if (view && spaceInvitation) openSettings("spaces");
  }, [view?.identity, spaceInvitation]);
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
  const currentConversationScope = useRef(conversationScope);
  currentConversationScope.current = conversationScope;
  const {
    text,
    mentions: draftMentions,
    setContent: setDraftContent,
    ready: draftReady,
    clearSubmitted: clearSubmittedDraft,
    expiry: messageExpiry,
    setExpiry: setMessageExpiry,
    attachment: pendingAttachment,
    setAttachment: setPendingAttachment,
    clear: clearComposerDrafts,
  } = useConversationDraft(
    view ? JSON.stringify([view.identity, view.credential]) : undefined,
    conversationScope,
    (attachment) =>
      void invoke("discard_exchange", { path: attachment.path }).catch(
        () => {},
      ),
    view && streamSummary
      ? {
          identity: view.identity,
          credential: view.credential,
          active_space: view.active_space ?? null,
          space: streamSummary.space,
          stream: streamSummary.stream,
          thread: null,
        }
      : undefined,
    reportError,
  );
  const threadDraftScope =
    view && streamSummary && threadRoot
      ? {
          identity: view.identity,
          credential: view.credential,
          active_space: view.active_space ?? null,
          space: streamSummary.space,
          stream: streamSummary.stream,
          thread: threadRoot,
        }
      : undefined;
  const threadComposerDraft = useConversationDraft(
    view ? JSON.stringify([view.identity, view.credential]) : undefined,
    JSON.stringify(threadDraftScope),
    () => {},
    threadDraftScope,
    reportError,
  );
  const selectingAttachment = useRef(false);
  const postingMessage = useRef(false);
  const outgoing = useOutgoingMessages(
    JSON.stringify([view?.identity, view?.credential]),
    conversationScope,
    history.rows,
    threadHistory.rows,
  );
  const messageScope = JSON.stringify([
    view?.identity,
    view?.active_space,
    streamSummary?.space,
    streamSummary?.stream,
    messagesActive,
    threadActive ? threadRoot : undefined,
  ]);
  const arrival = newMessage?.scope === messageScope ? newMessage : undefined;
  const stream = streamSummary
    ? {
        ...streamSummary,
        rows: outgoing.rows.filter(
          (row) =>
            !view?.blocked_users?.some(
              (p) => p.identity === row.body.issuer_identity,
            ),
        ),
      }
    : streamSummary;
  const calls = useCalls(view);
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
          outgoing.replies.filter(
            (row) =>
              !view?.blocked_users?.some(
                (person) => person.identity === row.body.issuer_identity,
              ),
          ),
          threadRoot,
        )
      : undefined;
  const messageEntrance = useMessageEntrance(
    JSON.stringify([
      messageScope,
      view?.credential,
      view?.blocked_users?.map((person) => person.identity),
      messageQuery,
      threadActive ? threadTarget?.key : messageTarget?.key,
    ]),
    threadActive && selectedThread
      ? [
          ...(selectedThread.root ? [selectedThread.root] : []),
          ...selectedThread.replies,
        ]
      : messageRows,
    (messagesActive || threadActive) &&
      visibleHistory.ready &&
      !visibleHistory.hasNewer &&
      !messageQuery.trim(),
  );
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
    const r = await invoke<{
      view?: View;
      result?: unknown;
      stream?: string;
      sent?: SendReceipt;
    }>("operate", {
      request: {
        ...request,
        expected_identity: view?.identity,
        expected_space: view?.active_space,
      },
    });
    if (request.op === "sync" || request.op === "sync_live")
      receiveSync(r as SyncResult);
    else if (r.view) setView(r.view);
    if (
      request.op === "send" ||
      request.op === "message_action" ||
      request.op === "attachment_upload"
    )
      requestSync();
    if (
      request.op === "remove_member" ||
      request.op === "contact_open" ||
      request.op === "contact_create_chat"
    )
      requestSync(true);
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
  const sendText = (
    value: string,
    thread?: string,
    expiry?: MessageExpiryHours,
    mentions: ComposerMention[] = [],
  ) => {
    if (!view || !stream)
      return Promise.reject(new Error("The profile is locked"));
    const createdAt = recordTimestamp();
    const logicalTime =
      [...stream.rows, ...threadHistory.rows].reduce(
        (highest, row) => Math.max(highest, messageLogicalTime(row)),
        Date.now(),
      ) + 1;
    return outgoing.send(
      {
        scope: conversationScope,
        identity: view.identity,
        credential: view.credential,
        text: value,
        mentions: mentionIdentities(value, mentions),
        createdAt,
        logicalTime,
        thread,
        expiresAt: expiry ? Date.now() + expiry * 3_600_000 : undefined,
      },
      async () => {
        const result = await call({
          op: "send",
          space: stream.space,
          stream: stream.stream,
          text: value,
          mentions: mentionIdentities(value, mentions),
          created_at: createdAt,
          expires_in_hours: expiry,
          ...(thread ? { reply_to: thread } : {}),
        });
        return result.sent!;
      },
    );
  };
  const chooseAttachment = () => {
    if (
      busy ||
      selectingAttachment.current ||
      !stream?.can_post ||
      stream.forked ||
      awaitingDirect
    )
      return;
    selectingAttachment.current = true;
    const scope = conversationScope;
    void perform(async () => {
      try {
        const selected = await invoke<SelectedAttachment | null>(
          "choose_attachment",
        );
        if (!selected) return;
        if (currentConversationScope.current !== scope) {
          await invoke("discard_exchange", { path: selected.path });
          return;
        }
        if (
          currentView.current?.identity === view?.identity &&
          currentView.current?.credential === view?.credential
        )
          setPendingAttachment(selected);
        else await invoke("discard_exchange", { path: selected.path });
      } finally {
        selectingAttachment.current = false;
      }
    });
  };
  const stageMediaAttachment = (file: File | undefined) => {
    if (
      !file ||
      busy ||
      selectingAttachment.current ||
      !stream?.can_post ||
      stream.forked ||
      awaitingDirect
    )
      return;
    selectingAttachment.current = true;
    const scope = conversationScope;
    void perform(async () => {
      try {
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
        if (currentConversationScope.current !== scope) return;
        const selected = await invoke<SelectedAttachment>("stage_attachment", {
          name: file.name || "attachment.bin",
          data: dataUrl.slice(separator + 1),
        });
        if (currentConversationScope.current !== scope) {
          await invoke("discard_exchange", { path: selected.path });
          return;
        }
        if (
          currentView.current?.identity === view?.identity &&
          currentView.current?.credential === view?.credential
        )
          setPendingAttachment(selected);
        else await invoke("discard_exchange", { path: selected.path });
      } finally {
        selectingAttachment.current = false;
      }
    });
  };
  const attachmentDrop = useAttachmentDrop({
    desktop: desktopLayout && !mobile,
    enabled:
      messagesActive &&
      !busy &&
      !!stream?.can_post &&
      !stream.forked &&
      !awaitingDirect,
    scope: conversationScope,
    onFile: stageMediaAttachment,
    onError: reportError,
  });
  const discardAttachment = () => {
    setPendingAttachment(null);
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
  useEffect(() => {
    clearAttachmentPreviews();
    setAttachmentStates({});
  }, [view?.identity, view?.credential]);
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
        const preview = await loadAttachmentPreview(
          {
            expected_identity: view!.identity,
            expected_space: view!.active_space!,
            space: stream.space,
            stream: stream.stream,
            record: row.id,
          },
          true,
        );
        if (preview) {
          await invoke("discard_exchange", { path: output });
        } else if (
          await invoke<boolean>("save_export", { path: output, filename })
        ) {
          await invoke("discard_exchange", { path: output });
          notify(t("file.exportSaved"));
        } else {
          // Closing the system picker discards only this export. The encrypted
          // local copy remains available for another attempt.
          await invoke("discard_exchange", { path: output });
        }
      } catch (error) {
        await invoke("discard_exchange", { path: output }).catch(() => {});
        const state = attachmentFailure(error);
        if (state && currentView.current?.identity === view?.identity)
          setAttachmentStates((current) => ({ ...current, [row.id]: state }));
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
      retryConversationDrafts();
      // Keep a manual refresh bounded; the foreground worker drains the rest.
      try {
        const result = await call({ op: "sync_live" });
        requestSync(true);
        setSyncSummary(
          t("sync.summary", result.result as Record<string, number>),
        );
      } finally {
        // A no-change or failed network pass must not leave already saved
        // messages hidden behind an older local page.
        if (visibleHistory.enabled) await visibleHistory.retry();
      }
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
  const openSessionChat = async (chat: Stream) => {
    const current = currentView.current;
    if (!current) return;
    const identity = current.identity;
    const context = chat.space_context ?? current.active_space;
    let next = current;
    if (context && context !== current.active_space) {
      const result = await invoke<{ view: View }>("operate", {
        request: {
          op: "space_select",
          id: context,
          expected_identity: identity,
        },
      });
      if (
        currentView.current?.identity !== identity ||
        result.view.identity !== identity
      )
        return;
      next = result.view;
      setView(next);
    }
    const verified = next.streams.find(
      (item) =>
        item.space === chat.space &&
        item.stream === chat.stream &&
        (item.space_context ?? next.active_space) === context &&
        !item.forked &&
        item.members.some(
          (member) =>
            member.identity_id === identity &&
            member.capabilities.includes("READ"),
        ),
    );
    if (!verified) return;
    clearMessages();
    openHome("chats");
    setSelected(verified.stream);
    setMessageQuery("");
    setSessionUnread(new Set());
    setConversationOpen(true);
    // A notification opens the verified conversation only. Join always needs
    // a separate user action and the latest signed session state.
  };
  const activityNotifications = useActivityNotifications({
    view,
    mobile,
    ready:
      !!view &&
      !view.space_setup &&
      !biometricOfferPending &&
      !biometricOfferName,
    onMessage: async (entry) => {
      setCollection(null);
      setInvitationRoute(null);
      setNewChat(null);
      setMembersOpen(false);
      return openStreamMessage(entry);
    },
    onChat: openSessionChat,
    onInbox: () => openHome("stream"),
    onError: reportError,
    isSessionAvailable: (target) =>
      !!view &&
      activeSessions(view, calls.getSnapshot().available).some(
        ({ call, chat }) =>
          call.call_id === target.call_id &&
          chat.space === target.space &&
          chat.stream === target.stream &&
          chat.space_context === target.space_context,
      ),
  });
  useSessionStarted(calls, (event) => {
    const sameChat =
      appHasAttention() &&
      (messagesActive || threadActive) &&
      stream?.space === event.chat.space &&
      stream.stream === event.chat.stream &&
      (stream.space_context ?? view?.active_space) === event.chat.space_context;
    if (sameChat) return;
    activityNotifications.session(
      event.chat,
      event.call.call_id,
      t("calls.sessionStartedInSpace", {
        name: event.starterName,
        chat: event.chat.name,
        space: event.spaceName,
      }),
    );
  });
  const storageNotices = useRef(new Map<string, number>());
  useEffect(() => {
    storageNotices.current.clear();
  }, [view?.identity]);
  function receiveSync(result: SyncResult, animateArrival = false) {
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
    if (
      animateArrival &&
      !result.result?.catching_up &&
      !result.result?.more &&
      !isOpeningPush() &&
      stream &&
      result.view.active_space === view?.active_space
    ) {
      const receivedChat = result.view.streams.find(
        (chat) =>
          chat.space === stream.space &&
          chat.stream === stream.stream &&
          chat.space_context === stream.space_context,
      );
      messageEntrance.receive(
        receivedChat?.rows ?? [],
        result.result?.received_messages ?? [],
      );
    }
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
    if (fresh.length > 0 || isOpeningPush()) return;
    const location =
      appHasAttention() && stream && (messagesActive || threadActive)
        ? {
            space: stream.space,
            space_context:
              stream.space_context ?? view?.active_space ?? undefined,
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
      if (!appHasAttention() || document.querySelector("dialog[open]")) return;
      const invites = invitationCount(result.view) > invitationCount(view!);
      const notifications =
        notificationCount(result.view) > notificationCount(view!);
      const page = invites ? "activity" : "notifications";
      if ((invites || notifications) && invitationRoute?.page !== page) {
        showMessage(
          t(invites ? "notifications.invitation" : "notifications.membership"),
          () => {
            const destination = result.view?.spaces?.find(
              (space) =>
                space.status === "joined" &&
                (space.activity ?? 0) >
                  (view?.spaces?.find((old) => old.id === space.id)?.activity ??
                    0),
            );
            void (async () => {
              if (destination && destination.id !== view?.active_space)
                await call({ op: "space_select", id: destination.id });
              setInvitationRoute({ page, unscoped: true });
            })().catch(reportError);
            setCollection(null);
            setNewChat(null);
            setMembersOpen(false);
            setSettingsOpen(false);
          },
        );
      }
      return;
    }
    activityNotifications.messages(entries, result.view);
  }
  const remoteSync = useRef<(space: string) => void>(() => {});
  const realtime = useRealtime(
    view,
    messagesActive || threadActive ? stream : undefined,
    (space) => remoteSync.current(space),
  );
  const remoteUploadCount =
    view && stream
      ? pendingRemoteUploads(
          realtime.value.events,
          view,
          stream,
          realtime.value.now,
        ).length
      : 0;
  const {
    request: requestSync,
    requestRemote,
    progress: syncProgress,
  } = useLiveSync(
    view,
    messagesActive || threadActive,
    busy,
    (result) => receiveSync(result, true),
    () => isOpeningPush() || (visibleHistory.enabled && !visibleHistory.ready),
    realtime.connectedSpaces,
  );
  remoteSync.current = requestRemote;
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
    async (entry, page, space, chat) => {
      if ((page || chat) && space && space !== view?.active_space) {
        await call({ op: "space_select", id: space });
      }
      clearMessages();
      setCollection(null);
      setNewChat(null);
      setMembersOpen(false);
      setInvitationRoute(null);
      if (entry) return openStreamMessage(entry);
      else if (chat) {
        openHome("chats");
        setSelected(chat.stream);
        setMessageQuery("");
        setThreadRoot(undefined);
        setMessageTarget(undefined);
        setConversationOpen(true);
      } else if (page) {
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
    clearComposerDrafts();
    setKeyboardPanel(null);
    setView(null);
    setChatQuery("");
    setMessageQuery("");
    setInvitationRoute(null);
    setSpaceInvitation(null);
    setMembersOpen(false);
    setNewChat(null);
    setMessageStatus(null);
    setHeaderMenu(null);
    setIdentifiersOpen(false);
    setCollection(null);

    setAction(null);
    setValues({});

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
      await flushConversationDrafts();
      try {
        await leaveBeforeLock(calls, () => invoke("lock"));
      } finally {
        clearProfileSession();
      }
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
  const biometricOffer = biometricOfferName && (
    <BiometricOfferDialog
      name={biometricOfferName}
      busy={busy}
      onDecline={dismissBiometricOffer}
      onAccept={acceptBiometricOffer}
    />
  );
  useEffect(() => {
    if (
      !desktopLayout ||
      mobile ||
      !view ||
      view.space_setup ||
      busy ||
      biometricOfferPending ||
      biometricOfferName ||
      notificationOpening
    )
      return;
    const key = (event: KeyboardEvent) => {
      if (document.querySelector("dialog[open]") || desktopProfileEditing)
        return;
      const command = desktopShortcut(event, macKeyboard);
      if (!command) return;
      if (command === "switch" || command === "help") {
        event.preventDefault();
        setKeyboardPanel(command);
        return;
      }
      if (command === "search") {
        if (!messagesActive) return;
        const field = document.querySelector<HTMLInputElement>(
          ".conversation .search-input",
        );
        if (field) {
          event.preventDefault();
          field.focus();
          field.select();
        }
      } else if (command === "compose") {
        event.preventDefault();
        begin(actions[0], { chat_kind: "direct" });
      } else if (command === "preferences") {
        event.preventDefault();
        openSettings("appearance");
      } else if (command === "attach") {
        if (
          !messagesActive ||
          !stream?.can_post ||
          stream.forked ||
          awaitingDirect
        )
          return;
        event.preventDefault();
        chooseAttachment();
      } else {
        const chats = switchableChats(view).filter(
          (chat) => chat.space_context === view.active_space,
        );
        const current = chats.findIndex(
          (chat) =>
            chat.space === stream?.space && chat.stream === stream.stream,
        );
        const direction =
          command === "previous" || command === "unreadPrevious" ? -1 : 1;
        const unreadOnly = command.startsWith("unread");
        for (let offset = 1; offset <= chats.length; offset++) {
          const next =
            chats[
              (current + direction * offset + chats.length * 2) % chats.length
            ];
          if (
            !unreadOnly ||
            (next.unread_count ?? 0) > 0 ||
            next.rows.some((row) => row.unread)
          ) {
            event.preventDefault();
            void openSessionChat(next).catch(reportError);
            break;
          }
        }
      }
    };
    document.addEventListener("keydown", key);
    return () => document.removeEventListener("keydown", key);
  });
  if (!view)
    return (
      <ProfileGate
        appearance={<Appearance theme={theme} onChange={changeTheme} compact />}
        theme={theme}
        onTheme={changeTheme}
        onOpen={(
          value,
          isMobile,
          verifiedPassword,
          demoProfile,
          supportsBiometrics,
        ) => {
          const epoch = ++authenticationEpoch.current;
          setBiometricOfferPending(false);
          storeView(value);
          setMobile(isMobile);
          setBiometricSupported(!!supportsBiometrics);
          setActiveDemoProfile(demoProfile);
          setConversationOpen(false);
          setMembersOpen(false);
          setSettingsOpen(false);
          setChatFilter("overview");
          setHomeTab("chats");
          setMessageTarget(undefined);
          if (supportsBiometrics && (verifiedPassword || demoProfile)) {
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
      <>
        <SpaceSetup
          key={spaceInvitation?.id ?? 0}
          view={view}
          mobile={mobile}
          onView={setView}
          onLock={lockProfile}
          initialLink={spaceInvitation?.link}
          onLinkClosed={() => setSpaceInvitation(null)}
        />
        {biometricOffer}
      </>
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
    <RealtimeProvider value={realtime.value}>
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
        {keyboardPanel === "switch" && (
          <QuickSwitcher
            key={view.identity}
            view={view}
            onClose={() => setKeyboardPanel(null)}
            onOpen={async (chat) => {
              await openSessionChat(chat).catch(reportError);
            }}
          />
        )}
        {keyboardPanel === "help" && (
          <KeyboardHelp
            mac={macKeyboard}
            onClose={() => setKeyboardPanel(null)}
          />
        )}
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
              onScan={() =>
                setInvitationRoute({ page: "scan", contacts: true })
              }
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
            activity={
              mobile ? (
                <ActiveSessions
                  calls={calls}
                  view={view}
                  onOpen={(chat) =>
                    void openSessionChat(chat).catch(reportError)
                  }
                />
              ) : undefined
            }
          />
          {threadActive && stream && selectedThread && (
            <ThreadView
              key={`${view.identity}:${stream.stream}:${selectedThread.rootId}`}
              view={view}
              chat={stream}
              thread={selectedThread}
              messageListRef={messageEntrance.list}
              hideAvatars={preferences.hideAvatars}
              mobile={mobile}
              busy={busy}
              savedDraft={threadComposerDraft}
              onFollow={async (followed) => {
                await perform(async () => {
                  await call({
                    op: "thread_follow",
                    space: stream.space,
                    stream: stream.stream,
                    message: selectedThread.rootId,
                    followed,
                  });
                });
              }}
              onBack={closeThread}
              onRefresh={refresh}
              onRead={markVisibleRead}
              onStatus={setMessageStatus}
              onFile={downloadAttachment}
              downloadingAttachment={downloadingAttachment}
              attachmentStates={attachmentStates}
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
              onSend={async (text, expiry, mentions) => {
                let sent = false;
                await perform(async () => {
                  await sendText(text, selectedThread.rootId, expiry, mentions);
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
                    <span className="avatar">
                      {t("profile.avatar")}
                      <OnlineIndicator identity={view.identity} />
                    </span>
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
                  {mobile && (
                    <ActiveSessions
                      calls={calls}
                      view={view}
                      onOpen={(chat) =>
                        void openSessionChat(chat).catch(reportError)
                      }
                    />
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
          <main
            className="conversation content-pane"
            {...attachmentDrop.handlers}
            data-file-drag={attachmentDrop.dragging || undefined}
          >
            {attachmentDrop.dragging && (
              <div className="attachment-drop-hint" role="status">
                {t("file.dropToAttach")}
              </div>
            )}
            <ScreenHeader
              title={stream?.name ?? t("channel.start")}
              search={
                <SearchField
                  label={t("search.messages")}
                  value={messageQuery}
                  onChange={setMessageQuery}
                />
              }
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
                      (space) =>
                        space.id === view.active_space && space.managed,
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
            {stream && (
              <ActiveSessionJoin calls={calls} view={view} chat={stream} />
            )}
            {stream?.forked && <p className="error">{t("warning.forked")}</p>}
            {mode === "expert" && syncSummary && (
              <p className="notice" role="status">
                {syncSummary}
              </p>
            )}
            <div
              className="searchable-list"
              ref={threadActive ? undefined : messageEntrance.list}
            >
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
                              {t(
                                r.body.expired
                                  ? "messageActions.expired"
                                  : "messageActions.deleted",
                              )}
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
                              canReply={
                                !r.local_echo &&
                                !!stream?.can_post &&
                                !stream.forked
                              }
                              onOpen={() => openThread(r, !entry.thread)}
                            />
                          ) : (
                            <AttachmentButton
                              row={r}
                              context={
                                view.active_space && stream
                                  ? {
                                      expected_identity: view.identity,
                                      expected_space: view.active_space,
                                      space: stream.space,
                                      stream: stream.stream,
                                    }
                                  : undefined
                              }
                              disabled={busy}
                              serverState={attachmentStates[r.id]}
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
                {!history.hasNewer && !messageQuery.trim() && (
                  <RemoteUploads
                    view={view}
                    chat={stream}
                    hideAvatars={preferences.hideAvatars}
                  />
                )}
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
                  !remoteUploadCount &&
                  !stream?.rows.length && (
                    <EmptyState
                      message={
                        awaitingDirect
                          ? t("dm.waiting")
                          : stream
                            ? t("channel.noMessages")
                            : t("groups.empty")
                      }
                    />
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
                      (space) =>
                        space.id === view.active_space && space.managed,
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
            <TypingIndicator chat={stream} />
            <form
              className="composer"
              data-message-expiry={messageExpiry}
              onSubmit={(e) => {
                e.preventDefault();
                if (
                  stream &&
                  !busy &&
                  !postingMessage.current &&
                  draftReady &&
                  stream.can_post &&
                  !stream.forked &&
                  !awaitingDirect &&
                  (text || pendingAttachment)
                ) {
                  postingMessage.current = true;
                  void perform(async () => {
                    let committed = false;
                    if (text) {
                      const submittedDraft = {
                        text,
                        expiry: messageExpiry,
                        mentions: draftMentions,
                        attachment: pendingAttachment,
                      };
                      setMessageTarget(undefined);
                      setOwnSendRevision((revision) => revision + 1);
                      try {
                        await sendText(
                          text,
                          undefined,
                          messageExpiry,
                          draftMentions,
                        );
                        clearSubmittedDraft(submittedDraft);
                      } catch (error) {
                        throw error;
                      }
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
                        // The draft store releases the native staging capability
                        // after persisting the cleared attachment selection.
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
                    if (committed) {
                      setMessageTarget(undefined);
                      setOwnSendRevision((revision) => revision + 1);
                    }
                  }).finally(() => {
                    postingMessage.current = false;
                  });
                }
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
                        <span
                          className="composer-upload-progress"
                          role="status"
                        >
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
                onPasteImage={stageMediaAttachment}
                value={text}
                mentions={draftMentions}
                mentionCandidates={
                  stream ? mentionCandidates(view, stream) : []
                }
                onDraftChange={setDraftContent}
                editTarget={
                  stream?.can_post && !stream.forked
                    ? (() => {
                        const row = [...stream.rows]
                          .reverse()
                          .find(
                            (row) =>
                              row.body.kind === "chat.message" &&
                              row.body.issuer_identity === view.identity &&
                              !row.local_echo,
                          );
                        return row ? { chat: stream, row } : undefined;
                      })()
                    : undefined
                }
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
              <div className="composer-actions">
                <ComposerExpiry
                  value={messageExpiry}
                  onChange={setMessageExpiry}
                  disabled={busy || !stream?.can_post}
                />
                <button
                  type="button"
                  className="composer-attach"
                  aria-label={t("file.attach")}
                  title={t("file.attach")}
                  disabled={
                    !stream?.can_post || stream.forked || awaitingDirect || busy
                  }
                  onClick={(event) =>
                    setAttachmentMenu(
                      event.currentTarget.getBoundingClientRect(),
                    )
                  }
                >
                  <Icon name="plus" />
                </button>
                <button
                  aria-label={t("composer.send")}
                  title={t("composer.send")}
                  disabled={
                    !draftReady ||
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
                biometricSupported={biometricSupported}
                blockedUsersPage={<BlockedUsers view={view} />}
                serviceRequests={
                  <ServiceRequests view={view} mobile={mobile} />
                }
                spaceContext={
                  <CurrentSpace
                    view={view}
                    onManage={() => setSettingsPage("spaces")}
                  />
                }
                spacesPage={
                  <Spaces
                    key={spaceInvitation?.id ?? 0}
                    view={view}
                    mobile={mobile}
                    hideAvatars={preferences.hideAvatars}
                    onView={setView}
                    initialPage={spaceInvitation ? "join" : "list"}
                    initialLink={spaceInvitation?.link}
                    onBack={() => {
                      setSpaceInvitation(null);
                      setSettingsPage("profile");
                    }}
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
                themePreference={themePreference}
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
                notificationSettings={
                  mobile ? pushSettings : activityNotifications.settings
                }
                soundSettings={activityNotifications.soundSettings}
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
              onSpaces={(link) => {
                setInvitationRoute(null);
                if (link) openSpaceInvitation(link);
                else setSpaceInvitation(null);
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
          {biometricOffer}
          {notificationOffer}
          {activityNotifications.offer}
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
                        setValues({
                          ...values,
                          [field.key]: event.target.value,
                        })
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
          <div
            className="notification-opening"
            role="status"
            aria-live="polite"
          >
            <span className="invitation-qr-loader" aria-hidden="true" />
            <p>{t("notifications.opening")}</p>
          </div>
        )}
      </MessageActionsProvider>
    </RealtimeProvider>
  );
}
createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <ToastProvider>
      <WindowChrome />
      <AccountDeletionNotice />
      <UpdateGate>
        <App />
      </UpdateGate>
    </ToastProvider>
  </React.StrictMode>,
);
