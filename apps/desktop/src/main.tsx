import { t, warningText, messageDayKey, formatMessageDay } from "./i18n";
import React, { useEffect, useRef, useState } from "react";
import { createRoot } from "react-dom/client";
import { invoke } from "@tauri-apps/api/core";
import {
  permissionText,
  recordTimestamp,
  profileName,
  notificationCount,
  invitationCount,
  senderName,
  isNewMessage,
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
import { Icon, NewIndicator } from "./Icon";
import { ActionDialog } from "./ActionDialog";
import { FloatingSearch, SearchField } from "./Search";
import { EmptyState } from "./EmptyState";
import { ProfileGate } from "./ProfileGate";
import { ToastProvider, useToast } from "./Toast";
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
} from "./biometric";

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
type Field = { key: string; label: string; type?: "checkbox" | "select" };
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
    id: "import_stream",
    title: t("action.importConfig.title"),
    global: true,
    description: t("action.importConfig.description"),
    fields: [
      f("name", t("field.channelName")),
      f("path", t("field.encryptedConfig")),
      f("space", t("field.confirmedSpace")),
      f("stream", t("field.streamId")),
      f("root", t("field.confirmedRoot")),
    ],
  },
  {
    id: "add_peer",
    title: t("action.addReplica.title"),
    global: true,
    description: t("action.addReplica.description"),
    fields: [f("path", t("field.replicaDescriptor"))],
  },
  {
    id: "invite_create",
    title: t("action.createInvite.title"),
    description: t("action.createInvite.description"),
    fields: [f("output", t("field.newInvitation"))],
  },
  {
    id: "invite_request",
    title: t("action.answerInvite.title"),
    global: true,
    description: t("action.answerInvite.description"),
    fields: [
      f("path", t("field.invitationFile")),
      f("space", t("field.confirmedSpace")),
      f("root", t("field.confirmedRoot")),
      f("output", t("field.newJoinRequest")),
    ],
  },
  {
    id: "invite_approve",
    title: t("action.approveCandidate.title"),
    description: t("action.approveCandidate.description"),
    fields: [
      f("path", t("field.joinRequest")),
      f("fingerprint", t("field.confirmedIdentity")),
      { key: "post", label: t("field.allowPost"), type: "checkbox" },
      {
        key: "share_history",
        label: t("field.allowHistory"),
        type: "checkbox",
      },
      f("output", t("field.candidateConfig")),
    ],
  },
  {
    id: "export_config",
    title: t("action.exportConfig.title"),
    description: t("action.exportConfig.description"),
    fields: [
      f("credential", t("field.memberCredential")),
      f("output", t("field.newConfig")),
    ],
  },
  {
    id: "remove_member",
    title: t("action.removeMember.title"),
    description: t("action.removeMember.description"),
    fields: [f("fingerprint", t("field.removedIdentity"))],
  },
  {
    id: "history_request",
    title: t("action.requestHistory.title"),
    description: t("action.requestHistory.description"),
    fields: [
      { key: "count", label: t("field.maximumMessages"), type: "select" },
      f("output", t("field.newHistoryRequest")),
    ],
  },
  {
    id: "history_preview",
    title: t("action.shareHistory.title"),
    description: t("action.shareHistory.description"),
    fields: [
      f("path", t("field.signedRequest")),
      f("output", t("field.newEncryptedBundle")),
    ],
  },
  {
    id: "history_import",
    title: t("action.importHistory.title"),
    description: t("action.importHistory.description"),
    fields: [
      f("request", t("field.originalRequest")),
      f("path", t("field.historyBundle")),
    ],
  },
  {
    id: "file_share",
    title: t("action.shareFile.title"),
    description: t("action.shareFile.description"),
    fields: [f("path", t("field.filePath"))],
  },
  {
    id: "file_download",
    title: t("action.downloadFile.title"),
    description: t("action.downloadFile.description"),
    fields: [
      f("record", t("field.metadataRecord")),
      f("output", t("field.newFilePath")),
    ],
  },
  {
    id: "device_export",
    title: t("action.exportDevice.title"),
    global: true,
    description: t("action.exportDevice.description"),
    fields: [f("output", t("field.newDevicePublicKey"))],
  },
  {
    id: "recovery_export",
    title: t("action.helpRecovery.title"),
    description: t("action.helpRecovery.description"),
    fields: [
      f("path", t("field.devicePublicKey")),
      f("credential", t("field.confirmedCredential")),
      f("output", t("field.newEncryptedConfig")),
    ],
  },
  {
    id: "controller_recover",
    title: t("action.recoverControl.title"),
    global: true,
    description: t("action.recoverControl.description"),
    fields: [
      f("name", t("field.channelName")),
      f("path", t("field.participantConfig")),
      f("space", t("field.confirmedSpace")),
      f("stream", t("field.streamId")),
      f("root", t("field.confirmedRoot")),
      f("recovery_card", t("field.recoveryCard")),
    ],
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
const commonActions = new Set([
  "create_chat",
  "set_chat_group",
  "invite_create",
  "invite_request",
  "file_share",
]);
const membershipActions = new Set([
  "invite_create",
  "invite_approve",
  "export_config",
  "remove_member",
]);

type Preview = {
  request_id: string;
  recipient: string;
  selection: { id: string; text: string }[];
};
type ConfigPreview = {
  expected_proof: string;
  expected_config: string;
  expected_recovery: string | null;
  controller: string;
  new_device: string;
  local_head: string | null;
  forked: boolean;
  members: View["streams"][number]["members"];
  warning: string;
  warning_code?: string;
};
function App() {
  useViewport();
  useInputModality();
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
  const threadReturnRow = useRef<string | undefined>(undefined);
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
  const membersButtonRef = useRef<HTMLButtonElement>(null);
  const [ownSendRevision, setOwnSendRevision] = useState(0);
  const [sessionUnread, setSessionUnread] = useState<Set<string>>(
    () => new Set(),
  );
  const [logoutOpen, setLogoutOpen] = useState(false);
  const [biometricOfferName, setBiometricOfferName] = useState("");
  const [biometricOfferPending, setBiometricOfferPending] = useState(false);
  const authenticationEpoch = useRef(0);
  const biometricOfferCredential = useRef({
    password: "",
    demoProfile: undefined as string | undefined,
  });
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [headerMenu, setHeaderMenu] = useState<{
    anchor: DOMRect;
    conversation: boolean;
  } | null>(null);
  const [identifiersOpen, setIdentifiersOpen] = useState(false);
  const [settingsPage, setSettingsPage] = useState<SettingsPage>("actions");
  const openSettings = (page: SettingsPage = "actions") => {
    setSettingsPage(page);
    setSettingsOpen(true);
  };
  const [pendingExport, setPendingExport] = useState("");
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
      if (e.key === "Escape" && settingsOpen) {
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
  }, [settingsOpen, settingsPage]);
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
    [values, setValues] = useState<Record<string, string | boolean>>({}),
    [preview, setPreview] = useState<Preview | null>(null),
    [configPreview, setConfigPreview] = useState<ConfigPreview | null>(null),
    [confirmedRecovery, setConfirmedRecovery] = useState(false);
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
    setText("");
    setThreadDrafts({});
    setAction(null);
    setPreview(null);
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
  const [chatFilter, setChatFilter] = useState("dms");
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
    !newChat;
  const streamActive =
    homeTab === "stream" &&
    !conversationOpen &&
    !settingsOpen &&
    !membersOpen &&
    !invitationRoute &&
    !newChat;
  const chatsActive =
    homeTab === "chats" &&
    !conversationOpen &&
    !settingsOpen &&
    !invitationRoute &&
    !newChat;
  const contactsActive =
    homeTab === "contacts" &&
    !conversationOpen &&
    !settingsOpen &&
    !invitationRoute &&
    !newChat;
  const messagesActive =
    (conversationOpen || (!mobile && homeTab === "chats")) &&
    !threadActive &&
    !settingsOpen &&
    !membersOpen &&
    !invitationRoute &&
    !newChat;
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
    threadActive ? threadRoot : undefined,
    threadActive ? threadTarget?.id : messageTarget?.id,
    preparedHistory,
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
  const stream =
    streamSummary && history.enabled
      ? { ...streamSummary, rows: history.rows }
      : streamSummary;
  const personalDM =
    stream?.chat_kind === "direct" && stream.members.length === 2;
  const awaitingDirect =
    !!stream?.direct_invitation &&
    !stream.members.some((member) => member.identity_id !== view?.identity);
  const timeline = chatTimeline(stream?.rows ?? [], messageQuery);
  const messageRows = timeline.map((entry) => entry.row);
  const firstMessageIndex = timeline.findIndex((entry) => !entry.placeholder);
  const selectedThread =
    threadRoot && stream ? findThread(stream.rows, threadRoot) : undefined;
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
    if (r.view) {
      if (request.op === "sync" || request.op === "sync_live")
        receiveSync(r as SyncResult);
      else setView(r.view);
    }
    if (request.op === "send" || request.op === "message_action") requestSync();
    if (request.op === "remove_member") requestSync(true);
    return r;
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
    setThreadRoot(undefined);
    setHomeTab(tab);
    setSettingsOpen(false);
    setConversationOpen(false);
    setMembersOpen(false);
    setInvitationRoute(null);
    setMessageTarget(undefined);
  };
  const openThread = (
    row: MessageRow,
    compose: boolean,
    chat = stream,
    fromSearch = !!messageQuery.trim(),
  ) => {
    if (!chat) return;
    const rootId = replyRoot(row) ?? row.id;
    if (threadRoot !== rootId || stream?.stream !== chat.stream) {
      const thread = findThread(chat.rows, rootId);
      threadReturnRow.current = fromSearch
        ? row.id
        : (thread.root?.id ?? thread.replies[0]?.id ?? row.id);
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
    if (threadReturnRow.current)
      setMessageTarget({
        id: threadReturnRow.current,
        key: ++messageTargetSerial.current,
      });
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
      openThread(entry.row, false, entry.chat, false);
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
    if (!stream || isOpeningPush()) return;
    const identity = view?.identity;
    const currentChat = stream;
    const unseen = records.filter(
      (id) =>
        !manuallyUnread.current.has(id) &&
        currentChat.rows.some((row) => row.id === id && row.unread),
    );
    if (!unseen.length) return;
    history.markRead(unseen);
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
  function receiveSync(result: SyncResult) {
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
    () => isOpeningPush() || (history.enabled && !history.ready),
  );
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
    () => history.enabled && !history.ready,
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
    if (pendingExport) {
      setError(t("file.exportPending"));
      setSettingsOpen(false);
      setMembersOpen(false);
      return;
    }
    setSettingsOpen(false);
    if (a.id === "create_chat") {
      setNewChat({
        kind: "direct",
        group: view?.groups?.some((g) => g.id === chatFilter) ? chatFilter : "",
      });
      setError("");
      return;
    }
    setAction(a);
    setGroupDraft(false);
    setValues({
      count: "20",
      ...(a.id === "set_chat_group" ? { group: stream?.group ?? "" } : {}),
      ...initial,
    });
    if (mobile && a.fields.some((f) => f.key === "output")) {
      void perform(async () => {
        const output = await invoke<string>("prepare_export", { kind: a.id });
        setValues((values) => ({ ...values, output }));
      });
    }
    setPreview(null);
    setConfigPreview(null);
    setConfirmedRecovery(false);
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
        ...(values.count ? { count: Number(values.count) } : {}),
      };
      if (action.id === "history_preview" && !preview) {
        setPreview(await invoke("operate", { request }));
        return;
      }
      if (
        ["controller_recover", "import_stream"].includes(action.id) &&
        !configPreview
      ) {
        setConfigPreview(
          await invoke("operate", {
            request: {
              ...request,
              op:
                action.id === "controller_recover"
                  ? "recovery_preview"
                  : "config_preview",
            },
          }),
        );
        return;
      }
      await call(
        configPreview
          ? {
              ...request,
              expected_proof: configPreview.expected_proof,
              expected_config: configPreview.expected_config,
              expected_recovery: configPreview.expected_recovery,
              confirmed_recovery: confirmedRecovery,
            }
          : preview
            ? {
                ...request,
                op: "history_approve",
                expected_request: preview.request_id,
                selection: preview.selection.map((r) => r.id),
              }
            : request,
      );
      if (mobile && typeof values.output === "string") {
        setPendingExport(values.output);
        setConversationOpen(true);
        setMembersOpen(false);
      }
      setAction(null);
      setPreview(null);
      setConfigPreview(null);
      setConfirmedRecovery(false);
      setValues({});
      if (action.id !== "remove_member") notify(t("notice.confirmed"));
    });
  const lockProfile = () =>
    void perform(async () => {
      await invoke("lock");
      setView(null);
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
      setPreview(null);
      setAction(null);
      setValues({});
      setConfigPreview(null);
      setPendingExport("");
      setConfirmedRecovery(false);
      setLogoutOpen(false);
      setActiveDemoProfile(undefined);
      setBiometricOfferName("");
      authenticationEpoch.current += 1;
      setBiometricOfferPending(false);
      biometricOfferCredential.current = {
        password: "",
        demoProfile: undefined,
      };
    });
  const dismissBiometricOffer = () => {
    markBiometricOfferHandled();
    biometricOfferCredential.current = {
      password: "",
      demoProfile: undefined,
    };
    setBiometricOfferName("");
  };
  const acceptBiometricOffer = () =>
    void perform(async () => {
      await enableBiometricUnlock(
        biometricOfferCredential.current.password,
        biometricOfferCredential.current.demoProfile,
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
          setChatFilter("dms");
          setHomeTab("chats");
          setMessageTarget(undefined);
          if (
            isMobile &&
            (verifiedPassword || demoProfile) &&
            shouldOfferBiometricUnlock()
          ) {
            setBiometricOfferPending(true);
            biometricOfferCredential.current = {
              password: verifiedPassword ?? "",
              demoProfile,
            };
            void readBiometricState()
              .then((state) => {
                if (authenticationEpoch.current !== epoch) return;
                if (state.available && !state.enabled)
                  setBiometricOfferName(biometricName(state.type));
                else
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
      onClick={() =>
        a.id === "invite_request"
          ? setInvitationRoute({ page: "scan" })
          : begin(a)
      }
    >
      {a.title}
      <Icon name="next" />
    </button>
  );
  const scopedActions = (conversation: boolean) =>
    actions
      .filter((a) => {
        if (!conversation) return a.id === "create_group";
        if (!stream) return false;
        if (a.id === "export_config")
          return (
            mode === "expert" && stream.can_manage_members && !stream.forked
          );
        return (
          !a.global &&
          a.id !== "file_download" &&
          !membershipActions.has(a.id) &&
          (commonActions.has(a.id) || mode === "expert")
        );
      })
      .sort(
        (a, b) =>
          Number(commonActions.has(b.id)) - Number(commonActions.has(a.id)),
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
            onFile={(row) =>
              begin(
                actions.find((a) => a.id === "file_download")!,
                { record: row.id },
              )
            }
            composeRevision={threadComposeRevision}
            target={threadTarget}
            newMessage={arrival}
            onJumpToLatest={(id) =>
              setThreadTarget({ id, key: ++messageTargetSerial.current })
            }
            historyLoading={history.loading}
            historyReady={history.ready}
            hasOlder={history.hasMore}
            hasNewer={history.hasNewer}
            onNewer={history.loadNewer}
            onRetry={history.retry}
            onOlder={history.loadMore}
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
        <aside>
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
                  <small title={mode === "expert" ? view.identity : undefined}>
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
                <div className="sync-progress" role="status" aria-live="polite">
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
              <div className="section-label expert-only">
                {t("replica.heading")}
                <span>{view.replicas.length}</span>
              </div>
              {view.replicas.map((p) => (
                <div className="replica expert-only" key={p.id + p.mailbox}>
                  <i />
                  <span title={p.id}>
                    {p.id.slice(0, 16)}…<small>{t("replica.role")}</small>
                  </span>
                </div>
              ))}
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
                  className="secondary expert-only"
                  disabled={busy}
                  onClick={() => begin(actions[2])}
                >
                  {t("action.addReplica.title")}
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
        <main className="conversation">
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
                <button
                  type="button"
                  className="secondary desktop-only"
                  disabled={busy}
                  onClick={() => void refresh()}
                >
                  {busy ? t("sync.busy") : t("refresh.action")}
                </button>
                {!personalDM && (
                  <button
                    ref={membersButtonRef}
                    type="button"
                    className="icon"
                    aria-label={t("members.heading")}
                    aria-expanded={membersOpen}
                    disabled={!stream}
                    onClick={() => {
                      setSettingsOpen(false);
                      setMembersOpen(true);
                    }}
                  >
                    <Icon name="people" />
                  </button>
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
          {pendingExport && (
            <div className="notice" role="status">
              <p>{t("file.exportReady")}</p>
              <button
                disabled={busy}
                onClick={() =>
                  void perform(async () => {
                    if (
                      await invoke<boolean>("save_export", {
                        path: pendingExport,
                      })
                    ) {
                      setPendingExport("");
                      notify(t("file.exportSaved"));
                    }
                  })
                }
              >
                {t("file.export")}
              </button>
            </div>
          )}
          <div className="searchable-list">
            <PullToRefresh
              className="messages"
              enabled={mobile && messagesActive}
              disabled={busy}
              onRefresh={refresh}
              resetKey={messageScope + String(settingsOpen)}
              newMessage={arrival}
              onJumpToLatest={(id) =>
                setMessageTarget({ id, key: ++messageTargetSerial.current })
              }
              showNewMessageButton={messagesActive && !messageQuery.trim()}
              scrollToEndKey={
                messagesActive && !messageTarget && !messageQuery.trim()
                  ? `${view.identity}:${stream?.stream}:${ownSendRevision}:${stream?.rows.filter((row) => row.body.issuer_identity === view.identity).at(-1)?.id ?? ""}`
                  : undefined
              }
              scrollToRecord={messagesActive ? messageTarget : undefined}
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
              {messageTarget && view.paged && (
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
                      messageDayKey(r.body.created_at) !==
                        messageDayKey(
                          messageRows[index - 1].body.created_at,
                        ) && (
                        <h3 className="message-day">
                          <span>{formatMessageDay(r.body.created_at)}</span>
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
                      data-target={messageTarget?.id === r.id || undefined}
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
                        onStatus={setMessageStatus}
                      >
                        {r.body.kind === "chat.message" ? (
                          <MessageBubble
                            key={`${view.identity}:${stream?.stream}:${r.id}`}
                            text={r.body.payload?.text ?? ""}
                            thread={entry.thread}
                            canReply={!!stream?.can_post && !stream.forked}
                            onOpen={() => openThread(r, !entry.thread)}
                          />
                        ) : (
                          <button
                            className="attachment"
                            disabled={busy}
                            onClick={() =>
                              begin(
                                actions.find((a) => a.id === "file_download")!,
                                { record: r.id },
                              )
                            }
                          >
                            ↓{" "}
                            {t("file.downloadLabel", {
                              filename: r.body.filename ?? "",
                              bytes: r.body.size_bytes ?? 0,
                            })}
                            <small>{t("file.onDemand")}</small>
                          </button>
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
              <FloatingSearch
                key={stream?.stream}
                label={t("search.messages")}
                value={messageQuery}
                onChange={setMessageQuery}
              />
            )}
          </div>
          <form
            className="composer"
            onSubmit={(e) => {
              e.preventDefault();
              if (stream && !awaitingDirect)
                void perform(async () => {
                  await call({
                    op: "send",
                    space: stream.space,
                    stream: stream.stream,
                    text,
                    created_at: recordTimestamp(),
                  });
                  setText("");
                  setMessageTarget(undefined);
                  setOwnSendRevision((revision) => revision + 1);
                });
            }}
          >
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
                aria-label={t("composer.send")}
                title={t("composer.send")}
                disabled={
                  !text ||
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
          className="details"
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
              onProfile={async ({ name, avatar }) => {
                setBusy(true);
                try {
                  const result = await invoke<{ view: View }>("operate", {
                    request: { op: "set_profile_details", name, avatar },
                  });
                  setView(result.view);
                } finally {
                  setBusy(false);
                }
              }}
              onInvitations={() =>
                setInvitationRoute({ page: "activity", unscoped: true })
              }
              onNotifications={() =>
                setInvitationRoute({ page: "notifications", unscoped: true })
              }
              onCode={() => setInvitationRoute({ page: "contact" })}
              notificationSettings={pushSettings}
              advancedActions={actions
                .filter(
                  (a) =>
                    a.global &&
                    !["create_chat", "create_group", "invite_request"].includes(
                      a.id,
                    ),
                )
                .map(actionButton)}
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
              requestAnimationFrame(() => membersButtonRef.current?.focus());
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
                    notify(
                      t(
                        (result as { notification_pending?: boolean })
                          .notification_pending
                          ? "notifications.mutePending"
                          : muted
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
          <div className="scrim">
            <section
              className="dialog"
              role="dialog"
              aria-modal="true"
              aria-labelledby="dialog-title"
            >
              <button
                aria-label={t("dialog.close")}
                className="close"
                disabled={busy}
                onClick={() => {
                  setAction(null);
                  setPreview(null);
                  setConfigPreview(null);
                  setConfirmedRecovery(false);
                  setValues({});
                }}
              >
                <Icon name="close" />
              </button>
              <span className="eyebrow">{t("dialog.eyebrow")}</span>
              <h2 id="dialog-title">{action.title}</h2>
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
                {action.fields
                  .filter((f) => !mobile || f.key !== "output")
                  .map((f) => (
                    <label
                      key={f.key}
                      className={f.type === "checkbox" ? "check" : ""}
                    >
                      {f.type === "checkbox" ? (
                        <>
                          <input
                            type="checkbox"
                            checked={Boolean(values[f.key])}
                            onChange={(e) =>
                              setValues({
                                ...values,
                                [f.key]: e.target.checked,
                              })
                            }
                          />
                          {f.label}
                        </>
                      ) : (
                        <>
                          {f.label}
                          {f.type === "select" ? (
                            <select
                              value={String(values[f.key] ?? "20")}
                              onChange={(e) =>
                                setValues({
                                  ...values,
                                  [f.key]: e.target.value,
                                })
                              }
                            >
                              {["20", "50", "100"].map((o) => (
                                <option key={o}>{o}</option>
                              ))}
                            </select>
                          ) : ["path", "request", "recovery_card"].includes(
                              f.key,
                            ) ? (
                            <>
                              {(!mobile || mode === "expert") && (
                                <input
                                  required
                                  value={String(values[f.key] ?? "")}
                                  autoComplete="off"
                                  autoCapitalize="none"
                                  autoCorrect="off"
                                  spellCheck={false}
                                  disabled={!!preview || !!configPreview}
                                  onChange={(e) =>
                                    setValues({
                                      ...values,
                                      [f.key]: e.target.value,
                                    })
                                  }
                                />
                              )}
                              <button
                                type="button"
                                className="secondary"
                                disabled={busy || !!preview || !!configPreview}
                                onClick={() =>
                                  void perform(async () => {
                                    const path = await invoke<string | null>(
                                      "choose_import",
                                    );
                                    if (path)
                                      setValues((values) => ({
                                        ...values,
                                        [f.key]: path,
                                      }));
                                  })
                                }
                              >
                                {values[f.key]
                                  ? t("file.selected")
                                  : t("file.choose")}
                              </button>
                            </>
                          ) : (
                            <input
                              required
                              value={String(values[f.key] ?? "")}
                              autoComplete="off"
                              autoCapitalize="none"
                              autoCorrect="off"
                              spellCheck={false}
                              disabled={!!preview || !!configPreview}
                              onChange={(e) =>
                                setValues({
                                  ...values,
                                  [f.key]: e.target.value,
                                })
                              }
                            />
                          )}
                        </>
                      )}
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
                {configPreview && (
                  <div className="preview">
                    <p>
                      {warningText(
                        configPreview.warning_code,
                        configPreview.warning,
                      )}
                    </p>
                    {configPreview.forked && (
                      <p className="error">{t("warning.conflictingProof")}</p>
                    )}
                    <label>
                      {t("preview.configuration")}
                      <code>{configPreview.expected_config}</code>
                    </label>
                    {configPreview.local_head &&
                      configPreview.local_head !==
                        configPreview.expected_config && (
                        <label>
                          {t("preview.localHead")}
                          <code>{configPreview.local_head}</code>
                        </label>
                      )}
                    {action.id === "controller_recover" && (
                      <label>
                        {t("preview.newDevice")}
                        <code>{configPreview.new_device}</code>
                        <small>{t("preview.replacesDevices")}</small>
                      </label>
                    )}
                    <strong>{t("preview.members")}</strong>
                    {configPreview.members.map((m) => (
                      <div className="member" key={m.identity_id}>
                        <code>{m.identity_id}</code>
                        <small>
                          {m.capabilities.map(permissionText).join(", ")}
                        </small>
                        {(action.id === "controller_recover" &&
                        m.identity_id === view.identity
                          ? [configPreview.new_device]
                          : m.credential_ids
                        ).map((id) => (
                          <code key={id}>{id}</code>
                        ))}
                      </div>
                    ))}
                    {(action.id === "controller_recover" ||
                      configPreview.expected_recovery) && (
                      <label className="check">
                        <input
                          type="checkbox"
                          checked={confirmedRecovery}
                          onChange={(e) =>
                            setConfirmedRecovery(e.target.checked)
                          }
                        />
                        {t("preview.confirmRecovery")}
                      </label>
                    )}
                    <button
                      type="button"
                      className="secondary"
                      disabled={busy}
                      onClick={() => {
                        setConfigPreview(null);
                        setConfirmedRecovery(false);
                      }}
                    >
                      {t("preview.back")}
                    </button>
                  </div>
                )}
                {preview && (
                  <div className="preview">
                    <strong>
                      {t("preview.recipient", { recipient: preview.recipient })}
                    </strong>
                    <p>
                      {t("preview.selection", {
                        count: preview.selection.length,
                      })}
                    </p>
                    {preview.selection.map((r) => (
                      <label key={r.id}>
                        <input
                          type="checkbox"
                          checked
                          onChange={() =>
                            setPreview({
                              ...preview,
                              selection: preview.selection.filter(
                                (x) => x.id !== r.id,
                              ),
                            })
                          }
                        />
                        <span>
                          {r.text}
                          <code>{r.id}</code>
                        </span>
                      </label>
                    ))}
                  </div>
                )}
                <button
                  disabled={
                    busy ||
                    groupDraft ||
                    action.fields.some(
                      (f) => f.type !== "checkbox" && !values[f.key],
                    ) ||
                    (preview !== null && !preview.selection.length) ||
                    (configPreview !== null &&
                      (action.id === "controller_recover" ||
                        configPreview.expected_recovery !== null) &&
                      !confirmedRecovery)
                  }
                >
                  {busy
                    ? t("dialog.verifying")
                    : configPreview
                      ? action.id === "controller_recover"
                        ? t("dialog.confirmRecovery")
                        : t("dialog.confirmConfig")
                      : preview
                        ? t("dialog.confirmHistory")
                        : ["controller_recover", "import_stream"].includes(
                              action.id,
                            )
                          ? t("dialog.previewConfig")
                          : action.id === "history_preview"
                            ? t("dialog.previewHistory")
                            : action.id === "set_chat_group"
                              ? t("groups.save")
                              : action.id === "create_group"
                                ? t("contacts.save")
                                : action.id === "remove_member"
                                  ? t("members.remove")
                                  : t("dialog.execute")}
                </button>
              </form>
            </section>
          </div>
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
      <App />
    </ToastProvider>
  </React.StrictMode>,
);
