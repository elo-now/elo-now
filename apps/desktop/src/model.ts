import { t } from "./i18n";
/** Signed records require UTC whole seconds; keep display/reminder dates separate. */
export const recordTimestamp = (date = new Date()): string =>
  date.toISOString().replace(/\.\d{3}Z$/, "Z");
export const statusText = (s: string): string =>
  ({
    LOCAL: t("status.local"),
    QUEUED: t("status.queued"),
    ACCEPTED: t("status.accepted"),
    STORED: t("status.stored"),
    REPAIR_PENDING: t("status.repairPending"),
    HELD_STALE_CONFIG: t("status.held"),
    QUARANTINED_STALE: t("status.quarantined"),
    WAITING_FOR_PROOF: t("status.waiting"),
    REJECTED: t("status.rejected"),
  })[s] ?? s;
export const permissionText = (capability: string): string =>
  ({
    READ: t("permission.read"),
    POST: t("permission.post"),
    SHARE_HISTORY: t("permission.shareHistory"),
    MANAGE: t("permission.manage"),
    REPLICATE: t("permission.replicate"),
  })[capability] ?? capability;
export type SpaceSummary = {
  id: string;
  name: string;
  status: "joined" | "pending" | "declined";
  owner: boolean;
  requests: number;
  activity?: number;
  managed: boolean;
};
export type Stream = {
  is_general?: boolean;
  space_context?: string;
  name: string;
  chat_kind?: "chat" | "direct";
  direct_invitation?: {
    people: string[];
    pending: string[];
    active: boolean;
    expires_at: number;
    automatic: boolean;
    delivered: boolean;
    link: string;
  } | null;
  group?: string | null;
  /** Private profile preference; unread state and delivery are unaffected. */
  muted?: boolean;
  created_at?: number;
  space: string;
  stream: string;
  head: string;
  controller: string;
  recovery: string | null;
  forked: boolean;
  can_post: boolean;
  can_manage_members?: boolean;
  owners: { identity_id: string }[];
  member_names?: Record<string, string>;
  members: {
    identity_id: string;
    identity_type?: string;
    external: boolean;
    capabilities: string[];
    credential_ids: string[];
  }[];
  rows: {
    reply_count?: number;
    id: string;
    state: string;
    unread?: boolean;
    marked_unread?: boolean;
    pinned?: boolean;
    reactions?: {
      emoji: string;
      count: number;
      mine: boolean;
      people: string[];
    }[];
    body: {
      logical_time?: number;
      issuer_credential?: string;
      kind: string;
      issuer_identity: string;
      created_at?: string;
      payload?: { text: string; sender_name?: string; thread_root?: string };
      filename?: string;
      size_bytes?: number;
    };
  }[];
  unread_count?: number;
};
export type ChatGroup = { id: string; name: string };
export type View = {
  paged?: boolean;
  partial?: boolean;
  space_setup?: boolean;
  active_space?: string | null;
  spaces?: SpaceSummary[];
  space_requests?: number;
  all_streams?: Stream[];
  all_invitations?: { actionable: number; notifications: number };
  all_reminders?: NonNullable<View["reminders"]>;
  /** Native operation order prevents an older sync response replacing a local edit. */
  revision?: number;
  contacts?: { id: string; name: string }[];
  reminders?: {
    stream: string;
    record: string;
    due_at: number;
    system_notification?: boolean;
  }[];
  name?: string | null;
  avatar?: string | null;
  invitations?: {
    enabled: boolean;
    pending: number;
    responses: number;
    actionable?: number;
    notifications?: number;
  };
  demo_names?: Record<string, string>;
  groups?: ChatGroup[];
  identity: string;
  credential: string;
  streams: Stream[];
  replicas: { id: string; mailbox: string }[];
  counts: {
    pending: number;
    stored: number;
    held: number;
    rejected: number;
    repair_pending: number;
  };
  inbox: Record<string, number>;
  history_warning: string;
  history_warning_code?: string;
  alpha_ready: false;
};

export function profileName(view: View): string {
  return view.name ?? view.demo_names?.[view.identity] ?? "";
}

export function invitationCount(view: View): number {
  return (
    (view.space_requests ?? 0) +
    (view.all_invitations?.actionable ??
      view.invitations?.actionable ??
      (view.invitations?.pending ?? 0) + (view.invitations?.responses ?? 0))
  );
}
export function notificationCount(view: View): number {
  return (
    view.all_invitations?.notifications ?? view.invitations?.notifications ?? 0
  );
}

function knownSenderName(
  view: View,
  identity: string,
  stream?: Stream,
): string | undefined {
  if (identity === view.identity) return profileName(view) || undefined;
  return (
    stream?.rows
      ?.filter(
        (row) =>
          row.body.issuer_identity === identity &&
          row.body.payload?.sender_name,
      )
      .at(-1)?.body.payload?.sender_name ??
    stream?.member_names?.[identity] ??
    view.contacts?.find((person) => person.id === identity)?.name ??
    view.demo_names?.[identity]
  );
}

export function senderName(
  view: View,
  identity: string,
  stream?: Stream,
): string {
  return (
    knownSenderName(view, identity, stream) ??
    (identity === view.identity
      ? t("profile.you")
      : identity.slice(0, 16) + "…")
  );
}

export function senderInitials(
  view: View,
  identity: string,
  stream?: Stream,
): string {
  const name = knownSenderName(view, identity, stream);
  return name
    ? name
        .split(/\s+/)
        .map((word) => Array.from(word)[0])
        .slice(0, 2)
        .join("")
        .toUpperCase()
    : identity === view.identity
      ? t("profile.avatar")
      : identity.slice(0, 2).toUpperCase();
}

export function isNewMessage(
  rows: Stream["rows"],
  index: number,
  sessionUnread: ReadonlySet<string>,
): boolean {
  const row = rows[index];
  return !!row && (!!row.unread || sessionUnread.has(row.id));
}

export function searchMessages(
  rows: Stream["rows"],
  query: string,
): Stream["rows"] {
  const term = query.trim().toLocaleLowerCase();
  if (!term) return rows;
  return rows.filter(
    (row) =>
      row.body.kind === "chat.message" &&
      row.body.payload?.text.toLocaleLowerCase().includes(term),
  );
}

export function beginsNewMessageSection(
  rows: Stream["rows"],
  index: number,
  sessionUnread: ReadonlySet<string>,
): boolean {
  return (
    isNewMessage(rows, index, sessionUnread) &&
    !rows
      .slice(0, index)
      .some((_, earlier) => isNewMessage(rows, earlier, sessionUnread))
  );
}

export function markVisibleMessagesRead(
  stream: Stream,
  recordIds: readonly string[],
): Stream {
  const visible = new Set(recordIds);
  const newlyRead = stream.rows.filter(
    (row) => row.unread && visible.has(row.id),
  ).length;
  if (!newlyRead) return stream;
  return {
    ...stream,
    unread_count: Math.max(0, (stream.unread_count ?? 0) - newlyRead),
    rows: stream.rows.map((row) =>
      row.unread && visible.has(row.id) ? { ...row, unread: false } : row,
    ),
  };
}

export function visibleMembers(view: View, stream: Stream, query: string) {
  const search = query.trim().toLocaleLowerCase();
  return stream.members
    .filter((member) =>
      [
        senderName(view, member.identity_id, stream),
        view.demo_names?.[member.identity_id] ?? "",
        member.identity_id,
      ].some((value) => value.toLocaleLowerCase().includes(search)),
    )
    .sort((a, b) => {
      if (a.identity_id === view.identity) return -1;
      if (b.identity_id === view.identity) return 1;
      return senderName(view, a.identity_id, stream).localeCompare(
        senderName(view, b.identity_id, stream),
      );
    });
}
