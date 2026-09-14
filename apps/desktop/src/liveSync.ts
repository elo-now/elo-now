import type { View } from "./model";

export type SyncResult = {
  view?: View;
  identity?: string;
  result?: {
    retry?: number;
    received_messages?: string[];
    more?: boolean;
    catching_up?: boolean;
    waiting_for_proof?: number;
  };
  delivery?: { retry?: number; more?: boolean; received?: number };
};
export type SyncProgress = {
  phase: "receiving" | "waiting";
  received: number;
} | null;

export type LiveContext = {
  conversation: boolean;
  busy: boolean;
  messages: boolean;
  invitations: boolean;
};

/** One foreground worker for both delivery loops. Native code owns durable
 * cursors/retries; this scheduler never retains decrypted messages or tokens. */
export function startLiveSync(
  identity: string,
  context: () => LiveContext,
  deliver: (
    op: "sync_live" | "invitation_sync",
    force?: boolean,
  ) => Promise<SyncResult>,
  onResult: (result: SyncResult) => void,
  onProgress: (progress: SyncProgress) => void = () => {},
) {
  let active = true;
  let running = false;
  let timer: ReturnType<typeof setTimeout> | undefined;
  let nextMessage = 0;
  let nextInvitation = 0;
  let messageFailures = 0;
  let invitationFailures = 0;
  let requests = 0;
  let invitationRequests = 0;
  let forceInvitation = false;
  let lastMessage = true;
  let progress: SyncProgress = null;
  const publish = (next: SyncProgress) => {
    progress = next;
    if (active) onProgress(next);
  };
  const visible = () =>
    document.visibilityState === "visible" && navigator.onLine !== false;
  const clear = () => {
    if (timer !== undefined) clearTimeout(timer);
    timer = undefined;
  };
  const schedule = (delay: number) => {
    clear();
    if (active && visible()) timer = setTimeout(() => void tick(), delay);
  };
  const tick = async () => {
    clear();
    if (!active || running || !visible()) return;
    const current = context();
    if (current.busy) {
      schedule(500);
      return;
    }
    const now = Date.now();
    const messageDue = current.messages ? nextMessage : Infinity;
    const invitationDue = current.invitations ? nextInvitation : Infinity;
    // Apply queued membership changes before uploading messages after resume.
    // A repeated push/status hint may make both loops due while discovery is
    // running. Always give message delivery a turn before another such pass.
    const bothDue = messageDue <= now && invitationDue <= now;
    const message = bothDue ? !lastMessage : messageDue < invitationDue;
    const due = Math.min(messageDue, invitationDue);
    if (!Number.isFinite(due)) return;
    if (due > now) {
      schedule(due - now);
      return;
    }
    running = true;
    lastMessage = message;
    const started = requests;
    const invitationStarted = invitationRequests;
    const force = !message && forceInvitation;
    if (!message) forceInvitation = false;
    let failed = false;
    let more = false;
    try {
      const op = message ? "sync_live" : "invitation_sync";
      const result = await (force ? deliver(op, true) : deliver(op));
      failed =
        ((message ? result.result?.retry : result.delivery?.retry) ?? 0) > 0;
      if (
        active &&
        (result.view
          ? result.view.identity === identity
          : result.identity === identity)
      ) {
        more = message
          ? result.result?.more === true
          : result.delivery?.more === true;
        if (!message && (result.delivery?.received ?? 0) > 0) nextMessage = 0;
        if (message) {
          const catching = result.result?.catching_up ?? more;
          if (catching || (failed && progress))
            publish({
              phase: failed || !visible() ? "waiting" : "receiving",
              received:
                (progress?.received ?? 0) +
                (result.result?.received_messages?.length ?? 0),
            });
          else publish(null);
        }
        onResult(result);
      }
    } catch {
      failed = true;
      if (progress) publish({ ...progress, phase: "waiting" });
    } finally {
      running = false;
      if (message) {
        messageFailures = failed ? Math.min(messageFailures + 1, 5) : 0;
        const base = context().conversation ? 4_000 : 20_000;
        nextMessage =
          Date.now() +
          (failed
            ? Math.min(10_000 * 2 ** (messageFailures - 1), 120_000)
            : more
              ? 250
              : base) +
          Math.random() * 1_000;
        if (requests !== started) nextMessage = 0;
      } else {
        invitationFailures = failed ? Math.min(invitationFailures + 1, 4) : 0;
        nextInvitation =
          Date.now() +
          (more && !failed
            ? 250
            : Math.min(30_000 * 2 ** invitationFailures, 300_000)) +
          Math.random() * (more && !failed ? 250 : 5_000);
        if (invitationRequests !== invitationStarted) nextInvitation = 0;
      }
      schedule(0);
    }
  };
  const resume = () => {
    clear();
    if (!visible()) {
      if (progress) publish({ ...progress, phase: "waiting" });
      return;
    }
    nextMessage = nextInvitation = 0;
    requests++;
    invitationRequests++;
    forceInvitation = true;
    if (!running) schedule(100);
  };
  document.addEventListener("visibilitychange", resume);
  window.addEventListener("online", resume);
  window.addEventListener("offline", resume);
  schedule(250);
  return {
    /** A locally committed send requests one pass; repeated calls coalesce. */
    request(membership = false) {
      requests++;
      nextMessage = 0;
      if (membership) {
        nextInvitation = 0;
        invitationRequests++;
        forceInvitation = true;
      }
      if (!running) schedule(100);
    },
    changed() {
      if (context().conversation)
        nextMessage = Math.min(nextMessage, Date.now() + 4_000);
      if (!running) schedule(100);
    },
    stop() {
      active = false;
      clear();
      document.removeEventListener("visibilitychange", resume);
      window.removeEventListener("online", resume);
      window.removeEventListener("offline", resume);
    },
  };
}

export function acceptView(current: View | null, next: View): View | null {
  if (!current || current.identity !== next.identity) return current;
  if ((next.revision ?? 0) < (current.revision ?? 0)) return current;
  if (!next.partial) return next;
  if (current.active_space !== next.active_space) return current;
  const merge = (old: View["streams"], updates: View["streams"]) =>
    old.map(
      (chat) =>
        updates.find(
          (update) =>
            update.space === chat.space &&
            update.stream === chat.stream &&
            update.space_context === chat.space_context,
        ) ?? chat,
    );
  return {
    ...current,
    revision: next.revision,
    counts: next.counts,
    streams: merge(current.streams, next.streams),
    all_streams: current.all_streams
      ? merge(current.all_streams, next.all_streams ?? next.streams)
      : undefined,
  };
}
