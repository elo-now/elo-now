import type { Stream, View } from "./model";

export type RealtimeScope = {
  space_context: string;
  space: string;
  stream: string;
};
export type RealtimeEvent = RealtimeScope & {
  issuer_identity: string;
  issuer_credential: string;
  created_at_ms: number;
  expires_at_ms: number;
  nonce: string;
  payload:
    | { kind: "presence" | "typing"; active: boolean }
    | {
        kind: "upload";
        attachment_id: string;
        name: string;
        size: number;
        status: "uploading" | "interrupted" | "cancelled" | "ready";
        record?: string;
      };
};
export type RealtimeNotice =
  | { type: "sync"; identity: string; space_context: string }
  | {
      type: "state";
      identity: string;
      connected_spaces: string[];
      events: RealtimeEvent[];
    };

/** Full native snapshots can repeat after unrelated operations. Keep every
 * lease/payload field in the comparison so expiry renewals are never lost. */
export function realtimeStateKey(
  connected: readonly string[],
  events: readonly RealtimeEvent[],
): string {
  return JSON.stringify([connected, events]);
}

export function realtimeScope(
  view: View,
  chat: Stream,
): RealtimeScope | undefined {
  const context = chat.space_context ?? view.active_space;
  return context
    ? { space_context: context, space: chat.space, stream: chat.stream }
    : undefined;
}

export function sameRealtimeScope(a: RealtimeScope, b: RealtimeScope): boolean {
  return (
    a.space_context === b.space_context &&
    a.space === b.space &&
    a.stream === b.stream
  );
}

/** Presence only belongs to verified shared conversations. Never extrapolate
 * an identity's presence into another Space or a different chat. */
export function realtimeScopes(view: View, selected?: Stream): RealtimeScope[] {
  const scopes: RealtimeScope[] = [];
  for (const chat of [
    ...(selected ? [selected] : []),
    ...view.streams,
    ...(view.all_streams ?? []),
  ]) {
    if (
      chat.forked ||
      !chat.members.some(
        (member) =>
          member.identity_id === view.identity &&
          member.capabilities.includes("READ"),
      )
    )
      continue;
    const scope = realtimeScope(view, chat);
    if (scope && !scopes.some((existing) => sameRealtimeScope(scope, existing)))
      scopes.push(scope);
    if (scopes.length === 256) break;
  }
  return scopes;
}

/** Recheck the current view as well as the native signature check. A membership
 * or blocking edit takes effect before the next native snapshot arrives. */
export function visibleRealtimeEvents(
  view: View,
  events: readonly RealtimeEvent[],
): RealtimeEvent[] {
  const chats = new Map<string, Stream>();
  const key = (scope: RealtimeScope) =>
    JSON.stringify([scope.space_context, scope.space, scope.stream]);
  for (const chat of [...(view.all_streams ?? []), ...view.streams]) {
    const scope = realtimeScope(view, chat);
    if (scope) chats.set(key(scope), chat);
  }
  const blocked = new Set(view.blocked_users?.map((person) => person.identity));
  return events.filter((event) => {
    if (blocked.has(event.issuer_identity)) return false;
    const chat = chats.get(key(event));
    return (
      !!chat &&
      !chat.forked &&
      chat.members.some(
        (member) =>
          member.identity_id === view.identity &&
          member.capabilities.includes("READ"),
      ) &&
      chat.members.some(
        (member) =>
          member.identity_id === event.issuer_identity &&
          member.capabilities.includes(
            event.payload.kind === "presence" ? "READ" : "POST",
          ),
      )
    );
  });
}

export function activeRealtimeEvents(
  events: readonly RealtimeEvent[],
  scope: RealtimeScope,
  now: number,
): RealtimeEvent[] {
  return events.filter(
    (event) => sameRealtimeScope(event, scope) && event.expires_at_ms > now,
  );
}

export function onlineInScope(
  events: readonly RealtimeEvent[],
  identity: string,
  scope: RealtimeScope,
  now: number,
): boolean {
  return activeRealtimeEvents(events, scope, now).some(
    (event) =>
      event.issuer_identity === identity &&
      event.payload.kind === "presence" &&
      event.payload.active,
  );
}

export function typingPeople(
  events: readonly RealtimeEvent[],
  scope: RealtimeScope,
  ownIdentity: string,
  now: number,
): string[] {
  return [
    ...new Set(
      activeRealtimeEvents(events, scope, now)
        .filter(
          (event) =>
            event.issuer_identity !== ownIdentity &&
            event.payload.kind === "typing" &&
            event.payload.active,
        )
        .map((event) => event.issuer_identity),
    ),
  ];
}

export type RemoteUpload = RealtimeEvent & {
  payload: Extract<RealtimeEvent["payload"], { kind: "upload" }>;
};

export function pendingRemoteUploads(
  events: readonly RealtimeEvent[],
  view: View,
  chat: Stream,
  now: number,
): RemoteUpload[] {
  const scope = realtimeScope(view, chat);
  if (!scope) return [];
  const knownRows = [chat, ...view.streams, ...(view.all_streams ?? [])]
    .filter((candidate) => {
      const candidateScope = realtimeScope(view, candidate);
      return candidateScope && sameRealtimeScope(candidateScope, scope);
    })
    .flatMap((candidate) => candidate.rows);
  const committedRecords = new Set(
    knownRows.flatMap((row) => [
      row.id,
      ...(row.body.deleted_record_id ? [row.body.deleted_record_id] : []),
    ]),
  );
  const committed = new Set(
    knownRows.flatMap((row) =>
      row.body.attachment ? [row.body.attachment.id] : [],
    ),
  );
  const latest = new Map<string, RemoteUpload>();
  for (const event of events) {
    if (
      !sameRealtimeScope(event, scope) ||
      event.payload.kind !== "upload" ||
      event.issuer_credential === view.credential ||
      committed.has(event.payload.attachment_id) ||
      (event.payload.record && committedRecords.has(event.payload.record))
    )
      continue;
    const key = `${event.issuer_identity}:${event.payload.attachment_id}`;
    const previous = latest.get(key);
    if (!previous || previous.created_at_ms <= event.created_at_ms)
      latest.set(key, event as RemoteUpload);
  }
  return [...latest.values()]
    .flatMap((event) => {
      if (event.payload.status === "cancelled") return [];
      if (event.expires_at_ms > now) return [event];
      // A missed final native snapshot must never leave a permanent spinner.
      if (
        (event.payload.status === "uploading" ||
          event.payload.status === "ready") &&
        event.expires_at_ms + 60_000 > now
      )
        return [
          {
            ...event,
            payload: { ...event.payload, status: "interrupted" as const },
          },
        ];
      return [];
    })
    .sort((a, b) => a.created_at_ms - b.created_at_ms);
}
