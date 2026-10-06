import { updateRequired, subscribeUpdateRequired } from "../releasePolicy";
import type { Stream, View } from "../model";
import {
  Control,
  callErrorCode,
  operate,
  requestContext,
  type Result,
} from "./control";
import {
  callKey,
  leader,
  muted,
  scopeKey,
  type ActiveCall,
  type MediaAdapter,
  type MediaState,
  type SignalPayload,
  type Snapshot,
} from "./types";
import { PeerMedia } from "./peer";
import {
  NativePeer,
  nativeMediaPermission,
  usesNativePeer,
} from "./nativePeer";
import { nativeCallState } from "./sessionActivity";
import {
  invitationKey,
  isRingingFor,
  readDismissed,
  saveDismissed,
  sessionKey,
} from "./attention";
import type { NativeActiveCall, NativeCallAction } from "./incomingNative";
import {
  activeSessions,
  sessionAvailable,
  type SessionStarted,
} from "./sessionPresence";
export class Calls {
  snapshot: Snapshot = {
    phase: "idle",
    media: { ...muted },
    tiles: [],
    available: {},
  };
  private view?: View;
  private connections = new Map<string, Control>();
  private endpoints = new Map<string, string>();
  private subscribed = new Map<string, string>();
  private subscriptionCursor = 0;
  private subscriptionRetry?: ReturnType<typeof setTimeout>;
  private notificationRetry?: ReturnType<typeof setTimeout>;
  private invitationRetries = new Map<string, ReturnType<typeof setTimeout>>();
  private incomingExpiry?: ReturnType<typeof setTimeout>;
  private subscriptionBackoff = new Map<string, number>();
  private listeners = new Set<() => void>();
  private sessionListeners = new Set<(event: SessionStarted) => void>();
  private seenSessions = new Set<string>();
  private adoptedNative = false;
  private seenInvitations = new Set<string>();
  private sessionDiscoverySince = Date.now();
  private endedSessions = new Set<string>();
  private initializingSubscriptions = new Set<string>();
  private revokedScopes = new Set<string>();
  private capture?: MediaStream;
  private nativeOwned = false;
  private nativeActivity?: {
    identity: string;
    sessionId: string;
    activation: string;
    context: Record<string, unknown>;
  };
  private activityQueue: Promise<void> = Promise.resolve();
  private audioActivationReady?: string;
  private sessionWork = new Set<Promise<void>>();
  private refreshBeforeStart = false;
  private mediaStopping: Promise<void> = Promise.resolve();
  private speakerMuted = false;
  private playbackRevision = 0;
  private screen?: MediaStream;
  private mediaChanging = false;
  private pendingMediaAdmission?: number;
  private adapter?: MediaAdapter;
  private epoch = 0;
  private mediaGeneration = 0;
  private groupConnecting?: number;
  private pendingSignals: SignalPayload[] = [];
  private presenceQueue: Promise<unknown> = Promise.resolve();
  private key?: { epoch: number; secret: string };
  private nonces = new Map<string, number>();
  private events: Promise<unknown> = Promise.resolve();
  private timer?: ReturnType<typeof setInterval>;
  private reconnectExpiry?: ReturnType<typeof setTimeout>;
  private reconnectRetry?: ReturnType<typeof setTimeout>;
  private ticking = false;
  private unsubscribePolicy?: () => void;
  private policyChanged = () => {
    if (!updateRequired()) {
      void this.subscribeChats();
      return;
    }
    const activeEndpoint =
      this.snapshot.active && this.snapshot.chat
        ? this.endpoints.get(this.snapshot.chat.space_context!)
        : undefined;
    for (const [endpoint, control] of this.connections) {
      if (endpoint === activeEndpoint) continue;
      control.close();
      this.connections.delete(endpoint);
    }
    this.subscribed.clear();
    this.change({ available: {} });
  };
  activate() {
    this.disposed = false;
    this.unsubscribePolicy ??= subscribeUpdateRequired(this.policyChanged);
    this.policyChanged();
    this.timer ??= setInterval(() => void this.tick(), 10000);
  }
  private generation = 0;
  private disposed = false;
  private busy = false;
  subscribe = (fn: () => void) => {
    this.listeners.add(fn);
    return () => {
      this.listeners.delete(fn);
    };
  };
  getSnapshot = () => this.snapshot;
  subscribeSessionStarted = (listener: (event: SessionStarted) => void) => {
    this.sessionListeners.add(listener);
    return () => {
      this.sessionListeners.delete(listener);
    };
  };
  private rememberSession(set: Set<string>, id: string) {
    set.add(id);
    if (set.size > 2048) set.delete(set.values().next().value!);
  }
  dismissError = () => this.change({ error: undefined });
  expand = () => this.change({ expanded: true });
  collapse = () => this.change({ expanded: false });
  cancelJoin = () => this.change({ joinRequest: undefined });
  setNativePresented = (presented: Snapshot["nativePresented"]) =>
    this.change({ nativePresented: presented ?? [] });
  async handleNativeAction(event: NativeCallAction) {
    const chat = this.chats().find(
      (candidate) =>
        candidate.space_context === event.hosting_space_id &&
        candidate.space === event.space &&
        candidate.stream === event.stream,
    );
    if (!chat || !this.view) return;
    const active = this.snapshot.active;
    if (event.action === "end") {
      if (
        active?.call_id === event.call_id &&
        callKey(active) === scopeKey(chat) &&
        event.activation &&
        this.nativeActivity?.activation === event.activation
      )
        await this.leave("native_end");
      return;
    }
    if (!event.invitation_id) return;
    const identity = this.view.identity;
    try {
      const result = await this.command(chat, { type: "subscribe" });
      if (this.view?.identity !== identity || this.disposed) return;
      const call = result.call;
      if (
        !call ||
        call.call_id !== event.call_id ||
        callKey(call) !== scopeKey(chat) ||
        !this.validate(call) ||
        call.invitations?.[identity]?.invitation_id !== event.invitation_id ||
        !isRingingFor(call, identity)
      )
        return;
      if (event.action === "decline") await this.decline(call);
      else if (event.action === "answer") {
        // Another call requires an explicit in-app End & answer as well; an
        // incoming notification alone never has authority to stop capture.
        this.updateIncoming([
          call,
          ...(this.snapshot.incoming ?? []).filter(
            (entry) => sessionKey(entry) !== sessionKey(call),
          ),
        ]);
        if (!active && this.snapshot.phase === "idle")
          await this.answer(chat, call, false, event.invitation_id);
      }
    } catch (error) {
      if (this.view?.identity === identity)
        this.change({ error: callErrorCode(error) });
    }
  }
  async adoptNative(value: NativeActiveCall) {
    if (
      !usesNativePeer() ||
      !this.view ||
      value.identity !== this.view.identity ||
      !["direct", "group"].includes(value.call.kind) ||
      value.call.participants[value.identity]?.credential_id !==
        this.view.credential ||
      !/^[a-f\d-]{36}$/i.test(value.session_id) ||
      !/^[a-f\d-]{36}$/i.test(value.activation)
    )
      return false;
    const chat = this.validate(value.call);
    if (!chat) return false;
    if (
      this.adapter instanceof NativePeer &&
      this.adapter.id === value.session_id
    )
      return true;
    if (this.snapshot.active || this.snapshot.phase !== "idle") return false;
    const generation = ++this.generation;
    await this.mediaStopping.catch(() => {});
    if (
      this.disposed ||
      this.view?.identity !== value.identity ||
      generation !== this.generation
    )
      return false;
    this.nativeOwned = true;
    this.adoptedNative = true;
    this.capture = new MediaStream();
    this.nativeActivity = {
      identity: value.identity,
      sessionId: value.call.call_id,
      activation: value.activation,
      context: requestContext(chat, value.identity),
    };
    this.audioActivationReady = value.activation;
    this.epoch = value.call.key_epoch;
    this.change({
      active: value.call,
      chat,
      media: value.media,
      phase: "connecting",
      error: undefined,
      joinRequest: undefined,
      incoming: (this.snapshot.incoming ?? []).filter(
        (call) => sessionKey(call) !== sessionKey(value.call),
      ),
    });
    const mediaGeneration = this.mediaGeneration;
    this.adapter = new NativePeer(
      this.view.credential,
      value.identity,
      (tiles) => {
        if (generation === this.generation) this.change({ tiles });
      },
      (error = "unavailable") => {
        if (generation === this.generation) this.fail(error);
      },
      () => {
        if (generation === this.generation) this.mediaConnected();
      },
      (call) => {
        if (
          generation === this.generation &&
          mediaGeneration === this.mediaGeneration
        )
          void this.presence(call);
      },
      undefined,
      {
        ...requestContext(chat, value.identity),
        call_id: value.call.call_id,
        activation: value.activation,
      },
      { sessionId: value.session_id },
    );
    return true;
  }
  reveal(chat: Stream) {
    if (!this.view) return;
    const call = this.snapshot.available[scopeKey(chat)];
    if (!call) return;
    this.change({
      dismissed: saveDismissed(
        this.view.identity,
        (this.snapshot.dismissed ?? []).filter(
          (key) => key !== sessionKey(call),
        ),
      ),
    });
  }
  dismiss(call: ActiveCall) {
    if (!this.view) return;
    this.change({
      dismissed: saveDismissed(this.view.identity, [
        ...(this.snapshot.dismissed ?? []),
        sessionKey(call),
      ]),
      incoming: (this.snapshot.incoming ?? []).filter(
        (value) => sessionKey(value) !== sessionKey(call),
      ),
    });
  }
  requestStart(chat: Stream, call = this.snapshot.available[scopeKey(chat)]) {
    this.reveal(chat);
    if (
      call &&
      this.snapshot.active?.call_id === call.call_id &&
      callKey(this.snapshot.active) === callKey(call)
    ) {
      this.expand();
      return;
    }
    if (this.snapshot.active || this.snapshot.phase !== "idle") {
      this.change({ joinRequest: { chat, call } });
      return;
    }
    void this.answer(chat, call);
  }
  async answer(
    chat: Stream,
    call?: ActiveCall,
    replace = false,
    invitationId?: string,
  ) {
    if (!this.view || this.snapshot.answering) return;
    const identity = this.view.identity;
    this.change({ answering: true });
    try {
      if (call) {
        // A tap is intent only. Refresh membership/session before acquiring media
        // or ending the current session, even for a verified native action.
        const result = await this.command(chat, { type: "subscribe" });
        if (this.view?.identity !== identity || this.disposed) return;
        if (
          !result.call ||
          result.call.call_id !== call.call_id ||
          callKey(result.call) !== callKey(call) ||
          !this.validate(result.call) ||
          !sessionAvailable(result.call) ||
          this.endedSessions.has(call.call_id) ||
          (invitationId &&
            (result.call.invitations?.[identity]?.invitation_id !==
              invitationId ||
              !isRingingFor(result.call, identity)))
        )
          throw new Error("ended");
        call = result.call;
      }
      if (this.snapshot.active || this.snapshot.phase !== "idle") {
        if (!replace) {
          this.change({ joinRequest: { chat, call } });
          return;
        }
        await this.leave();
        if (this.view?.identity !== identity || this.disposed) return;
      }
      this.change({
        joinRequest: undefined,
        incoming: (this.snapshot.incoming ?? []).filter(
          (value) => !call || sessionKey(value) !== sessionKey(call),
        ),
      });
      await this.start(chat, call, invitationId);
    } catch (error) {
      if (this.view?.identity === identity)
        this.change({ error: callErrorCode(error), joinRequest: undefined });
    } finally {
      if (this.view?.identity === identity) this.change({ answering: false });
    }
  }
  async decline(call: ActiveCall) {
    const chat = this.validate(call);
    const identity = this.view?.identity;
    this.dismiss(call);
    const invitationId =
      identity && call.invitations?.[identity]?.invitation_id;
    if (!chat || !identity || !invitationId) return;
    try {
      const result = await this.command(chat, {
        type: "decline",
        call_id: call.call_id,
        invitation_id: invitationId,
      });
      if (this.view?.identity === identity && result.call)
        await this.presence(result.call);
    } catch (error) {
      if (this.view?.identity === identity && callErrorCode(error) !== "ended")
        this.change({ error: callErrorCode(error) });
    }
  }
  async invite(identity: string) {
    const { active, chat } = this.snapshot;
    if (!active || !chat || active.kind !== "group") return;
    const generation = this.generation;
    try {
      const result = await this.command(chat, {
        type: "invite",
        call_id: active.call_id,
        to: identity,
      });
      if (generation === this.generation && result.call) {
        await this.presence(result.call);
        const invitation = result.call.invitations?.[identity];
        if (invitation && this.view?.identity === invitation.invited_by)
          void this.notifyInvitation(
            chat,
            result.call,
            identity,
            invitation.invitation_id,
            generation,
            invitation.expires_at * 1000,
          );
      }
    } catch (error) {
      if (generation === this.generation)
        this.change({ error: callErrorCode(error) });
    }
  }
  private async notifyInvitation(
    chat: Stream,
    call: ActiveCall,
    to: string,
    invitationId: string,
    generation: number,
    deadline: number,
  ) {
    const identity = this.view?.identity;
    const current = () =>
      identity &&
      this.view?.identity === identity &&
      !this.disposed &&
      generation === this.generation &&
      this.snapshot.active?.call_id === call.call_id &&
      callKey(this.snapshot.active) === callKey(call) &&
      this.snapshot.active.invitations?.[to]?.invitation_id === invitationId &&
      Date.now() < deadline;
    if (!current()) return;
    try {
      const result = await operate({
        ...requestContext(chat, identity!),
        op: "call_notify_ready",
        call_id: call.call_id,
        invitation_id: invitationId,
        to,
      });
      if (result.retry !== true) return;
    } catch (error) {
      if (["ended", "unauthorized", "invalid"].includes(callErrorCode(error)))
        return;
    }
    if (current()) {
      clearTimeout(this.invitationRetries.get(to));
      this.invitationRetries.set(
        to,
        setTimeout(
          () => {
            this.invitationRetries.delete(to);
            void this.notifyInvitation(
              chat,
              call,
              to,
              invitationId,
              generation,
              deadline,
            );
          },
          Math.min(8000, deadline - Date.now()),
        ),
      );
    }
  }
  private updateIncoming(values: ActiveCall[]) {
    clearTimeout(this.incomingExpiry);
    const identity = this.view?.identity;
    const incoming = identity
      ? values.filter((call) => isRingingFor(call, identity)).slice(0, 8)
      : [];
    this.change({ incoming });
    if (identity && incoming.length) {
      const expires = Math.min(
        ...incoming.map(
          (call) => call.invitations![identity].expires_at * 1000,
        ),
      );
      this.incomingExpiry = setTimeout(
        () => this.updateIncoming(this.snapshot.incoming ?? []),
        Math.max(1, expires - Date.now()),
      );
    }
  }
  private change(update: Partial<Snapshot>) {
    this.snapshot = { ...this.snapshot, ...update };
    this.listeners.forEach((fn) => fn());
  }
  update(view: View | null | undefined) {
    if (this.view?.identity !== view?.identity) {
      if (!view && this.adoptedNative) this.detachAdopted();
      else void this.leave("view_changed");
      this.connections.forEach((c) => c.close());
      this.connections.clear();
      this.subscribed.clear();
      this.subscriptionBackoff.clear();
      this.seenSessions.clear();
      this.seenInvitations.clear();
      clearTimeout(this.incomingExpiry);
      this.sessionDiscoverySince = Date.now();
      this.endedSessions.clear();
      this.initializingSubscriptions.clear();
      this.revokedScopes.clear();
      this.subscriptionCursor = 0;
      clearTimeout(this.subscriptionRetry);
      this.subscriptionRetry = undefined;
      this.endpoints.clear();
      this.change({
        available: {},
        error: undefined,
        incoming: [],
        joinRequest: undefined,
        expanded: false,
        nativePresented: [],
        dismissed: view ? readDismissed(view.identity) : [],
      });
    }
    this.view = view ?? undefined;
    if (!view) return;
    const available = Object.fromEntries(
      Object.entries(this.snapshot.available).filter(([, call]) =>
        this.validate(call),
      ),
    );
    if (
      Object.keys(available).length !==
      Object.keys(this.snapshot.available).length
    )
      this.change({ available });
    this.updateIncoming(
      (this.snapshot.incoming ?? []).filter((call) => this.validate(call)),
    );
    if (this.snapshot.active && !this.chatFor(this.snapshot.active))
      void this.leave("chat_unavailable");
    const active = this.snapshot.active;
    if (active) {
      const chat = this.chatFor(active);
      if (
        !chat ||
        chat.head !== active.config_id ||
        !chat.can_post ||
        (chat.chat_kind === "direct" &&
          chat.members.some((m) =>
            view.blocked_users?.some((b) => b.identity === m.identity_id),
          ))
      )
        void this.leave("access_changed");
    }
    void this.subscribeChats();
  }
  private chats() {
    return (this.view?.all_streams ?? this.view?.streams ?? [])
      .map((chat) => ({
        ...chat,
        space_context:
          chat.space_context ?? this.view?.active_space ?? undefined,
      }))
      .filter(
        (chat) =>
          chat.space_context &&
          chat.can_post &&
          !chat.forked &&
          this.view?.spaces?.some(
            (s) =>
              s.id === chat.space_context &&
              s.managed &&
              s.calls_available !== false &&
              s.status === "joined",
          ),
      );
  }
  private chatFor(call: ActiveCall) {
    return this.chats().find((chat) => scopeKey(chat) === callKey(call));
  }
  private async connection(chat: Stream) {
    if (!this.view || this.disposed) throw new Error("ended");
    const identity = this.view.identity;
    let endpoint = this.endpoints.get(chat.space_context!);
    if (!endpoint) {
      const result = await operate({
        ...requestContext(chat, this.view.identity),
        op: "call_endpoint",
      });
      endpoint = result.url as string;
      if (this.disposed || this.view?.identity !== identity)
        throw new Error("ended");
      const parsed = new URL(endpoint);
      if (
        parsed.protocol !== "https:" &&
        !(
          parsed.protocol === "http:" &&
          ["127.0.0.1", "localhost"].includes(parsed.hostname)
        )
      )
        throw new Error("unavailable");
      this.endpoints.set(chat.space_context!, endpoint);
    }
    let control = this.connections.get(endpoint);
    if (!control) {
      control = new Control(
        endpoint,
        this.view.identity,
        (event) => this.receiveEvent(event),
        () => {
          for (const chat of this.chats())
            if (this.endpoints.get(chat.space_context!) === endpoint)
              this.subscribed.delete(scopeKey(chat));
          // A connection to an unrelated deployment must not interrupt this call.
          if (
            !this.nativeOwned &&
            this.snapshot.chat &&
            this.endpoints.get(this.snapshot.chat.space_context!) === endpoint
          )
            this.beginReconnect();
        },
      );
      this.connections.set(endpoint, control);
    }
    return control;
  }
  private command(chat: Stream, operation: Record<string, unknown>) {
    return this.connection(chat).then((control) =>
      control.command(chat, operation),
    );
  }
  private async subscribeChats() {
    if (
      updateRequired() ||
      this.busy ||
      this.disposed ||
      this.subscriptionRetry
    )
      return;
    this.busy = true;
    const identity = this.view?.identity;
    try {
      const chats = this.chats();
      const start = this.subscriptionCursor % Math.max(1, chats.length);
      let attempts = 0;
      for (let offset = 0; offset < chats.length && attempts < 16; offset++) {
        if (this.disposed || this.view?.identity !== identity) return;
        const index = (start + offset) % chats.length;
        const chat = chats[index];
        this.subscriptionCursor = (index + 1) % chats.length;
        const key = scopeKey(chat);
        if (
          this.subscribed.get(key) === chat.head ||
          (this.subscriptionBackoff.get(key) ?? 0) > Date.now()
        )
          continue;
        attempts++;
        this.initializingSubscriptions.add(key);
        try {
          const previous = this.snapshot.available[key];
          const result = await this.command(chat, { type: "subscribe" });
          if (this.disposed || this.view?.identity !== identity) return;
          if (
            !this.chats().some(
              (current) =>
                scopeKey(current) === key && current.head === chat.head,
            )
          )
            continue;
          this.subscribed.set(key, chat.head);
          this.revokedScopes.delete(key);
          this.subscriptionBackoff.delete(key);
          if (result.call)
            await this.presence(
              result.call,
              this.newlyDiscoveredSession(result.call),
            );
          else if (previous && this.snapshot.available[key] === previous) {
            const available = { ...this.snapshot.available };
            delete available[key];
            this.change({ available });
          }
        } catch (error) {
          if (this.disposed || this.view?.identity !== identity) return;
          this.subscriptionBackoff.set(key, Date.now() + 10000);
          const reason = callErrorCode(error);
          // A rejected chat must not prevent other chats from receiving calls.
          // Transport failures still stop this pass to avoid repeated timeouts.
          if (reason !== "unauthorized" && reason !== "invalid") return;
        } finally {
          this.initializingSubscriptions.delete(key);
        }
      }
      // One signed command at a time; reserve the socket for interactive calls
      // between batches and stay below the server's command-rate budget.
      if (
        attempts === 16 &&
        this.chats().some(
          (chat) =>
            this.subscribed.get(scopeKey(chat)) !== chat.head &&
            (this.subscriptionBackoff.get(scopeKey(chat)) ?? 0) <= Date.now(),
        )
      ) {
        this.subscriptionRetry = setTimeout(() => {
          this.subscriptionRetry = undefined;
          void this.subscribeChats();
        }, 3000);
      }
    } finally {
      this.busy = false;
      if (!this.disposed && this.view?.identity !== identity)
        void this.subscribeChats();
    }
  }
  private validate(call: ActiveCall) {
    const chat = this.chatFor(call);
    if (
      !chat ||
      call.config_id !== chat.head ||
      !Number.isSafeInteger(call.key_epoch) ||
      call.key_epoch < 1
    ) {
      return;
    }
    if (
      Object.values(call.participants).some(
        (p) =>
          !chat.members.some(
            (m) =>
              m.identity_id === p.identity_id &&
              m.credential_ids.includes(p.credential_id) &&
              m.capabilities.includes("POST"),
          ),
      )
    ) {
      return;
    }
    return chat;
  }
  private newlyDiscoveredSession(call: ActiveCall) {
    const chat = this.chatFor(call);
    const now = Date.now();
    const ready = (call.ready_at ?? 0) * 1000;
    return (
      chat?.chat_kind === "direct" &&
      (chat.created_at ?? 0) >= this.sessionDiscoverySince &&
      (chat.created_at ?? 0) <= now &&
      ready > 0 &&
      ready <= now &&
      now < ready + 60_000
    );
  }
  private async event(event: Result) {
    if (event.type === "presence" && event.call)
      await this.presence(
        event.call,
        (this.subscribed.has(callKey(event.call)) &&
          !this.initializingSubscriptions.has(callKey(event.call))) ||
          this.newlyDiscoveredSession(event.call),
      );
    else if (event.type === "ended" || event.type === "access_revoked") {
      if (event.type === "ended" && typeof event.call_id === "string")
        this.rememberSession(this.endedSessions, event.call_id);
      const eventScope = event.scope as ActiveCall["scope"] | undefined;
      const matchesScope = (scope: ActiveCall["scope"]) =>
        scope.hosting_space_id === eventScope?.hosting_space_id &&
        scope.conversation.space_id === eventScope?.conversation?.space_id &&
        scope.conversation.stream_id === eventScope?.conversation?.stream_id;
      const matches = (call: ActiveCall) =>
        event.type === "access_revoked"
          ? matchesScope(call.scope)
          : call.call_id === event.call_id &&
            (!eventScope || matchesScope(call.scope));
      if (event.type === "access_revoked") {
        for (const chat of this.chats()) {
          const scope = {
            hosting_space_id: chat.space_context!,
            conversation: { space_id: chat.space, stream_id: chat.stream },
          };
          if (matchesScope(scope)) {
            this.subscribed.delete(scopeKey(chat));
            this.revokedScopes.add(scopeKey(chat));
          }
        }
      }
      const available = { ...this.snapshot.available };
      for (const [key, call] of Object.entries(available))
        if (matches(call)) delete available[key];
      this.change({ available });
      this.updateIncoming(
        (this.snapshot.incoming ?? []).filter((call) => !matches(call)),
      );
      if (this.snapshot.active && matches(this.snapshot.active))
        await this.leave(event.type);
    } else if (event.type === "signal") await this.signal(event);
  }
  private receiveEvent(event: Result) {
    const generation = this.generation;
    const handle = async () => {
      if (this.disposed || generation !== this.generation) return;
      try {
        await this.event(event);
      } catch (error) {
        // Teardown can reject outstanding SDP/ICE work after a normal hangup.
        if (generation === this.generation)
          this.fail(callErrorCode(error) === "ended" ? "ended" : "unavailable");
      }
    };
    if (event.type === "ended" || event.type === "access_revoked") {
      // Hangup must not wait for an SDP handshake or a signed media command.
      void handle();
      if (generation !== this.generation) this.events = Promise.resolve();
    } else this.events = this.events.catch(() => {}).then(handle);
  }
  private presence(call: ActiveCall, announce = false): Promise<void> {
    const generation = this.generation;
    const task = this.presenceQueue
      .catch(() => {})
      .then(() => {
        if (generation === this.generation)
          return this.applyPresence(call, announce);
      });
    this.presenceQueue = task;
    return task;
  }
  private async applyPresence(call: ActiveCall, announce = false) {
    const chat = this.validate(call);
    if (
      !chat ||
      !this.view ||
      this.endedSessions.has(call.call_id) ||
      this.revokedScopes.has(callKey(call))
    )
      return;
    const known = this.snapshot.available[callKey(call)];
    if (known?.call_id === call.call_id && known.key_epoch > call.key_epoch)
      return;
    if (Object.keys(call.participants).length === 0) {
      const key = callKey(call);
      const known = this.snapshot.available[key];
      if (known?.call_id === call.call_id) {
        const available = { ...this.snapshot.available };
        delete available[key];
        this.change({ available });
      }
      if (this.snapshot.active?.call_id === call.call_id)
        await this.leave("call_empty");
      return;
    }
    if (
      known?.call_id === call.call_id &&
      known.ready === true &&
      call.ready !== true
    )
      return;
    const available = { ...this.snapshot.available };
    if (sessionAvailable(call)) available[callKey(call)] = call;
    else if (known?.call_id === call.call_id) delete available[callKey(call)];
    this.change({ available });
    const pending = (this.snapshot.incoming ?? []).filter(
      (entry) => sessionKey(entry) !== sessionKey(call),
    );
    const ring = isRingingFor(call, this.view.identity);
    const alreadyIncoming = this.snapshot.incoming?.some(
      (entry) =>
        invitationKey(entry, this.view!.identity) ===
        invitationKey(call, this.view!.identity),
    );
    const invitation = invitationKey(call, this.view.identity);
    const firstInvitation = !this.seenInvitations.has(invitation);
    if (ring) this.rememberSession(this.seenInvitations, invitation);
    if (
      ring &&
      (alreadyIncoming || (announce && !chat.muted && firstInvitation))
    ) {
      pending.push(call);
    }
    this.updateIncoming(pending);
    if (sessionAvailable(call) && !this.seenSessions.has(call.call_id)) {
      this.rememberSession(this.seenSessions, call.call_id);
      if (announce && call.started_by !== this.view.identity && !chat.muted) {
        const session = activeSessions(this.view, { [callKey(call)]: call })[0];
        if (session)
          this.sessionListeners.forEach((listener) => {
            try {
              listener(session);
            } catch {}
          });
      }
    }
    if (!this.snapshot.active) return;
    if (call.call_id !== this.snapshot.active.call_id) return;
    if (
      call.participants[this.view.identity]?.credential_id !==
      this.view.credential
    )
      return this.leave("participant_removed");
    this.change({ active: call, chat });
    // Start presence can arrive before native activation and the signed media
    // grant. Do not request a provider token with the initial muted permissions.
    if (this.pendingMediaAdmission === this.generation) return;
    if (this.nativeOwned && this.adapter instanceof NativePeer) {
      // Native signaling owns membership changes and preserves capture in the background.
      this.epoch = call.key_epoch;
      return;
    }
    if (this.epoch === call.key_epoch) return;
    const stopping = this.stopMedia();
    const generation = this.mediaGeneration;
    this.epoch = call.key_epoch;
    this.change({ phase: "connecting", tiles: [] });
    if (this.key?.epoch !== call.key_epoch) this.key = undefined;
    // Presence and encrypted key delivery must not wait for an obsolete room's
    // network handshake. A newer epoch cancels this preparation immediately.
    void this.prepareMedia(call, chat, generation, stopping).catch((error) => {
      if (generation === this.mediaGeneration)
        this.fail(error instanceof Error ? error.message : "unavailable");
    });
  }
  private async prepareMedia(
    call: ActiveCall,
    chat: Stream,
    generation: number,
    stopping: Promise<void>,
  ) {
    await stopping;
    if (generation !== this.mediaGeneration || !this.view) return;
    const tiles = (tiles: import("./types").MediaTile[]) => {
      if (generation === this.mediaGeneration) this.change({ tiles });
    };
    const connected = () => {
      if (generation === this.mediaGeneration) this.mediaConnected();
    };
    if (this.nativeOwned) {
      const peer = new NativePeer(
        this.view.credential,
        this.view.identity,
        tiles,
        (reason = "unavailable") => {
          if (generation === this.mediaGeneration) this.fail(reason);
        },
        connected,
        (current) => {
          if (generation === this.mediaGeneration) void this.presence(current);
        },
        undefined,
        {
          ...requestContext(chat, this.view.identity),
          call_id: call.call_id,
          activation: this.nativeActivity?.activation,
          display_name: chat.name,
        },
      );
      this.adapter = peer;
      await peer.setSpeakerMuted(this.speakerMuted);
      await peer.update(this.snapshot.media);
      return;
    }
    if (call.kind === "direct") {
      const remote = Object.values(call.participants).find(
        (p) => p.credential_id !== this.view!.credential,
      );
      if (!remote) {
        // Admission prepares this device to call; only a remote media transport
        // establishes a direct conversation.
        return;
      }
      const access = (
        await this.command(chat, {
          type: "connect_media",
          call_id: call.call_id,
        })
      ).media;
      if (generation !== this.mediaGeneration) return;
      if (!access || access.epoch !== call.key_epoch)
        throw new Error("unavailable");
      const peer = new PeerMedia(
        access,
        remote.credential_id,
        (payload) => this.sendSignal(remote.credential_id, payload, generation),
        tiles,
        () => {
          if (generation === this.mediaGeneration) this.beginReconnect();
        },
        connected,
      );
      this.adapter = peer;
      await peer.update(this.snapshot.media, this.capture!, this.screen);
      if (generation !== this.mediaGeneration) return;
      for (const payload of this.pendingSignals.splice(0)) {
        await peer.signal(payload);
        if (generation !== this.mediaGeneration) return;
      }
      if (leader(call) === this.view.credential) await peer.offer();
      else
        await this.sendSignal(
          remote.credential_id,
          { type: "request_offer" },
          generation,
        );
    } else if (leader(call) === this.view.credential) {
      if (this.key?.epoch !== call.key_epoch)
        this.key = {
          epoch: call.key_epoch,
          secret: Array.from(crypto.getRandomValues(new Uint8Array(32)), (n) =>
            n.toString(16).padStart(2, "0"),
          ).join(""),
        };
      for (const participant of Object.values(call.participants))
        if (participant.credential_id !== this.view.credential)
          await this.sendSignal(
            participant.credential_id,
            {
              type: "media_key",
              epoch: call.key_epoch,
              key: this.key.secret,
            },
            generation,
          );
      if (generation !== this.mediaGeneration) return;
      await this.connectGroup();
    } else {
      await this.sendSignal(
        leader(call),
        {
          type: "request_key",
          epoch: call.key_epoch,
        },
        generation,
      );
    }
  }
  private async sendSignal(
    to: string,
    payload: SignalPayload,
    generation = this.mediaGeneration,
  ) {
    if (generation !== this.mediaGeneration) return;
    const { active, chat } = this.snapshot;
    if (!active || !chat || !this.view) throw new Error("ended");
    const sealed = await operate({
      ...requestContext(chat, this.view.identity),
      op: "call_encrypt_signal",
      call_id: active.call_id,
      epoch: active.key_epoch,
      to,
      payload,
      recipient_delegation: Object.values(active.participants).find(
        (participant) => participant.credential_id === to,
      )?.delegation,
    });
    if (generation !== this.mediaGeneration) return;
    await this.command(chat, {
      type: "signal",
      call_id: active.call_id,
      epoch: active.key_epoch,
      to,
      ciphertext: sealed.ciphertext,
    });
  }
  private async signal(event: Result) {
    if (this.nativeOwned) return;
    const generation = this.mediaGeneration;
    const { active, chat } = this.snapshot;
    if (
      !active ||
      !chat ||
      !this.view ||
      event.call_id !== active.call_id ||
      event.epoch !== active.key_epoch ||
      !Object.values(active.participants).some(
        (p) => p.credential_id === event.from,
      )
    )
      return;
    const { signal } = await operate({
      ...requestContext(chat, this.view.identity),
      op: "call_open_signal",
      call_id: active.call_id,
      epoch: active.key_epoch,
      ciphertext: event.ciphertext,
      sender_delegation: Object.values(active.participants).find(
        (participant) => participant.credential_id === event.from,
      )?.delegation,
    });
    if (generation !== this.mediaGeneration || !this.view) return;
    if (
      signal.from !== event.from ||
      signal.to !== this.view.credential ||
      signal.config_id !== active.config_id ||
      signal.epoch !== active.key_epoch ||
      this.nonces.has(signal.nonce)
    )
      return;
    this.nonces.set(signal.nonce, Date.now());
    if (this.nonces.size > 2048) throw new Error("unavailable");
    const payload = signal.payload as SignalPayload;
    if (
      payload.type === "media_key" &&
      signal.from === leader(active) &&
      payload.epoch === active.key_epoch &&
      /^[0-9a-f]{64}$/.test(payload.key)
    ) {
      if (this.key && this.key.secret !== payload.key)
        throw new Error("unauthorized");
      this.key = { epoch: payload.epoch, secret: payload.key };
      if (!this.adapter)
        void this.connectGroup().catch((error) => {
          if (generation === this.mediaGeneration)
            this.fail(error instanceof Error ? error.message : "unavailable");
        });
    } else if (
      payload.type === "request_key" &&
      leader(active) === this.view.credential &&
      this.key?.epoch === payload.epoch
    ) {
      void this.sendSignal(
        signal.from,
        {
          type: "media_key",
          epoch: payload.epoch,
          key: this.key.secret,
        },
        generation,
      ).catch(() => {
        if (generation === this.mediaGeneration) this.fail("unavailable");
      });
    } else if (
      active.kind === "direct" &&
      ["offer", "answer", "ice", "request_offer"].includes(payload.type)
    ) {
      if (
        ((payload.type === "request_offer" || payload.type === "answer") &&
          leader(active) !== this.view.credential) ||
        (payload.type === "offer" && signal.from !== leader(active))
      )
        return;
      if (this.adapter) await this.adapter.signal?.(payload);
      else if (this.pendingSignals.length < 128)
        this.pendingSignals.push(payload);
      else throw new Error("unavailable");
    }
  }
  private async connectGroup() {
    const generation = this.mediaGeneration;
    if (this.groupConnecting === generation) return;
    this.groupConnecting = generation;
    try {
      await this.openGroup(generation);
    } finally {
      if (this.groupConnecting === generation) this.groupConnecting = undefined;
    }
  }
  private async openGroup(generation: number) {
    const { active, chat } = this.snapshot;
    if (!active || !chat || !this.key || this.adapter) return;
    const secret = this.key.secret;
    const epoch = active.key_epoch;
    const access = (
      await this.command(chat, {
        type: "connect_media",
        call_id: active.call_id,
      })
    ).media;
    if (
      generation !== this.mediaGeneration ||
      this.snapshot.active?.key_epoch !== epoch
    )
      return;
    if (!access || access.epoch !== epoch) throw new Error("unavailable");
    const { GroupMedia } = await import("./livekit");
    if (
      generation !== this.mediaGeneration ||
      this.snapshot.active?.key_epoch !== epoch ||
      this.adapter
    )
      return;
    const media = new GroupMedia(
      (tiles) => {
        if (this.adapter === media) this.change({ tiles });
      },
      (reason) => {
        if (reason === "encryption_error") {
          if (this.adapter === media) this.fail("encryption_unavailable");
          return;
        }
        setTimeout(() => {
          if (
            this.adapter === media &&
            this.snapshot.active?.key_epoch === epoch
          )
            this.beginReconnect();
        }, 4000);
      },
    );
    this.adapter = media;
    try {
      await media.connect(access, secret);
      if (
        generation !== this.mediaGeneration ||
        this.snapshot.active?.key_epoch !== epoch
      ) {
        await media.stop();
        return;
      }
      await media.update(this.snapshot.media, this.capture!, this.screen);
      if (generation !== this.mediaGeneration) return;
      this.mediaConnected();
    } catch (error) {
      await media.stop();
      if (this.adapter === media) this.adapter = undefined;
      if (
        generation === this.mediaGeneration &&
        this.snapshot.active?.key_epoch === epoch
      )
        throw error;
    }
  }
  async start(chat: Stream, existing?: ActiveCall, invitationId?: string) {
    if (this.snapshot.active || this.snapshot.phase !== "idle" || !this.view)
      return;
    if (updateRequired()) {
      this.change({ error: "updateRequired" });
      return;
    }
    const joined = existing?.participants[this.view.identity];
    if (
      !this.refreshBeforeStart &&
      joined &&
      joined.credential_id !== this.view.credential
    ) {
      this.change({ error: "already_joined" });
      return;
    }
    this.change({
      error: undefined,
      phase: "connecting",
      chat,
    });
    const generation = ++this.generation;
    this.pendingMediaAdmission = generation;
    const identity = this.view.identity;
    let capture: MediaStream | undefined;
    let finishAdmission: (() => void) | undefined;
    try {
      // A cancelled Start may still need to leave the session it just created.
      // Finish that cleanup before admitting this device again to the same call.
      while (this.sessionWork.size) await Promise.all([...this.sessionWork]);
      if (generation !== this.generation) return;
      if (this.refreshBeforeStart) {
        const result = await this.command(chat, { type: "subscribe" });
        if (generation !== this.generation) return;
        existing = result.call;
        if (existing && !this.validate(existing))
          throw new Error("unauthorized");
        const available = { ...this.snapshot.available };
        if (
          existing &&
          sessionAvailable(existing) &&
          !this.endedSessions.has(existing.call_id)
        )
          available[scopeKey(chat)] = existing;
        else delete available[scopeKey(chat)];
        this.change({ available });
        this.refreshBeforeStart = false;
      }
      const joined = existing?.participants[identity];
      if (joined && joined.credential_id !== this.view?.credential)
        throw new Error("already_joined");
      const direct = existing
        ? existing.kind === "direct"
        : chat.chat_kind === "direct" && chat.members.length === 2;
      this.nativeOwned = usesNativePeer();
      if (!direct && !this.nativeOwned) {
        const sdk = await import("livekit-client");
        if (!sdk.isE2EESupported()) throw new Error("encryption_unavailable");
      }
      if (this.nativeOwned) {
        await nativeMediaPermission(identity, false);
        capture = new MediaStream();
      } else
        capture = await navigator.mediaDevices.getUserMedia({
          audio: { echoCancellation: true, noiseSuppression: true },
          video: false,
        });
      if (generation !== this.generation) {
        capture.getTracks().forEach((t) => t.stop());
        return;
      }
      this.capture = capture;
      finishAdmission = this.beginSessionWork();
      const result = await this.command(
        chat,
        existing
          ? {
              type: "join",
              call_id: existing.call_id,
              ...(invitationId ? { invitation_id: invitationId } : {}),
            }
          : {
              type: "start",
              kind: direct ? "direct" : "group",
              initial_media: "audio",
            },
      );
      if (generation !== this.generation) {
        if (result.call)
          await this.command(chat, {
            type: "leave",
            call_id: result.call.call_id,
          }).catch(() => {});
        return;
      }
      if (
        !result.call ||
        !this.validate(result.call) ||
        this.endedSessions.has(result.call.call_id)
      )
        throw new Error("unauthorized");
      this.change({
        active: result.call,
        chat,
        media: {
          audio_muted: false,
          video_published: false,
          screen_published: false,
        },
      });
      this.nativeActivity = {
        identity,
        sessionId: result.call.call_id,
        activation: crypto.randomUUID(),
        context: requestContext(chat, identity),
      };
      await this.setNativeActivity(true, false);
      if (generation !== this.generation) return;
      const published = await this.command(chat, {
        type: "media",
        call_id: result.call.call_id,
        state: this.snapshot.media,
      });
      if (generation !== this.generation) return;
      this.pendingMediaAdmission = undefined;
      const admitted = published.call ?? result.call;
      const current = this.getSnapshot().active;
      await this.presence(
        current?.call_id === admitted.call_id &&
          current.key_epoch > admitted.key_epoch
          ? current
          : admitted,
      );
      // Ready means captured/admitted media: a direct session can wait for its
      // first peer. Notification delivery must never interrupt that session.
      if (
        generation === this.generation &&
        admitted.ready === true &&
        admitted.started_by === identity &&
        !existing
      ) {
        void this.notifyReady(chat, admitted, generation, Date.now() + 60_000);
      }
    } catch (error) {
      capture?.getTracks().forEach((t) => t.stop());
      if (generation !== this.generation) return;
      await this.leave("start_failed");
      if (generation + 1 !== this.generation) return;
      this.change({
        error:
          callErrorCode(error) === "ended"
            ? undefined
            : error instanceof DOMException
              ? error.name
              : error instanceof Error
                ? error.message
                : "unavailable",
      });
      if (existing && error instanceof Error && error.message === "ended") {
        const available = { ...this.snapshot.available };
        if (available[scopeKey(chat)]?.call_id === existing.call_id)
          delete available[scopeKey(chat)];
        this.change({ available });
      }
    } finally {
      if (this.pendingMediaAdmission === generation)
        this.pendingMediaAdmission = undefined;
      finishAdmission?.();
    }
  }
  private async notifyReady(
    chat: Stream,
    call: ActiveCall,
    generation: number,
    deadline: number,
    attempt = 0,
  ) {
    const current = () =>
      !this.disposed &&
      this.generation === generation &&
      this.snapshot.active?.call_id === call.call_id &&
      callKey(this.snapshot.active) === callKey(call) &&
      this.view?.identity === call.started_by &&
      Date.now() < deadline;
    if (!current()) return;
    try {
      const result = await operate({
        ...requestContext(chat, call.started_by),
        op: "call_notify_ready",
        call_id: call.call_id,
      });
      if (result.retry !== true) return;
    } catch (error) {
      if (!current()) return;
      // Fixed diagnostic codes only; native failures may contain private data.
      const code = callErrorCode(error);
      console.warn("Session notification handoff failed.", code);
      if (["ended", "unauthorized", "invalid"].includes(code)) return;
    }
    // A relay acknowledgement can also conceal a not-yet-authorized DM scope.
    // Keep its original event/TTL and let the relay deduplicate actual delivery.
    if (!current() || attempt >= 7) return;
    this.notificationRetry = setTimeout(() => {
      this.notificationRetry = undefined;
      void this.notifyReady(chat, call, generation, deadline, attempt + 1);
    }, 8000);
  }
  async toggle(kind: "audio" | "video" | "screen") {
    const { active, chat } = this.snapshot;
    if (!active || !chat || !this.capture || this.mediaChanging) return;
    if (kind === "screen") return this.toggleScreen();
    this.mediaChanging = true;
    this.change({ changingMedia: true });
    const generation = this.generation;
    const capture = this.capture;
    const state: MediaState = { ...this.snapshot.media };
    try {
      if (kind === "audio") state.audio_muted = !state.audio_muted;
      if (kind === "video") {
        state.video_published = !state.video_published;
        if (
          state.video_published &&
          !this.nativeOwned &&
          !this.capture.getVideoTracks().some((t) => t.readyState === "live")
        ) {
          const video = await navigator.mediaDevices.getUserMedia({
            video: {
              width: { ideal: 1280 },
              height: { ideal: 720 },
              frameRate: { max: 30 },
            },
          });
          if (generation !== this.generation) {
            video.getTracks().forEach((t) => t.stop());
            return;
          }
          video.getTracks().forEach((t) => capture.addTrack(t));
        }
      }
      await this.command(chat, {
        type: "media",
        call_id: active.call_id,
        state,
      });
      if (generation !== this.generation) return;
      await this.adapter?.update(state, capture, this.screen);
      if (generation !== this.generation) return;
      this.capture.getAudioTracks().forEach((t) => {
        t.enabled = !state.audio_muted;
      });
      if (!state.video_published) {
        this.capture.getVideoTracks().forEach((t) => {
          t.stop();
          this.capture!.removeTrack(t);
        });
      }
      if (!state.screen_published) {
        this.screen?.getTracks().forEach((t) => t.stop());
        this.screen = undefined;
      }
      if (kind === "video") {
        await this.setNativeActivity(true, state.video_published);
        if (generation !== this.generation) return;
      }
      this.change({ media: state, error: undefined });
    } catch (error) {
      if (generation === this.generation)
        this.fail(error instanceof Error ? error.message : "unavailable");
    } finally {
      this.mediaChanging = false;
      if (generation === this.generation) this.change({ changingMedia: false });
    }
  }
  private async toggleScreen() {
    const { active, chat } = this.snapshot;
    if (!active || !chat || !this.capture) return;
    const generation = this.generation;
    const capture = this.capture;
    const previous = { ...this.snapshot.media };
    const starting = !previous.screen_published;
    let acquired: MediaStream | undefined;
    let admitted = false;
    this.mediaChanging = true;
    this.change({ changingMedia: true, error: undefined });
    try {
      if (starting) {
        // Called synchronously from the click to preserve system picker activation.
        acquired = await navigator.mediaDevices.getDisplayMedia({
          video: {
            width: { max: 1920 },
            height: { max: 1080 },
            frameRate: { max: 15 },
          },
          audio: false,
        });
        if (generation !== this.generation) return;
        const track = acquired.getVideoTracks()[0];
        if (!track || track.readyState === "ended") return;
        track.contentHint = "detail";
        this.screen = acquired;
        track.onended = () => {
          if (!this.mediaChanging && this.snapshot.media.screen_published)
            void this.toggle("screen");
        };
      } else {
        // Stop capture immediately, even if the control service is unavailable.
        this.screen?.getTracks().forEach((track) => track.stop());
        this.screen = undefined;
        this.change({ media: { ...previous, screen_published: false } });
      }
      const state = { ...previous, screen_published: starting };
      if (starting) {
        // The SFU only allows the sources granted by call control. Grant screen
        // publication first; otherwise a connected audio call rejects this track.
        await this.command(chat, {
          type: "media",
          call_id: active.call_id,
          state,
        });
        admitted = true;
        if (generation !== this.generation) return;
        await this.adapter?.update(state, capture, this.screen);
      } else {
        // Release publication before waiting for the server to revoke its grant.
        await this.adapter?.update(state, capture);
        if (generation !== this.generation) return;
        await this.command(chat, {
          type: "media",
          call_id: active.call_id,
          state,
        });
      }
      if (generation !== this.generation) return;
      this.change({ media: state, error: undefined });
    } catch (error) {
      if (generation !== this.generation) return;
      acquired?.getTracks().forEach((track) => track.stop());
      if (starting) {
        this.screen = undefined;
        if (acquired)
          await this.adapter?.update(previous, capture).catch(() => {});
        if (admitted && generation === this.generation)
          await this.command(chat, {
            type: "media",
            call_id: active.call_id,
            state: previous,
          }).catch(() => {});
      }
      // Closing the system picker is not a call failure.
      const cancelled =
        starting &&
        error instanceof DOMException &&
        ["NotAllowedError", "AbortError"].includes(error.name);
      if (!cancelled) this.change({ error: "screen_unavailable" });
    } finally {
      if (generation !== this.generation || this.screen !== acquired)
        acquired?.getTracks().forEach((track) => track.stop());
      this.mediaChanging = false;
      if (generation === this.generation) {
        this.change({ changingMedia: false });
        if (
          this.snapshot.media.screen_published &&
          this.screen?.getVideoTracks()[0]?.readyState === "ended"
        )
          void this.toggle("screen");
      }
    }
  }
  isNativeMedia() {
    return this.nativeOwned;
  }
  audioOutputContext() {
    const context = this.nativeActivity;
    return context && this.audioActivationReady === context.activation
      ? {
          identity: context.identity,
          sessionId: context.sessionId,
          activation: context.activation,
        }
      : undefined;
  }
  async setSpeakerMuted(muted: boolean): Promise<boolean> {
    const previous = this.speakerMuted;
    const generation = this.generation;
    const adapter = this.adapter;
    const revision = ++this.playbackRevision;
    this.speakerMuted = muted;
    try {
      await adapter?.setSpeakerMuted?.(muted);
      return true;
    } catch {
      if (
        generation !== this.generation ||
        adapter !== this.adapter ||
        revision !== this.playbackRevision
      )
        return true;
      this.speakerMuted = previous;
      if (this.snapshot.active) this.change({ error: "audio_unavailable" });
      return false;
    }
  }
  async setParticipantMuted(
    credential: string,
    muted: boolean,
  ): Promise<boolean> {
    const adapter = this.adapter;
    const generation = this.generation;
    if (!(adapter instanceof NativePeer)) return true;
    if (
      !Object.values(this.snapshot.active?.participants ?? {}).some(
        (person) => person.credential_id === credential,
      )
    )
      return false;
    try {
      await adapter.setParticipantMuted(credential, muted);
      return true;
    } catch {
      if (generation === this.generation)
        this.change({ error: "audio_unavailable" });
      return false;
    }
  }
  localCapture() {
    return this.capture;
  }
  localScreen() {
    return this.screen;
  }
  private async stopMedia() {
    ++this.mediaGeneration;
    this.groupConnecting = undefined;
    this.pendingSignals = [];
    const old = this.adapter;
    this.adapter = undefined;
    this.epoch = 0;
    // Reconnect can request another stop before the previous native stop has
    // returned. A replacement must wait for both, even when adapter is empty.
    const stopping = old?.stop();
    this.mediaStopping = Promise.allSettled([
      this.mediaStopping,
      stopping,
    ]).then(([, current]) => {
      // Report this teardown's failure after all previous cleanup settles.
      // A failure already reported by an earlier stop must not block rejoining.
      if (current.status === "rejected") throw current.reason;
    });
    await this.mediaStopping;
  }
  private setNativeActivity(active: boolean, camera = false) {
    const context = this.nativeActivity;
    if (!context) return Promise.resolve();
    if (!active) {
      this.nativeActivity = undefined;
      this.audioActivationReady = undefined;
    }
    const work = this.activityQueue
      .catch(() => {})
      .then(() => nativeCallState({ ...context, active, camera }))
      .then(() => {
        if (active && this.nativeActivity === context) {
          this.audioActivationReady = context.activation;
          this.change({});
        }
      });
    this.activityQueue = work;
    return work;
  }
  private beginSessionWork() {
    let resolve!: () => void;
    const work = new Promise<void>((done) => {
      resolve = done;
    });
    this.sessionWork.add(work);
    return () => {
      this.sessionWork.delete(work);
      resolve();
    };
  }
  async nativeSessionEnded(sessionId: string, activation: string) {
    if (
      this.nativeActivity?.sessionId === sessionId &&
      this.nativeActivity.activation === activation
    )
      await this.leave("native_end");
  }
  private detachAdopted() {
    if (!this.adoptedNative || !(this.adapter instanceof NativePeer)) return;
    ++this.generation;
    ++this.mediaGeneration;
    this.adapter.detach();
    this.adapter = undefined;
    this.adoptedNative = false;
    this.nativeOwned = false;
    this.nativeActivity = undefined;
    this.audioActivationReady = undefined;
    this.capture = undefined;
    this.screen = undefined;
    this.key = undefined;
    this.epoch = 0;
    this.clearReconnect();
    this.change({
      active: undefined,
      chat: undefined,
      phase: "idle",
      media: { ...muted },
      tiles: [],
      expanded: false,
      changingMedia: false,
    });
  }
  async leave(reason = "user") {
    this.adoptedNative = false;
    const { active, chat } = this.snapshot;
    const identity = this.view?.identity;
    if (
      active?.kind === "group" &&
      (reason === "user" || reason === "native_end")
    )
      this.dismiss(active);
    if (active || this.sessionWork.size) this.refreshBeforeStart = true;
    ++this.generation;
    clearTimeout(this.notificationRetry);
    this.invitationRetries.forEach(clearTimeout);
    this.invitationRetries.clear();
    this.notificationRetry = undefined;
    this.pendingMediaAdmission = undefined;
    this.clearReconnect();
    this.capture?.getTracks().forEach((t) => t.stop());
    this.capture = undefined;
    this.screen?.getTracks().forEach((t) => t.stop());
    this.screen = undefined;
    this.key = undefined;
    this.speakerMuted = false;
    this.nativeOwned = false;
    this.nonces.clear();
    this.change({
      active: undefined,
      chat: undefined,
      phase: "idle",
      changingMedia: false,
      expanded: false,
      media: { ...muted },
      tiles: [],
    });
    const stopping = this.stopMedia();
    const finishLeave =
      active && chat && !this.disposed ? this.beginSessionWork() : undefined;
    const leaving =
      active && chat && !this.disposed
        ? this.command(chat, {
            type: "leave",
            call_id: active.call_id,
          })
            .then(async (result) => {
              if (this.view?.identity !== identity || this.disposed) return;
              if (result.call) await this.presence(result.call);
              else if (
                this.snapshot.available[scopeKey(chat)]?.call_id ===
                active.call_id
              ) {
                const available = { ...this.snapshot.available };
                delete available[scopeKey(chat)];
                this.change({ available });
              }
            })
            .catch(() => {})
            .finally(() => finishLeave?.())
        : undefined;
    const activity = this.setNativeActivity(false).catch(() => {});
    await Promise.all([stopping, leaving, activity]);
    if (updateRequired()) this.policyChanged();
  }
  private fail(code: string) {
    void this.leave("failure");
    this.change({ error: code === "ended" ? undefined : code });
  }
  private clearReconnect() {
    clearTimeout(this.reconnectExpiry);
    clearTimeout(this.reconnectRetry);
    this.reconnectExpiry = undefined;
    this.reconnectRetry = undefined;
  }
  private mediaConnected() {
    this.clearReconnect();
    this.change({ phase: "connected" });
  }
  private beginReconnect() {
    if (!this.snapshot.active || this.disposed || this.nativeOwned) return;
    if (!this.reconnectExpiry) {
      const generation = this.generation;
      // Stop media until fresh signed admission is confirmed. Keep capture only
      // for this bounded recovery window; leave/expiry always releases it.
      void this.stopMedia();
      this.change({ phase: "reconnecting" });
      this.reconnectExpiry = setTimeout(() => {
        if (generation === this.generation) this.fail("unavailable");
      }, 25000);
    }
    this.reconnectRetry ??= setTimeout(() => {
      this.reconnectRetry = undefined;
      void this.tick();
    }, 1500);
  }
  private async tick() {
    const now = Date.now();
    for (const [nonce, time] of this.nonces)
      if (now - time > 65000) this.nonces.delete(nonce);
    if (this.disposed || this.ticking) return;
    this.ticking = true;
    const generation = this.generation;
    try {
      const { active, chat } = this.snapshot;
      if (active && chat && !this.nativeOwned) {
        try {
          const result = await this.command(chat, {
            type: "heartbeat",
            call_id: active.call_id,
          });
          if (generation !== this.generation) return;
          if (result.call) await this.presence(result.call);
        } catch (error) {
          if (generation !== this.generation) return;
          const code = error instanceof Error ? error.message : "unavailable";
          if (code === "unavailable") this.beginReconnect();
          else this.fail(code);
        }
      }
      await this.subscribeChats();
    } finally {
      this.ticking = false;
    }
  }
  dispose() {
    clearTimeout(this.incomingExpiry);
    this.unsubscribePolicy?.();
    this.unsubscribePolicy = undefined;
    this.disposed = true;
    clearInterval(this.timer);
    this.timer = undefined;
    clearTimeout(this.subscriptionRetry);
    this.subscriptionRetry = undefined;
    this.subscriptionBackoff.clear();
    if (this.adoptedNative) this.detachAdopted();
    else void this.leave("disposed");
    this.connections.forEach((c) => c.close());
    this.connections.clear();
    this.subscribed.clear();
    this.view = undefined;
  }
}
