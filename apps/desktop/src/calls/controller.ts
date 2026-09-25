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
  takeIncomingControl,
  nativeIncomingAction,
} from "./nativePeer";
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
  private subscriptionBackoff = new Map<string, number>();
  private listeners = new Set<() => void>();
  private capture?: MediaStream;
  private nativeDirect = false;
  private managedIncoming?: string;
  private mediaStopping: Promise<void> = Promise.resolve();
  private speakerMuted = false;
  private screen?: MediaStream;
  private mediaChanging = false;
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
    this.change({ available: {}, incoming: undefined });
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
  dismissError = () => this.change({ error: undefined });
  setNativeAnswer = (nativeAnswer: Snapshot["nativeAnswer"]) => {
    if (this.snapshot.nativeAnswer?.id !== nativeAnswer?.id)
      this.change({ nativeAnswer });
  };
  setNativeAnswerChecked = (nativeAnswerChecked: boolean) => {
    if (this.snapshot.nativeAnswerChecked !== nativeAnswerChecked)
      this.change({ nativeAnswerChecked });
  };
  private change(update: Partial<Snapshot>) {
    this.snapshot = { ...this.snapshot, ...update };
    this.listeners.forEach((fn) => fn());
  }
  update(view: View | null | undefined) {
    if (this.view?.identity !== view?.identity) {
      void this.leave("view_changed");
      this.connections.forEach((c) => c.close());
      this.connections.clear();
      this.subscribed.clear();
      this.subscriptionBackoff.clear();
      this.subscriptionCursor = 0;
      clearTimeout(this.subscriptionRetry);
      this.subscriptionRetry = undefined;
      this.endpoints.clear();
      this.change({ available: {}, incoming: undefined, error: undefined });
    }
    this.view = view ?? undefined;
    if (!view) return;
    const incoming = this.snapshot.incoming;
    if (incoming) {
      const chat = this.chatFor(incoming.call);
      if (!chat || !this.canRing(incoming.call, chat))
        this.change({ incoming: undefined });
    }
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
              s.id === chat.space_context && s.managed && s.status === "joined",
          ),
      );
  }
  private chatFor(call: ActiveCall) {
    return this.chats().find((chat) => scopeKey(chat) === callKey(call));
  }
  private canRing(call: ActiveCall, chat: Stream) {
    return (
      !updateRequired() &&
      call.kind === "direct" &&
      call.ringing &&
      !chat.muted &&
      call.started_by !== this.view?.identity &&
      !this.view?.blocked_users?.some((b) => b.identity === call.started_by)
    );
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
        (event) => {
          this.events = this.events
            .catch(() => {})
            .then(() => this.event(event))
            .catch(() => {
              this.fail("unavailable");
            });
        },
        () => {
          const incoming = this.snapshot.incoming;
          if (
            incoming &&
            this.endpoints.get(incoming.chat.space_context!) === endpoint
          )
            this.change({ incoming: undefined });
          for (const chat of this.chats())
            if (this.endpoints.get(chat.space_context!) === endpoint)
              this.subscribed.delete(scopeKey(chat));
          // A connection to an unrelated deployment must not interrupt this call.
          if (
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
        try {
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
          this.subscriptionBackoff.delete(key);
          if (result.call) await this.presence(result.call);
        } catch (error) {
          if (this.disposed || this.view?.identity !== identity) return;
          this.subscriptionBackoff.set(key, Date.now() + 10000);
          const reason = callErrorCode(error);
          // A rejected chat must not prevent other chats from receiving calls.
          // Transport failures still stop this pass to avoid repeated timeouts.
          if (reason !== "unauthorized" && reason !== "invalid") return;
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
  private async event(event: Result) {
    if (event.type === "presence" && event.call)
      await this.presence(event.call);
    else if (event.type === "ended" || event.type === "access_revoked") {
      const eventScope = event.scope as ActiveCall["scope"] | undefined;
      const matchesScope = (scope: ActiveCall["scope"]) =>
        scope.hosting_space_id === eventScope?.hosting_space_id &&
        scope.conversation.space_id === eventScope?.conversation?.space_id &&
        scope.conversation.stream_id === eventScope?.conversation?.stream_id;
      const matches = (call: ActiveCall) =>
        call.call_id === event.call_id || matchesScope(call.scope);
      if (event.type === "access_revoked") {
        for (const chat of this.chats()) {
          const scope = {
            hosting_space_id: chat.space_context!,
            conversation: { space_id: chat.space, stream_id: chat.stream },
          };
          if (matchesScope(scope)) this.subscribed.delete(scopeKey(chat));
        }
      }
      const available = { ...this.snapshot.available };
      for (const [key, call] of Object.entries(available))
        if (matches(call)) delete available[key];
      const incoming = this.snapshot.incoming;
      this.change({
        available,
        incoming: incoming && matches(incoming.call) ? undefined : incoming,
      });
      if (this.snapshot.active && matches(this.snapshot.active))
        await this.leave(event.type);
    } else if (event.type === "signal") await this.signal(event);
  }
  private presence(call: ActiveCall): Promise<void> {
    const task = this.presenceQueue
      .catch(() => {})
      .then(() => this.applyPresence(call));
    this.presenceQueue = task;
    return task;
  }
  private async applyPresence(call: ActiveCall) {
    const chat = this.validate(call);
    if (!chat || !this.view) return;
    if (Object.keys(call.participants).length === 0) {
      const key = callKey(call);
      const known = this.snapshot.available[key];
      if (known?.call_id === call.call_id) {
        const available = { ...this.snapshot.available };
        delete available[key];
        this.change({ available });
      }
      if (this.snapshot.incoming?.call.call_id === call.call_id)
        this.change({ incoming: undefined });
      if (this.snapshot.active?.call_id === call.call_id)
        await this.leave("call_empty");
      return;
    }
    const known = this.snapshot.available[callKey(call)];
    if (known?.call_id === call.call_id && known.key_epoch > call.key_epoch)
      return;
    this.change({
      available: { ...this.snapshot.available, [callKey(call)]: call },
    });
    if (!this.snapshot.active) {
      if (this.canRing(call, chat)) this.change({ incoming: { call, chat } });
      else if (this.snapshot.incoming?.call.call_id === call.call_id)
        this.change({ incoming: undefined });
      return;
    }
    if (call.call_id !== this.snapshot.active.call_id) return;
    if (
      call.participants[this.view.identity]?.credential_id !==
      this.view.credential
    )
      return this.leave("participant_removed");
    this.change({ active: call, chat });
    if (this.managedIncoming) return; // Rust owns the peer and its signaling.
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
    if (call.kind === "direct") {
      const remote = Object.values(call.participants).find(
        (p) => p.credential_id !== this.view!.credential,
      );
      if (!remote) return;
      const access = (
        await this.command(chat, {
          type: "connect_media",
          call_id: call.call_id,
        })
      ).media;
      if (generation !== this.mediaGeneration) return;
      if (!access) throw new Error("unavailable");
      const callbacks = [
        (payload: SignalPayload) =>
          this.sendSignal(remote.credential_id, payload, generation),
        (tiles: import("./types").MediaTile[]) => {
          if (generation === this.mediaGeneration) this.change({ tiles });
        },
        () => {
          if (generation === this.mediaGeneration) this.beginReconnect();
        },
        () => {
          if (generation === this.mediaGeneration) this.mediaConnected();
        },
      ] as const;
      const peer = this.nativeDirect
        ? new NativePeer(
            access,
            this.view.credential,
            remote.credential_id,
            this.view.identity,
            ...callbacks,
            undefined,
            {
              ...requestContext(chat, this.view.identity),
              call_id: call.call_id,
            },
          )
        : new PeerMedia(access, remote.credential_id, ...callbacks);
      this.adapter = peer;
      if (peer instanceof NativePeer)
        await peer.setSpeakerMuted(this.speakerMuted);
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
      to,
      payload,
    });
    if (generation !== this.mediaGeneration) return;
    await this.command(chat, {
      type: "signal",
      call_id: active.call_id,
      to,
      ciphertext: sealed.ciphertext,
    });
  }
  private async signal(event: Result) {
    if (this.managedIncoming) return;
    const generation = this.mediaGeneration;
    const { active, chat } = this.snapshot;
    if (
      !active ||
      !chat ||
      !this.view ||
      event.call_id !== active.call_id ||
      !Object.values(active.participants).some(
        (p) => p.credential_id === event.from,
      )
    )
      return;
    const { signal } = await operate({
      ...requestContext(chat, this.view.identity),
      op: "call_open_signal",
      call_id: active.call_id,
      ciphertext: event.ciphertext,
    });
    if (generation !== this.mediaGeneration || !this.view) return;
    if (
      signal.from !== event.from ||
      signal.to !== this.view.credential ||
      signal.config_id !== active.config_id ||
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
  async start(chat: Stream, video = false, existing?: ActiveCall) {
    if (this.snapshot.active || this.snapshot.phase !== "idle" || !this.view)
      return;
    if (updateRequired()) {
      this.change({ error: "updateRequired", incoming: undefined });
      return;
    }
    const joined = existing?.participants[this.view.identity];
    if (joined && joined.credential_id !== this.view.credential) {
      this.change({ error: "already_joined", incoming: undefined });
      return;
    }
    this.change({
      error: undefined,
      phase: "connecting",
      chat,
      incoming: undefined,
      nativeAnswer: undefined,
    });
    const generation = ++this.generation;
    let capture: MediaStream | undefined;
    try {
      if (chat.chat_kind !== "direct") {
        const sdk = await import("livekit-client");
        if (!sdk.isE2EESupported()) throw new Error("encryption_unavailable");
      }
      this.nativeDirect =
        usesNativePeer() &&
        (existing
          ? existing.kind === "direct"
          : chat.chat_kind === "direct" && chat.members.length === 2);
      if (this.nativeDirect) {
        await nativeMediaPermission(this.view.identity, video);
        capture = new MediaStream();
      } else
        capture = await navigator.mediaDevices.getUserMedia({
          audio: { echoCancellation: true, noiseSuppression: true },
          video: video
            ? {
                width: { ideal: 1280 },
                height: { ideal: 720 },
                frameRate: { ideal: 30, max: 30 },
              }
            : false,
        });
      if (generation !== this.generation) {
        capture.getTracks().forEach((t) => t.stop());
        return;
      }
      this.capture = capture;
      const result = await this.command(
        chat,
        existing
          ? { type: "join", call_id: existing.call_id }
          : {
              type: "start",
              kind:
                chat.chat_kind === "direct" && chat.members.length === 2
                  ? "direct"
                  : "group",
              initial_media: video ? "video" : "audio",
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
      if (!result.call || !this.validate(result.call))
        throw new Error("unauthorized");
      this.change({
        active: result.call,
        chat,
        media: {
          audio_muted: false,
          video_published: video,
          screen_published: false,
        },
      });
      const published = await this.command(chat, {
        type: "media",
        call_id: result.call.call_id,
        state: this.snapshot.media,
      });
      await this.presence(published.call ?? result.call);
    } catch (error) {
      capture?.getTracks().forEach((t) => t.stop());
      if (generation !== this.generation) return;
      await this.leave("start_failed");
      this.change({
        error:
          error instanceof DOMException
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
    }
  }
  async answer() {
    const incoming = this.snapshot.incoming;
    if (
      !incoming ||
      !this.view ||
      this.snapshot.nativeAnswer ||
      this.snapshot.phase !== "idle"
    )
      return;
    const identity = this.view.identity;
    if (usesNativePeer()) {
      this.setNativeAnswer({
        id: incoming.call.call_id,
        cancel: () => {
          void this.decline();
        },
      });
      try {
        if (
          await nativeIncomingAction(identity, incoming.call.call_id, "answer")
        )
          return;
      } catch (error) {
        this.setNativeAnswer(undefined);
        this.change({ error: callErrorCode(error) });
        return;
      }
      this.setNativeAnswer(undefined);
    }
    if (
      this.view?.identity === identity &&
      this.snapshot.incoming?.call.call_id === incoming.call.call_id
    )
      await this.start(incoming.chat, false, incoming.call);
  }
  async decline() {
    const incoming = this.snapshot.incoming;
    const id = incoming?.call.call_id ?? this.snapshot.nativeAnswer?.id;
    this.change({ incoming: undefined, nativeAnswer: undefined });
    if (id && this.view && usesNativePeer())
      await nativeIncomingAction(this.view.identity, id, "decline").catch(
        () => {},
      );
    if (incoming)
      await this.command(incoming.chat, {
        type: "decline",
        call_id: incoming.call.call_id,
      });
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
          !this.nativeDirect &&
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
  isNativeDirect() {
    return this.nativeDirect;
  }
  /** Attach the UI to a call already admitted/connected by native CallKit Answer. */
  async adoptIncoming(
    value: {
      id: string;
      call_id: string;
      phase: "connecting" | "connected";
      call?: ActiveCall | null;
    },
    cancel: () => void,
  ) {
    if (!this.view || !usesNativePeer() || this.disposed) return;
    if (this.snapshot.active && this.snapshot.active.call_id !== value.call_id)
      return;
    if (!value.call) {
      this.managedIncoming = value.id;
      this.change({
        incoming: undefined,
        nativeAnswer: { id: value.call_id, cancel },
      });
      return;
    }
    const call = value.call;
    const chat = this.chats().find((item) => scopeKey(item) === callKey(call));
    if (
      !chat ||
      !this.validate(call) ||
      call.participants[this.view.identity]?.credential_id !==
        this.view.credential
    )
      return;
    if (this.adapter && this.managedIncoming === value.id) {
      this.change({
        active: call,
        phase: value.phase,
        media: call.participants[this.view.identity].media,
      });
      await this.takeIncomingControl(value.id, call, chat, value.phase);
      return;
    }
    const identity = this.view.identity;
    const stopping = this.stopMedia();
    const generation = this.mediaGeneration;
    await stopping;
    if (
      !this.view ||
      this.view.identity !== identity ||
      generation !== this.mediaGeneration ||
      this.disposed
    )
      return;
    this.managedIncoming = value.id;
    this.nativeDirect = true;
    this.epoch = call.key_epoch;
    this.capture = new MediaStream();
    const remote = Object.values(call.participants).find(
      (p) => p.credential_id !== this.view!.credential,
    );
    if (!remote) return;
    this.change({
      active: call,
      chat,
      phase: value.phase,
      incoming: undefined,
      nativeAnswer: undefined,
      available: { ...this.snapshot.available, [callKey(call)]: call },
      media: call.participants[this.view.identity].media,
    });
    this.adapter = new NativePeer(
      {
        provider: "p2p",
        url: "",
        token: "",
        epoch: call.key_epoch,
        ice_servers: [],
      },
      this.view.credential,
      remote.credential_id,
      this.view.identity,
      (payload) => this.sendSignal(remote.credential_id, payload, generation),
      (tiles) => {
        if (generation === this.mediaGeneration) this.change({ tiles });
      },
      () => {
        if (generation === this.mediaGeneration)
          this.managedIncoming
            ? this.fail("unavailable")
            : this.beginReconnect();
      },
      () => {
        if (generation === this.mediaGeneration) this.mediaConnected();
      },
      undefined,
      undefined,
      value.id,
    );
    await this.takeIncomingControl(value.id, call, chat, value.phase);
  }
  private async takeIncomingControl(
    id: string,
    call: ActiveCall,
    chat: Stream,
    phase: string,
  ) {
    if (phase !== "connected" || !this.view || this.managedIncoming !== id)
      return;
    try {
      // Authenticate the foreground socket before relinquishing the native one.
      const current = await this.command(chat, {
        type: "heartbeat",
        call_id: call.call_id,
      });
      if (
        !current.call ||
        current.call.call_id !== call.call_id ||
        !this.validate(current.call) ||
        !this.view ||
        this.managedIncoming !== id
      )
        return;
      await takeIncomingControl(this.view.identity, id);
      if (this.managedIncoming === id) this.managedIncoming = undefined;
    } catch {
      /* Keep the native owner if the foreground connection is not ready. */
    }
  }
  async finishManagedIncoming() {
    if (this.managedIncoming) await this.leave("native_end");
  }
  setSpeakerMuted(muted: boolean) {
    this.speakerMuted = muted;
    void this.adapter?.setSpeakerMuted?.(muted).catch(() => {
      if (this.snapshot.active) this.fail("unavailable");
    });
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
    this.mediaStopping = Promise.all([this.mediaStopping, stopping]).then(
      () => {},
    );
    await this.mediaStopping;
  }
  async leave(reason = "user") {
    const { active, chat } = this.snapshot;
    ++this.generation;
    this.clearReconnect();
    this.capture?.getTracks().forEach((t) => t.stop());
    this.capture = undefined;
    this.screen?.getTracks().forEach((t) => t.stop());
    this.screen = undefined;
    this.key = undefined;
    this.speakerMuted = false;
    this.nativeDirect = false;
    this.managedIncoming = undefined;
    this.nonces.clear();
    this.change({
      active: undefined,
      nativeAnswer: undefined,
      chat: undefined,
      phase: "idle",
      changingMedia: false,
      media: { ...muted },
      tiles: [],
    });
    await this.stopMedia();
    if (active && chat && !this.disposed)
      await this.command(chat, {
        type: "leave",
        call_id: active.call_id,
      }).catch(() => {});
    if (updateRequired()) this.policyChanged();
  }
  private fail(code: string) {
    void this.leave("failure");
    this.change({ error: code });
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
    if (!this.snapshot.active || this.disposed) return;
    if (this.managedIncoming) return; // The native control transport owns this lease.
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
      if (active && chat) {
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
    this.unsubscribePolicy?.();
    this.unsubscribePolicy = undefined;
    this.disposed = true;
    clearInterval(this.timer);
    this.timer = undefined;
    clearTimeout(this.subscriptionRetry);
    this.subscriptionRetry = undefined;
    this.subscriptionBackoff.clear();
    void this.leave("disposed");
    this.connections.forEach((c) => c.close());
    this.connections.clear();
    this.subscribed.clear();
    this.view = undefined;
  }
}
