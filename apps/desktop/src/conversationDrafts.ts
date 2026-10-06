import { invoke } from "@tauri-apps/api/core";
import { useLayoutEffect, useState, useSyncExternalStore } from "react";
import type { SetStateAction } from "react";
import type { MessageExpiryHours } from "./messageExpiry";
import { reconcileMentions, type ComposerMention } from "./composerMentions";

export type DraftAttachment = {
  path: string;
  name: string;
  size_bytes: number;
};
export type Draft = {
  text: string;
  expiry: MessageExpiryHours | undefined;
  mentions: ComposerMention[];
  attachment: DraftAttachment | null;
};
export type DraftScope = {
  identity: string;
  credential: string;
  active_space: string | null;
  space: string;
  stream: string;
  thread: string | null;
};
export type ConversationDraftScope = Omit<DraftScope, "thread">;
function sameConversation(a: DraftScope, b: ConversationDraftScope) {
  return (
    a.identity === b.identity &&
    a.credential === b.credential &&
    a.active_space === b.active_space &&
    a.space === b.space &&
    a.stream === b.stream
  );
}
export interface DraftPersistence {
  load(scope: DraftScope): Promise<{ session: string; draft: Draft }>;
  save(scope: DraftScope, session: string, draft: Draft): Promise<void>;
}
const nativePersistence: DraftPersistence = {
  async load(scope) {
    const value = await invoke<{ session: string; draft: Draft }>(
      "draft_load",
      { scope },
    );
    return {
      ...value,
      draft: { ...value.draft, expiry: value.draft.expiry ?? undefined },
    };
  },
  save(scope, session, draft) {
    return invoke("draft_save", {
      scope,
      session,
      content: {
        text: draft.text,
        expiry: draft.expiry ?? null,
        mentions: draft.mentions,
      },
      attachment: draft.attachment,
    });
  },
};
const empty: Draft = {
  text: "",
  expiry: undefined,
  mentions: [],
  attachment: null,
};
const pendingWrites = new Set<Promise<void>>();
const failedWrites = new Map<Entry, unknown>();
const activeStores = new Set<ConversationDrafts>();
/** Reuse foreground/focus/manual Refresh instead of adding recovery controls. */
export function retryConversationDrafts() {
  activeStores.forEach((store) => store.retryFailures());
}
/** Call after native deletion has revoked the conversation's save sessions. */
export function deleteConversationDrafts(scope: ConversationDraftScope) {
  activeStores.forEach((store) => store.deleteConversation(scope));
}
async function settleDraftWrites() {
  while (pendingWrites.size) await Promise.allSettled([...pendingWrites]);
}
/** Explicit lock waits for the last local write before destroying the session key. */
export async function flushConversationDrafts() {
  await settleDraftWrites();
  // A transient disk/capability failure must not permanently prevent Log out.
  // Try the current dirty state once, without requiring a new keystroke.
  retryConversationDrafts();
  await settleDraftWrites();
  if (failedWrites.size) throw failedWrites.values().next().value;
}
type Entry = {
  cancelled: boolean;
  scope: DraftScope;
  draft: Draft;
  ready: boolean;
  loading: boolean;
  loadError?: unknown;
  reportedError?: string;
  savedAttachment: DraftAttachment | null;
  revision: number;
  session?: string;
  edited: Set<keyof Draft>;
  loaded: Promise<void>;
  saving: Promise<void>;
  running: boolean;
  savedRevision: number;
};
/** The in-memory projection is cleared on lock; the native store remains encrypted. */
export class ConversationDrafts {
  private profile: string | undefined;
  private generation = 0;
  private drafts = new Map<string, Entry>();
  private listeners = new Set<() => void>();
  constructor(
    private discard: (attachment: DraftAttachment) => void,
    private persistence: DraftPersistence = nativePersistence,
    private onError: (error: unknown) => void = () => {},
  ) {}
  subscribe = (listener: () => void) => {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  };
  private notify() {
    this.listeners.forEach((listener) => listener());
  }
  deleteConversation(scope: ConversationDraftScope) {
    let changed = false;
    for (const [key, entry] of this.drafts) {
      if (!sameConversation(entry.scope, scope)) continue;
      entry.cancelled = true;
      failedWrites.delete(entry);
      pendingWrites.delete(entry.saving);
      this.drafts.delete(key);
      const attachments = new Map(
        [entry.draft.attachment, entry.savedAttachment]
          .filter((file): file is DraftAttachment => !!file)
          .map((file) => [file.path, file]),
      );
      entry.draft = empty;
      entry.savedAttachment = null;
      entry.session = undefined;
      entry.edited.clear();
      attachments.forEach((file) => this.discard(file));
      changed = true;
    }
    if (changed) this.notify();
  }
  reset(profile?: string) {
    if (this.profile === profile) return;
    const attachments = [...this.drafts.values()]
      .map((entry) => entry.draft.attachment)
      .filter((file): file is DraftAttachment => !!file);
    // Do not invalidate staged files while a queued encrypted save still reads them.
    void flushConversationDrafts()
      .catch(() => {})
      .finally(() =>
        attachments.forEach((attachment) => this.discard(attachment)),
      );
    this.generation++;
    for (const entry of this.drafts.values()) failedWrites.delete(entry);
    this.drafts.clear();
    this.profile = profile;
    if (profile) activeStores.add(this);
    else activeStores.delete(this);
    this.notify();
  }
  open(
    profile: string | undefined,
    key: string,
    scope: DraftScope | undefined,
  ) {
    if (!profile || profile !== this.profile || !scope) return;
    const existing = this.drafts.get(key);
    if (existing) {
      this.retryEntry(existing);
      return;
    }
    const entry: Entry = {
      cancelled: false,
      scope,
      draft: empty,
      ready: false,
      loading: false,
      savedAttachment: null,
      revision: 0,
      edited: new Set(),
      loaded: Promise.resolve(),
      saving: Promise.resolve(),
      running: false,
      savedRevision: 0,
    };
    this.drafts.set(key, entry);
    this.load(entry);
  }
  private report(entry: Entry, error: unknown) {
    if (entry.reportedError !== String(error)) {
      entry.reportedError = String(error);
      this.onError(error);
    }
  }
  private load(entry: Entry) {
    if (entry.loading || entry.ready || !this.profile) return;
    const generation = this.generation;
    const profile = this.profile;
    entry.loading = true;
    entry.loadError = undefined;
    entry.loaded = this.persistence
      .load(entry.scope)
      .then(({ session, draft }) => {
        if (
          entry.cancelled ||
          this.generation !== generation ||
          this.profile !== profile
        ) {
          if (draft.attachment) this.discard(draft.attachment);
          return;
        }
        const merged = { ...draft };
        for (const field of entry.edited)
          Object.assign(merged, { [field]: entry.draft[field] });
        if (
          entry.edited.has("attachment") &&
          draft.attachment &&
          draft.attachment.path !== merged.attachment?.path
        )
          this.discard(draft.attachment);
        entry.session = session;
        entry.draft = merged;
        entry.savedAttachment = draft.attachment;
        entry.ready = true;
        entry.reportedError = undefined;
        this.notify();
      })
      .catch((error) => {
        if (!entry.cancelled && this.generation === generation) {
          entry.loadError = error;
          this.report(entry, error);
        }
      })
      .finally(() => {
        entry.loading = false;
      });
  }
  private retryEntry(entry: Entry) {
    if (entry.loadError) this.load(entry);
    if (entry.revision !== entry.savedRevision && !entry.running)
      this.persist(entry);
  }
  retryFailures() {
    if (!this.profile) return;
    this.drafts.forEach((entry) => {
      if (entry.loadError || failedWrites.has(entry)) this.retryEntry(entry);
    });
  }
  read(profile: string | undefined, key: string): Draft {
    return profile && profile === this.profile
      ? (this.drafts.get(key)?.draft ?? empty)
      : empty;
  }
  ready(profile: string | undefined, key: string) {
    return (
      !!profile && profile === this.profile && !!this.drafts.get(key)?.ready
    );
  }
  private persist(entry: Entry) {
    if (entry.cancelled || entry.running) return;
    if (entry.loadError) this.load(entry);
    entry.running = true;
    const generation = this.generation;
    const save = (async () => {
      await entry.loaded;
      if (entry.cancelled || generation !== this.generation) return;
      if (!entry.session)
        throw entry.loadError ?? new Error("The draft could not be loaded.");
      let recoveredAttachment = false;
      while (entry.savedRevision !== entry.revision) {
        if (entry.cancelled || generation !== this.generation) return;
        const revision = entry.revision;
        const draft = entry.draft;
        try {
          await this.persistence.save(entry.scope, entry.session, draft);
        } catch (error) {
          if (entry.cancelled || generation !== this.generation) return;
          // An older failing selection must not stall a newer removal/edit that
          // was queued while that native save was in flight.
          if (revision !== entry.revision) continue;
          if (
            !recoveredAttachment &&
            /Invalid exchange handle|exchange file/i.test(String(error)) &&
            (await this.restoreSavedAttachment(entry, generation))
          ) {
            recoveredAttachment = true;
            continue;
          }
          throw error;
        }
        if (entry.cancelled || generation !== this.generation) return;
        entry.savedRevision = revision;
        entry.savedAttachment = draft.attachment;
        entry.reportedError = undefined;
        failedWrites.delete(entry);
      }
    })();
    pendingWrites.add(save);
    entry.saving = save;
    void save.catch((error) => {
      if (!entry.cancelled && generation === this.generation) {
        failedWrites.set(entry, error);
        this.report(entry, error);
      }
    });
    void save
      .finally(() => {
        entry.running = false;
        if (
          !entry.cancelled &&
          generation === this.generation &&
          entry.session &&
          !failedWrites.has(entry) &&
          entry.savedRevision !== entry.revision
        )
          this.persist(entry);
        pendingWrites.delete(save);
      })
      .catch(() => {});
  }
  private async restoreSavedAttachment(entry: Entry, generation: number) {
    const previous = entry.draft.attachment;
    // Never replace a newly selected, unsaved file with an older disk draft.
    if (!previous || entry.savedAttachment?.path !== previous.path)
      return false;
    const restored = await this.persistence.load(entry.scope);
    const attachment = restored.draft.attachment;
    if (
      entry.cancelled ||
      generation !== this.generation ||
      entry.session !== restored.session ||
      entry.draft.attachment?.path !== previous.path ||
      !attachment ||
      attachment.name !== previous.name ||
      attachment.size_bytes !== previous.size_bytes
    ) {
      if (attachment) this.discard(attachment);
      return false;
    }
    entry.draft = { ...entry.draft, attachment };
    entry.savedAttachment = attachment;
    entry.revision++;
    this.discard(previous);
    this.notify();
    return true;
  }
  update<K extends keyof Draft>(
    profile: string | undefined,
    key: string,
    field: K,
    value: SetStateAction<Draft[K]>,
  ) {
    if (!profile || this.profile !== profile) return;
    const entry = this.drafts.get(key);
    if (!entry) return;
    const old = entry.draft;
    const next = typeof value === "function" ? value(old[field]) : value;
    entry.draft = { ...old, [field]: next };
    entry.edited.add(field);
    if (field === "text") {
      entry.draft.mentions = reconcileMentions(
        old.text,
        entry.draft.text,
        old.mentions,
      );
      entry.edited.add("mentions");
    }
    entry.revision++;
    this.persist(entry);
    if (
      field === "attachment" &&
      old.attachment &&
      old.attachment.path !== entry.draft.attachment?.path
    ) {
      void entry.saving
        .then(() => this.discard(old.attachment!))
        .catch(() => {});
    }
    this.notify();
  }
  setContent(
    profile: string | undefined,
    key: string,
    text: string,
    mentions: ComposerMention[],
  ) {
    if (!profile || this.profile !== profile) return;
    const entry = this.drafts.get(key);
    if (!entry) return;
    entry.draft = { ...entry.draft, text, mentions };
    entry.edited.add("text");
    entry.edited.add("mentions");
    entry.revision++;
    this.persist(entry);
    this.notify();
  }
  clearSubmitted(profile: string | undefined, key: string, submitted: Draft) {
    if (!profile || this.profile !== profile) return;
    const entry = this.drafts.get(key);
    if (!entry) return;
    // A network completion from a previous send may not erase newly typed text.
    if (
      entry.draft.text === submitted.text &&
      JSON.stringify(entry.draft.mentions) ===
        JSON.stringify(submitted.mentions)
    ) {
      entry.draft = {
        ...entry.draft,
        text: "",
        mentions: [],
        expiry:
          entry.draft.expiry === submitted.expiry
            ? undefined
            : entry.draft.expiry,
      };
      entry.edited.add("text");
      entry.edited.add("mentions");
      entry.edited.add("expiry");
      entry.revision++;
      this.persist(entry);
      this.notify();
    }
  }
}

export function useConversationDraft(
  profile: string | undefined,
  key: string,
  discard: (attachment: DraftAttachment) => void,
  scope?: DraftScope,
  onError?: (error: unknown) => void,
) {
  const [store] = useState(
    () => new ConversationDrafts(discard, nativePersistence, onError),
  );
  useLayoutEffect(() => {
    store.reset(profile);
    return () => store.reset();
  }, [store, profile]);
  useLayoutEffect(() => {
    store.open(profile, key, scope);
  }, [store, profile, key]);
  useLayoutEffect(() => {
    const retry = () => {
      if (document.visibilityState !== "hidden") store.retryFailures();
    };
    window.addEventListener("focus", retry);
    document.addEventListener("visibilitychange", retry);
    document.addEventListener("focusin", retry);
    return () => {
      window.removeEventListener("focus", retry);
      document.removeEventListener("visibilitychange", retry);
      document.removeEventListener("focusin", retry);
    };
  }, [store]);
  const draft = useSyncExternalStore(
    store.subscribe,
    () => store.read(profile, key),
    () => empty,
  );
  return {
    ...draft,
    ready: store.ready(profile, key),
    setText: (value: SetStateAction<string>) =>
      store.update(profile, key, "text", value),
    setContent: (text: string, mentions: ComposerMention[]) =>
      store.setContent(profile, key, text, mentions),
    setExpiry: (value: SetStateAction<MessageExpiryHours | undefined>) =>
      store.update(profile, key, "expiry", value),
    setAttachment: (value: SetStateAction<DraftAttachment | null>) =>
      store.update(profile, key, "attachment", value),
    clearSubmitted: (submitted: Draft) =>
      store.clearSubmitted(profile, key, submitted),
    clear: () => store.reset(),
  };
}
