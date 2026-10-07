/** Isolated UI integration fixture. All IPC is mocked; no account or network writes. */
import { mockIPC, mockWindows } from "@tauri-apps/api/mocks";
import { emit } from "@tauri-apps/api/event";
import type { View, Stream } from "../src/model";
import { clearAttachmentPreviews } from "../src/attachmentPreview";
const params = new URLSearchParams(location.search);
if (params.has("composer-blur")) {
  // Reproduce WebKit losing textarea focus before a chip's click arrives.
  // This must also work when no expiry is selected or the last one is cleared.
  document.addEventListener("pointerdown", (event) => {
    if (
      event.target instanceof Element &&
      event.target.closest(".composer-expiry button") &&
      document.activeElement instanceof HTMLTextAreaElement
    ) {
      document.activeElement.blur();
    }
  }, true);
}
mockWindows("main");
localStorage.clear();
if (params.get("theme") !== "default")
  localStorage.setItem("elo.appearance", params.get("theme") ?? "light");
localStorage.setItem("elo.biometricOffer.v1", "handled");
localStorage.setItem("elo.notificationOffer.v1", "handled");
const names = { alex: "Alex", maya: "Maya", sam: "Sam" };
let sequence = 1;
const makeChat = (name: string, id: string, kind = "chat"): Stream => ({
  name,
  stream: id,
  space: "studio",
  space_context: "studio",
  head: "fixture",
  controller: "alex",
  recovery: null,
  forked: false,
  can_post: true,
  can_manage_members: true,
  chat_kind: kind as "chat",
  owners: [{ identity_id: "alex" }],
  members: Object.keys(names).map((identity_id) => ({
    identity_id,
    external: false,
    capabilities: ["READ", "POST"],
    credential_ids: [identity_id],
  })),
  member_names: names,
  rows: [],
});
const general = makeChat("General", "general");
general.is_general = true;
general.rows = [
  {
    id: "first",
    state: "STORED",
    pinned: true,
    body: {
      kind: "chat.message",
      issuer_identity: "maya",
      created_at: "2026-09-20T10:00:00Z",
      payload: { text: "Welcome to the desktop test." },
    },
  },
];
if (params.has("paged")) {
  general.rows = Array.from({ length: 40 }, (_, index) => ({
    id: `parent-${index.toString().padStart(2, "0")}`,
    state: "STORED",
    reply_count: 1,
    body: {
      kind: "chat.message",
      issuer_identity: "maya",
      logical_time: index * 2,
      created_at: `2026-09-20T10:${index.toString().padStart(2, "0")}:00Z`,
      payload: { text: `Conversation message ${index}` },
    },
  }));
  general.rows = general.rows.flatMap((row, index) => [
    row,
    {
      id: `reply-${index.toString().padStart(2, "0")}`,
      state: "STORED",
      body: {
        kind: "chat.message",
        issuer_identity: "sam",
        logical_time: index * 2 + 1,
        created_at: row.body.created_at,
        payload: { text: `Thread response ${index}`, thread_root: row.id },
      },
    },
  ]);
}
const design = makeChat("Design", "design");
design.rows = [
  {
    id: "unread-design",
    state: "ACCEPTED",
    unread: true,
    body: {
      kind: "chat.message",
      issuer_identity: "sam",
      created_at: "2026-09-20T11:00:00Z",
      payload: {
        text: "The new sketches are ready. Let’s review them together.",
      },
    },
  },
];
const view: View = {
  identity: "alex",
  credential: "alex-device",
  name: "Alex",
  avatar: null,
  paged: params.has("paged"),
  active_space: "studio",
  space_setup: false,
  streams: [general, design, makeChat("Maya", "dm-maya", "direct")],
  contacts: [
    { id: "maya", name: "Maya" },
    { id: "sam", name: "Sam" },
  ],
  groups: [],
  demo_names: names,
  spaces: [
    {
      id: "studio",
      name: "Studio",
      status: "joined",
      managed: true,
      owner: true,
      deletable: true,
      requests: 0,
    },
    {
      id: "family",
      name: "Family",
      status: "joined",
      managed: true,
      owner: false,
      requests: 0,
    },
  ],
  reminders: [
    { stream: "general", record: "first", due_at: Date.now() - 1000 },
  ],
  blocked_users: [{ identity: "blocked", name: "Chris" }],
  invitations: {
    enabled: true,
    pending: 0,
    responses: 0,
    actionable: 0,
    notifications: 0,
  },
  replicas: [],
  inbox: {},
  history_warning: "",
  alpha_ready: false,
  counts: { pending: 0, stored: 1, held: 0, rejected: 0, repair_pending: 0 },
};
const management = {
  primary_owner: "alex",
  roles_revision: 1,
  contact_email: "owner@example.test",
  attachments: {
    used_bytes: 0,
    reserved_bytes: 0,
    policy: {
      max_space_bytes: 209715200,
      max_file_bytes: 5242880,
      retention: { hours: 1 },
    },
  },
  members: Object.entries(names).map(([identity, name]) => ({
    identity,
    name,
    role: identity === "alex" ? "primary_owner" : "member",
  })),
  requests: [],
  offers: [] as {
    id: string;
    link: string;
    expires_at: number;
    require_approval: boolean;
    revoked: boolean;
  }[],
};
const calls: { command: string; request?: Record<string, any> }[] = [];
const latency: Record<string, number> = {
  profile_environment: Number(params.get("profile-delay")) || 0,
  "plugin:biometry|remove_data": Number(params.get("cleanup-delay")) || 0,
};
const failures: Record<string, string> = {};
if (params.has("profile-error")) failures.profile_environment = "Local profile unavailable";
const pairing = {
  request: null as null | { id: string; name: string },
  accepted: false,
};
const downloadedImages = new Set<string>();
const transfers = new Map<
  string,
  { resolve: () => void; reject: (error: Error) => void }
>();
Object.assign(window, {
  __desktopQA: {
    calls,
    latency,
    failures,
    pairing,
    clearAttachmentPreviews,
    async buzzMessages() {
      const ownRoot = { id: "buzz-own-root", state: "STORED", body: { kind: "chat.message", issuer_identity: view.identity, created_at: new Date().toISOString(), payload: { text: "My thread" } } };
      const mention = { id: "buzz-mention", state: "STORED", unread: true, body: { kind: "chat.message", issuer_identity: "maya", created_at: new Date().toISOString(), payload: { text: "@Alex please review", mentions: [view.identity] } } };
      const reply = { id: "buzz-reply", state: "STORED", unread: true, body: { kind: "chat.message", issuer_identity: "sam", created_at: new Date().toISOString(), payload: { text: "A reply for you", thread_root: ownRoot.id } } };
      general.rows.push(ownRoot, mention, reply);
      general.unread_count = general.rows.filter(row => row.unread).length;
      general.participating_threads = [...(general.participating_threads ?? []), ownRoot.id];
      view.revision = (view.revision ?? 0) + 1;
      await emit("desktop-sync", structuredClone({ view, identity: view.identity, result: {} }));
    },
    async transferProgress(received: number, total = 1048576) {
      for (const transfer_id of transfers.keys())
        await emit("attachment-transfer-progress", {
          transfer_id,
          received,
          total,
        });
    },
    finishTransfers() {
      transfers.forEach((transfer) => transfer.resolve());
      transfers.clear();
    },
    async ownMessage(kind: string, options: { expiresAt?: number; attachmentExpiresAt?: number; text?: string } = {}) {
      const id = `own-${sequence++}`;
      general.rows.push({
        id,
        state: "STORED",
        body: {
          kind,
          issuer_identity: view.identity,
          created_at: new Date().toISOString(),
          ...(kind === "file.shared"
            ? { filename: params.has("inline-images") ? "photo.jpg" : "sample.pdf", size_bytes: 2048 }
            : { payload: { text: options.text ?? "Own deletion fixture", expires_at_ms: options.expiresAt } }),
          ...(options.attachmentExpiresAt == null ? {} : { attachment: {
            id: "fixture-attachment", object_id: "fixture-object", name: "photo.jpg", mime: "image/jpeg",
            plaintext_size: 2048, encrypted_size: 2200, created_at_ms: Date.now(), expires_at_ms: options.attachmentExpiresAt,
          } }),
        },
      });
      view.revision = (view.revision ?? 0) + 1;
      await emit(
        "desktop-sync",
        structuredClone({ view, identity: view.identity, result: {} }),
      );
      return id;
    },
    async backgroundMessage(live = false) {
      const id = `background-${sequence++}`;
      general.rows.push({
        id,
        state: "STORED",
        unread: true,
        body: {
          kind: "chat.message",
          issuer_identity: "maya",
          created_at: new Date().toISOString(),
          payload: { text: "Background delivery" },
        },
      });
      general.unread_count = general.rows.filter((row) => row.unread).length;
      view.revision = (view.revision ?? 0) + 1;
      await emit(
        "desktop-sync",
        structuredClone({ view, identity: view.identity, result: live ? { received_messages: [id] } : {} }),
      );
      return id;
    },
  },
});
const conversationDrafts = new Map<string, unknown>();
const qr =
  '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><rect width="100" height="100" fill="white"/><path fill="black" d="M10 10h25v25H10zM65 10h25v25H65zM10 65h25v25H10zM55 55h20v20H55z"/></svg>';
mockIPC(
  async (command, payload) => {
    const args = payload as {
      request?: Record<string, any>;
      action?: string;
      task?: string;
      transferId?: string;
    };
    calls.push({ command, request: args?.request ?? args });
    const failure = failures[args?.request?.op ?? command];
    if (failure) throw new Error(failure);
    const delay = latency[args?.request?.op ?? command];
    if (delay) await new Promise((resolve) => setTimeout(resolve, delay));
    if (command === "draft_load") {
      const scope = (payload as any).scope;
      return { session: "fixture-session", draft: conversationDrafts.get(JSON.stringify(scope)) ?? { text: "", expiry: null, mentions: [], attachment: null } };
    }
    if (command === "draft_save") {
      const value = payload as any;
      conversationDrafts.set(JSON.stringify(value.scope), { ...value.content, attachment: value.attachment });
      return;
    }
    if (command === "prepare_export") return "/fixture/download";
    if (command === "save_export") return false;
    if (command === "attachment_preview") {
      if (!params.has("inline-images") || !downloadedImages.has(args.request?.record)) return null;
      const canvas = document.createElement("canvas");
      canvas.width = 640; canvas.height = 480;
      const context = canvas.getContext("2d")!;
      context.fillStyle = "#bbdac9"; context.fillRect(0, 0, 640, 480);
      context.fillStyle = "#2d493d"; context.fillRect(130, 100, 380, 280);
      return canvas.toDataURL("image/png");
    }
    if (command === "share_cached_attachment") return null;
    if (command === "stage_attachment") {
      const input = payload as { name: string; data: string };
      return { path: `/fixture/staged-${sequence++}`, name: input.name, size_bytes: atob(input.data).length };
    }
    if (command === "choose_attachment")
      return {
        path: "/fixture/attachment",
        name: params.get("attachment-name") ?? "Redmi attachment test.txt",
        size_bytes: 4194304,
      };
    if (command === "attachment_transfer") {
      await new Promise<void>((resolve, reject) =>
        transfers.set(args.transferId!, { resolve, reject }),
      );
      if (args.request?.op !== "attachment_upload") {
        downloadedImages.add(args.request!.record);
        return { result: {} };
      }
      const chat = view.streams.find(
        (chat) => chat.stream === args.request!.stream,
      )!;
      const id = `uploaded-${sequence++}`;
      chat.rows.push({
        id,
        state: "PENDING",
        body: {
          kind: "file.shared",
          issuer_identity: view.identity,
          created_at: new Date().toISOString(),
          filename: args.request.name,
          size_bytes: 4194304,
        },
      });
      view.revision = (view.revision ?? 0) + 1;
      return structuredClone({ view, result: { record: id } });
    }
    if (command === "cancel_attachment_transfer") {
      transfers
        .get(args.transferId!)
        ?.reject(new Error("Attachment transfer cancelled."));
      transfers.delete(args.transferId!);
      return;
    }
    if (command === "profile_environment")
      return {
        mobile: params.has("mobile"),
        platform: params.get("platform") ?? undefined,
        has_profile: !params.has("new-profile"),
        directory: "fixture",
        demo_helpers: false,
        saved_profiles: [],
      };
    if (command === "unlock") return structuredClone(view);
    if (command === "push_task")
      return { available: false, enabled: false, pending: false };
    if (command.includes("biometry"))
      return { isAvailable: false, biometryType: 0 };
    if (command === "invitation_qr") return [qr];
    if (
      command === "profile_task" &&
      ["device_list", "device_revoke"].includes(args.request?.op)
    )
      return {
        devices: [
          {
            id: "1".repeat(64),
            credential: "synthetic-current-credential",
            current: true,
          },
          {
            id: "2".repeat(64),
            credential: "synthetic-other-credential",
            current: false,
          },
        ],
        pending: calls.some((call) => call.request?.op === "device_revoke")
          ? 1
          : 0,
        unavailable: 0,
      };
    if (command === "profile_task" && args.request?.op === "pair_approve") {
      pairing.accepted = true;
      return {};
    }
    if (command === "profile_task" && args.request?.op === "pair_poll") {
      return pairing.accepted
        ? {
            requests: [],
            credential: "synthetic-accepted-credential",
            device_id: "3".repeat(64),
          }
        : { requests: pairing.request ? [pairing.request] : [] };
    }
    if (command === "profile_task")
      return {
        svg: qr,
        code: "elo://test",
        expires: Date.now() + 300000,
        requests: [],
      };
    if (command === "operate") {
      const request = args.request ?? {};
      const stream = view.streams.find(
        (chat) => chat.stream === request.stream,
      );
      if (request.op === "history_page" && stream) {
        const all = stream.rows;
        let rows = all.filter((row) => !row.body.payload?.thread_root);
        let next: string | null = null;
        let newer: string | null = null;
        if (request.records) {
          rows = all.filter((row) => request.records.includes(row.id));
        } else if (request.thread) {
          rows = all.filter(
            (row) =>
              row.id === request.thread ||
              row.body.payload?.thread_root === request.thread,
          );
        } else if (request.query?.trim()) {
          rows = all.filter((row) =>
            row.body.payload?.text.includes(request.query),
          );
        } else if (request.around) {
          rows = all.filter((row) => row.id === request.around);
          newer = "after-target";
        } else {
          const end = request.before ? Number(request.before) : rows.length;
          rows = rows.slice(Math.max(0, end - 20), end);
          next = end > 20 ? String(end - 20) : null;
        }
        return structuredClone({
          history: {
            identity: view.identity,
            space_context: view.active_space,
            space: stream.space,
            stream: stream.stream,
            revision: view.revision ?? 0,
            rows,
            context: [],
            next,
            newer,
            thread: request.thread,
            query: request.query,
          },
        });
      }
      if (
        request.op === "message_action" &&
        request.action?.type === "delete" &&
        stream
      ) {
        const row = stream.rows.find((row) => row.id === request.action.target);
        if (!row || row.body.issuer_identity !== view.identity)
          throw new Error("Only the author can delete this message.");
        row.body = {
          kind: "deleted",
          issuer_identity: view.identity,
          created_at: row.body.created_at,
          deleted_record_id: row.id,
          payload: { text: "", thread_root: row.body.payload?.thread_root },
        };
        row.unread = false;
        row.pinned = false;
        row.reactions = [];
      }
      if (request.op === "message_action" && request.action?.type === "edit" && stream) {
        const row = stream.rows.find((row) => row.id === request.action.target);
        if (!row || row.body.issuer_identity !== view.identity || row.body.kind !== "chat.message")
          throw new Error("Only the author can edit this message.");
        row.body.payload = { ...row.body.payload, text: request.action.text,
          mentions: request.action.mentions ?? [], edited_at_ms: Date.now() };
      }
      let result: object = {};
      if (request.op === "message_action" && request.action?.type === "expiry" && stream) {
        const row = stream.rows.find((row) => row.id === request.action.target);
        if (!row || row.body.issuer_identity !== view.identity || row.body.kind !== "chat.message")
          throw new Error("message_expiry_author_only");
        const hours = request.action.hours;
        row.body.payload = { ...row.body.payload,
          expires_at_ms: hours == null ? null : Date.now() + hours * 3_600_000,
          expiry_hours: hours,
        };
      }
      let sent: { id: string; logical_time: number } | undefined;
      let created: string | undefined;
      if (request.op === "mark_read" && stream) {
        for (const row of stream.rows)
          if (request.records?.includes(row.id)) row.unread = false;
        stream.unread_count = stream.rows.filter((row) => row.unread).length;
      }
      if (request.op === "thread_follow" && stream) {
        stream.followed_threads = (stream.followed_threads ?? []).filter(id => id !== request.message);
        stream.unfollowed_threads = (stream.unfollowed_threads ?? []).filter(id => id !== request.message);
        (request.followed ? stream.followed_threads : stream.unfollowed_threads).push(request.message);
      }
      if (["create_chat", "contact_create_chat"].includes(request.op)) {
        created = `created-${sequence++}`;
        view.streams.push(
          makeChat(request.name || "Maya, Sam", created, request.chat_kind),
        );
      }
      if (request.op === "create_group") {
        view.groups ??= [];
        view.groups.push({ id: `group-${sequence++}`, name: request.name.trim() });
      }
      if (request.op === "set_chat_group" && stream)
        stream.group = request.group || null;
      if (request.op === "contact_open") created = "dm-maya";
      if (request.op === "send" && stream) {
        sent = { id: `sent-${sequence++}`, logical_time: Date.now() };
        stream.rows.push({
          id: sent.id,
          state: "LOCAL",
          body: {
            kind: "chat.message",
            logical_time: sent.logical_time,
            issuer_identity: "alex",
            created_at: new Date().toISOString(),
            payload: { text: request.text, mentions: request.mentions ?? [], thread_root: request.reply_to,
              expiry_hours: request.expires_in_hours ?? null,
              expires_at_ms: request.expires_in_hours ? Date.now() + request.expires_in_hours * 3_600_000 : undefined },
          },
        });
      }
      if (request.op === "set_profile_details") {
        view.name = request.name;
        view.avatar = request.avatar;
      }
      if (request.op === "reminder_remove")
        view.reminders = view.reminders?.filter(
          (item) => item.record !== request.record,
        );
      if (request.op === "space_select") view.active_space = request.id;
      if (request.op === "space_invite") {
        management.offers.push({
          id: "invitation",
          link: "elo://space/v1#test",
          expires_at: Date.now() + 3600000,
          require_approval: false,
          revoked: false,
        });
        result = { link: "elo://space/v1#test" };
      }
      if (request.op === "space_manage") result = management;
      if (request.op === "space_attachment_retention") {
        management.attachments.policy.retention = { hours: request.body.hours };
        result = { policy: management.attachments.policy };
      }
      if (request.op === "space_attachment_cleanup_preview")
        result = {
          files: 0,
          bytes: 0,
          before_ms: Date.now(),
          days: request.body.days,
        };
      if (request.op === "space_contact")
        result = { contact_email: management.contact_email };
      if (request.op === "space_storage")
        result = {
          used_bytes: 32768,
          quota_bytes: 268435456,
          before_ms: Date.now(),
          removable_bytes: 1024,
          removable_copies: 2,
        };
      if (request.op === "set_user_blocked") view.blocked_users = [];
      if (request.op === "set_chat_muted" && stream)
        stream.muted = request.muted;
      if (request.op === "contact_code")
        result = { link: "elo://exchange/v1#test" };
      view.revision = (view.revision ?? 0) + 1;
      return structuredClone({
        view,
        stream: created,
        sent,
        result,
        received: [],
        incoming: [],
        outgoing: [],
        notices: [],
        errors: [],
      });
    }
    return null;
  },
  { shouldMockEvents: true },
);
await import("../src/main");
