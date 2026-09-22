/** Isolated UI integration fixture. All IPC is mocked; no account or network writes. */
import { mockIPC, mockWindows } from "@tauri-apps/api/mocks";
import { emit } from "@tauri-apps/api/event";
import type { View, Stream } from "../src/model";
const params = new URLSearchParams(location.search);
mockWindows("main");
localStorage.clear();
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
      retention: "never",
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
const latency: Record<string, number> = {};
const failures: Record<string, string> = {};
const transfers = new Map<
  string,
  { resolve: () => void; reject: (error: Error) => void }
>();
Object.assign(window, {
  __desktopQA: {
    calls,
    latency,
    failures,
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
    async ownMessage(kind: string) {
      const id = `own-${sequence++}`;
      general.rows.push({
        id,
        state: "STORED",
        body: {
          kind,
          issuer_identity: view.identity,
          created_at: new Date().toISOString(),
          ...(kind === "file.shared"
            ? { filename: "sample.pdf", size_bytes: 2048 }
            : { payload: { text: "Own deletion fixture" } }),
        },
      });
      view.revision = (view.revision ?? 0) + 1;
      await emit(
        "desktop-sync",
        structuredClone({ view, identity: view.identity, result: {} }),
      );
      return id;
    },
    async backgroundMessage() {
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
        structuredClone({ view, identity: view.identity, result: {} }),
      );
      return id;
    },
  },
});
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
    if (command === "prepare_export") return "/fixture/download";
    if (command === "save_export") return false;
    if (command === "choose_attachment")
      return {
        path: "/fixture/attachment",
        name: "Redmi attachment test.txt",
        size_bytes: 4194304,
      };
    if (command === "attachment_transfer") {
      await new Promise<void>((resolve, reject) =>
        transfers.set(args.transferId!, { resolve, reject }),
      );
      if (args.request?.op !== "attachment_upload") return { result: {} };
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
        has_profile: true,
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
      let result: object = {};
      let created: string | undefined;
      if (request.op === "mark_read" && stream) {
        for (const row of stream.rows)
          if (request.records?.includes(row.id)) row.unread = false;
        stream.unread_count = stream.rows.filter((row) => row.unread).length;
      }
      if (["create_chat", "contact_create_chat"].includes(request.op)) {
        created = `created-${sequence++}`;
        view.streams.push(
          makeChat(request.name || "Maya, Sam", created, request.chat_kind),
        );
      }
      if (request.op === "contact_open") created = "dm-maya";
      if (request.op === "send" && stream)
        stream.rows.push({
          id: `sent-${sequence++}`,
          state: "LOCAL",
          body: {
            kind: "chat.message",
            issuer_identity: "alex",
            created_at: new Date().toISOString(),
            payload: { text: request.text },
          },
        });
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
