import { useEffect, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import {
  scan,
  cancel,
  checkPermissions,
  requestPermissions,
  Format,
} from "@tauri-apps/plugin-barcode-scanner";
import { shareText } from "@choochmeque/tauri-plugin-sharekit-api";
import { t } from "./i18n";
import { ScreenHeader } from "./ScreenHeader";
import { EmptyState } from "./EmptyState";
import { SpaceJoinRequests } from "./SpaceJoinRequests";
import { PullToRefresh } from "./PullToRefresh";
import { Icon } from "./Icon";
import { useToast } from "./Toast";
import { QrParts } from "./invitationTransport";
import { profileName, type View, type Stream } from "./model";
import "./invitations.css";

export type InvitationRoute = {
  page:
    | "invite"
    | "requests"
    | "invitations"
    | "scan"
    | "contact"
    | "activity"
    | "notifications";
  link?: string;
  shareLink?: string;
  contacts?: boolean;
  unscoped?: boolean;
};
type Preview = {
  kind: "invitation" | "request" | "grant" | "declined" | "contact";
  id: string;
  name: string;
  identity: string;
  stream: string;
  space: string;
  root?: string;
  capabilities?: string[];
  expires_at?: number;
  automatic?: boolean;
};
type Entry = {
  id: string;
  identity: string;
  name: string;
  status: string;
  grant?: string;
  capabilities: string[];
};
type Offer = {
  id: string;
  active: boolean;
  expires_at: number;
  reusable: boolean;
  capabilities: string[];
  link: string;
};
type Reply = {
  view?: View;
  link?: string;
  id?: string;
  stream?: string;
  requests?: Entry[];
  offers?: Offer[];
  automatic?: boolean;
  incoming?: { id: string; name: string; space: string; stream: string }[];
  received?: { id: string; name: string; identity: string; link: string }[];
  notices?: {
    id: string;
    kind: "removed";
    name: string;
    stream: string;
    seen: boolean;
  }[];
  outgoing?: {
    id: string;
    name: string;
    stream: string;
    status:
      | "queued"
      | "waiting"
      | "manual"
      | "approved"
      | "declined"
      | "joined"
      | "expired";
    link?: string;
    request_link: string;
    seen?: boolean;
  }[];
};
export function InvitationFlow({
  route,
  stream,
  view,
  mobile,
  onClose,
  onView,
  onJoined,
  embedded = false,
  active = true,
  onInvite,
  onScan,
  onSpaces,
}: {
  route: InvitationRoute;
  embedded?: boolean;
  active?: boolean;
  onSpaces?: () => void;
  onInvite?: () => void;
  onScan?: () => void;
  stream?: Stream;
  view: View;
  mobile: boolean;
  onClose: () => void;
  onView: (view: View) => void;
  onJoined: (stream: string) => void;
}) {
  const { reportError, showError } = useToast();
  const [page, setPage] = useState(route.page);
  const [busy, setBusy] = useState(false);
  const [contactError, setContactError] = useState(false);
  const [post, setPost] = useState(true);
  const [history, setHistory] = useState(false);
  const [reusable, setReusable] = useState(true);
  const [lifetime, setLifetime] = useState("24h");
  const [name, setName] = useState(profileName(view));
  const [input, setInput] = useState(route.link ?? "");
  const [preview, setPreview] = useState<Preview | null>(null);
  const [trusted, setTrusted] = useState(false);
  const [output, setOutput] = useState<{
    link: string;
    kind: "invitation" | "request" | "grant" | "contact";
    name?: string;
    automatic?: boolean;
  } | null>(
    route.shareLink
      ? { link: route.shareLink, kind: "invitation", name: stream?.name }
      : null,
  );
  const [requests, setRequests] = useState<Entry[]>([]);
  const [offers, setOffers] = useState<Offer[]>([]);
  const [activity, setActivity] = useState<Reply>({});
  const [requestsRefresh, setRequestsRefresh] = useState(0);
  const [selected, setSelected] = useState<Entry | null>(null);
  const [disable, setDisable] = useState<string | null>(null);
  const [scanning, setScanning] = useState(false);
  const [progress, setProgress] = useState({ received: 0, total: 0 });
  const scanningRef = useRef(false);
  const mounted = useRef(true);
  const contactRequest = useRef<Promise<Reply> | null>(null);
  const initialName = useRef(profileName(view));
  const pageRef = useRef<HTMLElement>(null);
  const call = async (request: Record<string, unknown>) => {
    const r = await invoke<Reply>("operate", {
      request: {
        space: stream?.space,
        stream: stream?.stream,
        ...request,
        expected_identity: view.identity,
        expected_space: view.active_space,
      },
    });
    if (r.view) onView(r.view);
    return r;
  };
  const perform = async (fn: () => Promise<void>) => {
    if (busy) return;
    setBusy(true);
    try {
      await fn();
    } catch (error) {
      reportError(error);
    } finally {
      if (mounted.current) setBusy(false);
    }
  };
  const load = async () => {
    const r = await call({ op: "invitation_list" });
    if (mounted.current) {
      setRequests(r.requests ?? []);
      setOffers(r.offers ?? []);
    }
  };
  const loadActivity = async () => {
    const r = await call({ op: "invitation_activity" });
    if (mounted.current) {
      setActivity(r);
      if (page === "notifications") {
        const ids = [
          ...(r.notices ?? [])
            .filter((entry) => !entry.seen)
            .map((entry) => entry.id),
          ...(r.outgoing ?? [])
            .filter(
              (entry) => entry.status === "declined" && entry.seen === false,
            )
            .map((entry) => entry.id),
        ];
        if (ids.length)
          await call({ op: "invitation_notifications_seen", ids });
      }
    }
  };
  const refresh = async () => {
    setRequestsRefresh((value) => value + 1);
    await call({ op: "invitation_sync", force: true });
    if (page === "activity" || page === "notifications") await loadActivity();
    if (page === "requests" || page === "invitations") await load();
  };
  const inspect = async (link: string) => {
    const p = await invoke<Preview>("operate", {
      request: {
        op: route.contacts ? "contact_preview" : "invitation_preview",
        link,
        space: stream?.space,
        stream: stream?.stream,
      },
    });
    if (mounted.current) {
      setInput(link);
      setPreview(p);
      setTrusted(false);
      setOutput(null);
    }
  };
  const stopScan = () => {
    scanningRef.current = false;
    setScanning(false);
    document.documentElement.classList.remove("elo-scanning");
    void cancel().catch(() => {});
  };
  useEffect(() => {
    mounted.current = true;
    pageRef.current?.focus();
    return () => {
      mounted.current = false;
      scanningRef.current = false;
      document.documentElement.classList.remove("elo-scanning");
      if (mobile) void cancel().catch(() => {});
    };
  }, [mobile]);
  useEffect(() => {
    if (!active) return;
    if (page === "requests" || page === "invitations") void perform(load);
    if (page === "activity" || page === "notifications")
      void perform(loadActivity);
  }, [page, stream?.stream, view, active]);
  useEffect(() => {
    if (route.link) void perform(() => inspect(route.link!));
  }, [route.link]);
  useEffect(() => {
    if (route.page !== "contact" || !initialName.current) return;
    let active = true;
    setBusy(true);
    contactRequest.current ??= invoke<Reply>("operate", {
      request: {
        op: "contact_create",
        name: initialName.current,
        expected_identity: view.identity,
        expected_space: view.active_space,
      },
    });
    void contactRequest.current
      .then((result) => {
        if (active && result.link)
          setOutput({
            link: result.link,
            kind: "contact",
            name: initialName.current,
          });
      })
      .catch((error) => {
        if (active) {
          setContactError(true);
          reportError(error);
        }
      })
      .finally(() => {
        if (active) setBusy(false);
      });
    return () => {
      active = false;
    };
  }, [route.page]);
  const goBack = () => {
    if (scanning) {
      stopScan();
      return;
    }
    if (output) {
      if (route.page === "contact" && initialName.current) {
        onClose();
        return;
      }
      setOutput(null);
      return;
    }
    if (selected) {
      setSelected(null);
      setTrusted(false);
      return;
    }
    if (preview) {
      setPreview(null);
      setTrusted(false);
      return;
    }
    if (embedded && page !== route.page) {
      setPage(route.page);
      return;
    }
    onClose();
  };
  const inline =
    embedded &&
    page === route.page &&
    !selected &&
    !preview &&
    !output &&
    !scanning;
  useEffect(() => {
    if (!active) return;
    const key = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        e.preventDefault();
        e.stopPropagation();
        goBack();
      }
    };
    document.addEventListener("keydown", key, true);
    return () => document.removeEventListener("keydown", key, true);
  });
  const startScan = async () => {
    if (scanningRef.current) return;
    let started = false;
    try {
      const permission = await checkPermissions();
      if (
        permission !== "granted" &&
        (await requestPermissions()) !== "granted"
      ) {
        showError(t("invite.cameraDenied"));
        return;
      }
      const parts = new QrParts();
      scanningRef.current = true;
      started = true;
      setScanning(true);
      setProgress(parts.progress);
      document.documentElement.classList.add("elo-scanning");
      while (scanningRef.current) {
        const result = await scan({ formats: [Format.QRCode], windowed: true });
        if (!scanningRef.current) break;
        const link = parts.add(result.content);
        setProgress(parts.progress);
        if (link) {
          stopScan();
          await perform(() => inspect(link));
          break;
        }
      }
    } catch (error) {
      if (!started || scanningRef.current) {
        const reason = error instanceof Error ? error.message : "";
        if (reason === "invitationMixedCodes")
          showError(t("invite.mixedCodes"));
        else if (
          reason === "invitationInvalidCode" ||
          reason === "invitationTooLarge"
        )
          showError(t("invite.invalidCode"));
        else reportError(error);
      }
      stopScan();
    }
  };
  const title = output
    ? t(`invite.output.${output.kind}`)
    : selected
      ? t("invite.request")
      : preview
        ? t(
            preview.kind === "contact"
              ? "contacts.review"
              : preview.kind === "declined"
                ? "invite.declined"
                : preview.kind === "grant"
                  ? "invite.approval"
                  : preview.kind === "request"
                    ? "invite.request"
                    : "members.invite",
          )
        : page === "scan" && route.contacts
          ? t("contacts.add")
          : t(`invite.page.${page}`);
  const chatName = output
    ? output.kind === "contact"
      ? undefined
      : output.name
    : preview
      ? preview.kind === "contact"
        ? undefined
        : preview.kind === "request"
          ? view.streams.find((item) => item.stream === preview.stream)?.name
          : preview.name
      : selected ||
          (page !== "contact" &&
            page !== "activity" &&
            page !== "notifications")
        ? stream?.name
        : undefined;
  const codeOutput =
    output ??
    (page === "contact" && initialName.current && !contactError
      ? {
          kind: "contact" as const,
          link: undefined,
          automatic: false,
        }
      : null);
  const notificationsPage = page === "notifications";
  const ownedSpace = view.spaces?.find(
    (space) =>
      space.id === view.active_space &&
      space.owner &&
      space.status === "joined",
  );
  const otherSpaceRequests = Math.max(
    0,
    (view.space_requests ?? 0) - (ownedSpace?.requests ?? 0),
  );
  const received = notificationsPage ? [] : (activity.received ?? []);
  const incoming = notificationsPage ? [] : (activity.incoming ?? []);
  const outgoing = (activity.outgoing ?? []).filter(
    (entry) =>
      ["joined", "declined", "expired"].includes(entry.status) ===
      notificationsPage,
  );
  const notices = notificationsPage ? (activity.notices ?? []) : [];
  return (
    <section
      className={`${inline ? "invitation-panel" : "invitation-page"}${scanning ? " invitation-scanner" : ""}`}
      ref={pageRef}
      tabIndex={-1}
      aria-label={title}
    >
      {!inline && <ScreenHeader title={title} onBack={goBack} />}
      {page === "activity" &&
        !scanning &&
        onSpaces &&
        otherSpaceRequests > 0 && (
          <button onClick={onSpaces}>
            {t("spaces.otherRequests", { count: otherSpaceRequests })}
          </button>
        )}
      {scanning ? (
        <>
          <div className="scan-window" aria-label={t("invite.camera")}>
            <span />
          </div>
          <div className="scan-controls">
            <p aria-live="polite">
              {progress.total
                ? t("invite.scannedParts", { ...progress })
                : t("invite.scanHint")}
            </p>
            <button onClick={stopScan}>{t("invite.cancel")}</button>
          </div>
        </>
      ) : (
        <PullToRefresh
          className={`invitation-scroll${page === "activity" && ownedSpace && !selected && !preview && !output ? " has-join-requests" : ""}`}
          enabled={
            mobile &&
            !selected &&
            !preview &&
            !output &&
            (page === "activity" ||
              page === "notifications" ||
              page === "requests" ||
              page === "invitations")
          }
          disabled={busy}
          onRefresh={refresh}
          resetKey={page}
        >
          {chatName &&
            !inline &&
            page !== "invite" &&
            output?.kind !== "invitation" && (
              <p className="invitation-context">{chatName}</p>
            )}
          {codeOutput ? (
            <>
              <p className="invitation-hint">
                {codeOutput.kind === "invitation"
                  ? t("invite.hint.invitation", { chat: chatName ?? "" })
                  : t(
                      codeOutput.kind === "contact"
                        ? "contacts.hint"
                        : codeOutput.automatic &&
                            (codeOutput.kind === "request" ||
                              codeOutput.kind === "grant")
                          ? `invite.delivery.${codeOutput.kind}`
                          : `invite.hint.${codeOutput.kind}`,
                    )}
              </p>
              {codeOutput.automatic ? (
                <>
                  <button
                    onClick={() => {
                      setOutput(null);
                      setPage("activity");
                    }}
                  >
                    {t("invite.activity.open")}
                  </button>
                  <details>
                    <summary>{t("invite.delivery.manual")}</summary>
                    <InvitationCode link={codeOutput.link} mobile={mobile} />
                  </details>
                </>
              ) : (
                <InvitationCode
                  link={codeOutput.link}
                  mobile={mobile}
                  showLink={codeOutput.kind !== "contact"}
                />
              )}
            </>
          ) : selected ? (
            <>
              <Person name={selected.name} identity={selected.identity} />
              {selected.status === "pending" ? (
                <>
                  <Permissions
                    post={post}
                    history={history}
                    allowPost={selected.capabilities.includes("POST")}
                    allowHistory={selected.capabilities.includes(
                      "SHARE_HISTORY",
                    )}
                    onPost={setPost}
                    onHistory={setHistory}
                  />
                  <label className="check">
                    <input
                      type="checkbox"
                      checked={trusted}
                      onChange={(e) => setTrusted(e.target.checked)}
                    />
                    {t("invite.recognize")}
                  </label>
                  <div className="invitation-buttons">
                    <button
                      disabled={busy || !trusted}
                      onClick={() =>
                        void perform(async () => {
                          const r = await call({
                            op: "invitation_approve",
                            id: selected.id,
                            confirmed_identity: selected.identity,
                            confirmed: trusted,
                            post,
                            share_history: history,
                          });
                          if (r.link) {
                            setSelected(null);
                            setOutput({
                              link: r.link,
                              kind: "grant",
                              name: stream?.name,
                              automatic: r.automatic,
                            });
                          }
                          await load();
                        })
                      }
                    >
                      {t("invite.approve")}
                    </button>
                    <button
                      className="quiet danger"
                      disabled={busy}
                      onClick={() =>
                        void perform(async () => {
                          await call({
                            op: "invitation_decline",
                            id: selected.id,
                          });
                          setSelected(null);
                          await load();
                        })
                      }
                    >
                      {t("invite.decline")}
                    </button>
                  </div>
                </>
              ) : (
                <>
                  <p className="invitation-hint">
                    {selected.status === "approved"
                      ? t("invite.approved")
                      : t("invite.declined")}
                  </p>
                  {selected.grant && (
                    <button
                      onClick={() =>
                        setOutput({
                          link: selected.grant!,
                          kind: "grant",
                          name: stream?.name,
                        })
                      }
                    >
                      {t("invite.shareApproval")}
                    </button>
                  )}
                </>
              )}
            </>
          ) : preview ? (
            <>
              <Person
                name={
                  preview.kind === "request" || preview.kind === "contact"
                    ? preview.name
                    : t("invite.inviter")
                }
                identity={preview.identity}
              />
              {preview.kind === "contact" ? (
                <>
                  <p className="invitation-hint">{t("contacts.reviewHint")}</p>
                  <label className="check">
                    <input
                      type="checkbox"
                      checked={trusted}
                      onChange={(e) => setTrusted(e.target.checked)}
                    />
                    {t("invite.recognize")}
                  </label>
                  <button
                    disabled={busy || !trusted}
                    onClick={() =>
                      void perform(async () => {
                        await call({
                          op: "contact_add",
                          link: input,
                          trusted,
                          confirmed_contact: preview.id,
                        });
                        onClose();
                      })
                    }
                  >
                    {t("contacts.save")}
                  </button>
                </>
              ) : preview.kind === "invitation" ? (
                <>
                  <p className="invitation-hint">
                    {t(
                      preview.automatic
                        ? "invite.delivery.hint"
                        : "invite.requiresApproval",
                    )}
                  </p>
                  <PermissionSummary
                    capabilities={preview.capabilities ?? []}
                  />
                  <label>
                    {t("invite.yourName")}
                    <input
                      autoComplete="nickname"
                      maxLength={120}
                      value={name}
                      onChange={(e) => setName(e.target.value)}
                    />
                  </label>
                  <label className="check">
                    <input
                      type="checkbox"
                      checked={trusted}
                      onChange={(e) => setTrusted(e.target.checked)}
                    />
                    {t("invite.trustInviter")}
                  </label>
                  <button
                    disabled={busy || !trusted || !name.trim()}
                    onClick={() =>
                      void perform(async () => {
                        const r = await call({
                          op: "invitation_request",
                          link: input,
                          confirmed_invitation: preview.id,
                          trusted,
                          name,
                        });
                        if (r.link) {
                          setPreview(null);
                          setOutput({
                            link: r.link,
                            kind: "request",
                            name: preview.name,
                            automatic: r.automatic,
                          });
                        }
                      })
                    }
                  >
                    {t("invite.requestAccess")}
                  </button>
                </>
              ) : preview.kind === "request" ? (
                <>
                  <p className="invitation-hint">{t("invite.reviewFirst")}</p>
                  <button
                    disabled={busy}
                    onClick={() =>
                      void perform(async () => {
                        const r = await call({
                          op: "invitation_receive",
                          link: input,
                        });
                        const list = await invoke<Reply>("operate", {
                          request: {
                            op: "invitation_list",
                            space: preview.space,
                            stream: preview.stream,
                          },
                        });
                        const entry = list.requests?.find((e) => e.id === r.id);
                        if (entry) {
                          onJoined(preview.stream);
                          setSelected(entry);
                          setPost(entry.capabilities.includes("POST"));
                          setHistory(false);
                          setPreview(null);
                          setTrusted(false);
                        }
                      })
                    }
                  >
                    {t("invite.review")}
                  </button>
                </>
              ) : preview.kind === "declined" ? (
                <>
                  <p className="invitation-hint">{t("invite.declined")}</p>
                  <button
                    onClick={() =>
                      void perform(async () => {
                        await call({
                          op: "invitation_dismiss",
                          id: preview.id,
                        });
                        setPreview(null);
                        setPage("activity");
                      })
                    }
                  >
                    {t("invite.delivery.dismiss")}
                  </button>
                </>
              ) : (
                <>
                  <PermissionSummary
                    capabilities={preview.capabilities ?? []}
                  />
                  <label className="check">
                    <input
                      type="checkbox"
                      checked={trusted}
                      onChange={(e) => setTrusted(e.target.checked)}
                    />
                    {t("invite.trustChat")}
                  </label>
                  <button
                    disabled={busy || !trusted}
                    onClick={() =>
                      void perform(async () => {
                        await call({
                          op: "invitation_join",
                          link: input,
                          confirmed_reference: preview.id,
                          trusted,
                        });
                        onJoined(preview.stream);
                        onClose();
                      })
                    }
                  >
                    {t("invite.join")}
                  </button>
                </>
              )}
            </>
          ) : page === "activity" || page === "notifications" ? (
            <>
              {!notificationsPage && ownedSpace && (
                <SpaceJoinRequests
                  key={`${view.identity}:${ownedSpace.id}`}
                  identity={view.identity}
                  space={ownedSpace}
                  refresh={requestsRefresh}
                  onView={onView}
                />
              )}
              {(notificationsPage || !ownedSpace) &&
                !incoming.length &&
                !outgoing.length &&
                !received.length &&
                !notices.length && (
                  <EmptyState
                    message={t(
                      notificationsPage
                        ? "notifications.empty"
                        : "invite.activity.empty",
                    )}
                  />
                )}
              {!!notices.length && (
                <ul className="member-list">
                  {notices.map((entry) => (
                    <li key={entry.id}>
                      <button
                        className="member-row"
                        onClick={() => {
                          onJoined(entry.stream);
                          onClose();
                        }}
                      >
                        <Icon name="bell" />
                        <span className="member-copy">
                          <strong>{entry.name}</strong>
                          <small>{t("notifications.removed")}</small>
                        </span>
                        <Icon name="next" />
                      </button>
                    </li>
                  ))}
                </ul>
              )}
              {!!received.length && (
                <>
                  <h3>{t("invite.activity.received")}</h3>
                  <ul className="member-list">
                    {received.map((entry) => (
                      <li key={entry.id} className="received-invitation">
                        <button
                          className="member-row"
                          disabled={busy}
                          onClick={() =>
                            void perform(() => inspect(entry.link))
                          }
                        >
                          <Icon name="person" />
                          <span className="member-copy">
                            <strong>{entry.name}</strong>
                            <small>{t("dm.invitedYou")}</small>
                          </span>
                          <Icon name="next" />
                        </button>
                        <button
                          className="secondary"
                          disabled={busy}
                          onClick={() =>
                            void perform(async () => {
                              await call({
                                op: "invitation_ignore",
                                id: entry.id,
                              });
                              await loadActivity();
                            })
                          }
                        >
                          {t("dm.ignore")}
                        </button>
                      </li>
                    ))}
                  </ul>
                </>
              )}
              {!!incoming.length && (
                <>
                  <h3>{t("invite.activity.incoming")}</h3>
                  <ul className="member-list">
                    {incoming.map((entry) => (
                      <li key={entry.id}>
                        <button
                          className="member-row"
                          disabled={busy}
                          onClick={() =>
                            void perform(async () => {
                              const r = await call({
                                op: "invitation_list",
                                space: entry.space,
                                stream: entry.stream,
                              });
                              const found = r.requests?.find(
                                (item) => item.id === entry.id,
                              );
                              if (found) {
                                onJoined(entry.stream);
                                setSelected(found);
                                setTrusted(false);
                                setPost(found.capabilities.includes("POST"));
                                setHistory(false);
                              }
                            })
                          }
                        >
                          <span className="avatar">
                            {entry.name.slice(0, 2).toUpperCase()}
                          </span>
                          <span className="member-copy">
                            <strong>{entry.name}</strong>
                            <small>
                              {
                                view.streams.find(
                                  (s) => s.stream === entry.stream,
                                )?.name
                              }
                            </small>
                          </span>
                          <Icon name="next" />
                        </button>
                      </li>
                    ))}
                  </ul>
                </>
              )}
              {!!outgoing.length && (
                <>
                  {!notificationsPage && (
                    <h3>{t("invite.activity.outgoing")}</h3>
                  )}
                  <ul className="member-list">
                    {outgoing.map((entry) => (
                      <li key={entry.id}>
                        <button
                          className="member-row"
                          disabled={busy}
                          onClick={() =>
                            void perform(async () => {
                              if (entry.status === "joined") {
                                onJoined(entry.stream);
                                onClose();
                              } else if (entry.link) await inspect(entry.link);
                              else
                                setOutput({
                                  link: entry.request_link,
                                  kind: "request",
                                  name: entry.name,
                                  automatic: entry.status !== "manual",
                                });
                            })
                          }
                        >
                          <Icon
                            name={
                              entry.status === "approved" ? "verified" : "inbox"
                            }
                          />
                          <span className="member-copy">
                            <strong>{entry.name}</strong>
                            <small>
                              {t(`invite.activity.${entry.status}`)}
                            </small>
                          </span>
                          <Icon name="next" />
                        </button>
                      </li>
                    ))}
                  </ul>
                </>
              )}
            </>
          ) : page === "invite" ? (
            <>
              <p className="invitation-hint">
                {t("invite.chooseAccess", { chat: stream?.name ?? "" })}
              </p>
              <Permissions
                post={post}
                history={history}
                onPost={setPost}
                onHistory={setHistory}
              />
              <label className="check">
                <input
                  type="checkbox"
                  checked={reusable}
                  onChange={(e) => setReusable(e.target.checked)}
                />
                {t("invite.reusable")}
              </label>
              <label>
                {t("invite.expires")}
                <select
                  value={lifetime}
                  onChange={(e) => setLifetime(e.target.value)}
                >
                  <option value="1m">{t("invite.oneMinute")}</option>
                  <option value="10m">{t("invite.tenMinutes")}</option>
                  <option value="30m">{t("invite.thirtyMinutes")}</option>
                  <option value="1h">{t("invite.oneHour")}</option>
                  <option value="24h">{t("invite.twentyFourHours")}</option>
                  <option value="100y">{t("invite.hundredYears")}</option>
                </select>
              </label>
              {lifetime === "100y" && (
                <p className="invitation-hint">{t("invite.longLivedHint")}</p>
              )}
              <button
                disabled={busy}
                onClick={() =>
                  void perform(async () => {
                    const r = await call({
                      op: "invitation_create",
                      post,
                      share_history: history,
                      reusable,
                      lifetime,
                    });
                    if (r.link)
                      setOutput({
                        link: r.link,
                        kind: "invitation",
                        name: stream?.name,
                      });
                  })
                }
              >
                {t("invite.create")}
              </button>
            </>
          ) : page === "requests" ? (
            <>
              <p className="invitation-hint">{t("invite.requestsHint")}</p>
              <button
                className="action-link"
                onClick={() => {
                  if (onScan) onScan();
                  else {
                    setInput("");
                    setPage("scan");
                  }
                }}
              >
                {t("invite.scanOrPaste")}
                <Icon name="qr" />
              </button>
              {requests.length ? (
                <ul className="member-list">
                  {requests.map((entry) => (
                    <li key={entry.id}>
                      <button
                        className="member-row"
                        onClick={() => {
                          setSelected(entry);
                          setPost(entry.capabilities.includes("POST"));
                          setHistory(false);
                          setTrusted(false);
                        }}
                      >
                        <span className="avatar">
                          {entry.name.slice(0, 2).toUpperCase()}
                        </span>
                        <span className="member-copy">
                          <strong>{entry.name}</strong>
                          <small>
                            {t(
                              entry.status === "approved"
                                ? "invite.approved"
                                : entry.status === "declined"
                                  ? "invite.declined"
                                  : "invite.pending",
                            )}
                          </small>
                        </span>
                        <Icon name="next" />
                      </button>
                    </li>
                  ))}
                </ul>
              ) : (
                <EmptyState message={t("invite.noRequests")} />
              )}
            </>
          ) : page === "invitations" ? (
            <>
              <p className="invitation-hint">{t("invite.invitationsHint")}</p>
              <button
                onClick={onInvite ?? (() => setPage("invite"))}
                disabled={busy}
              >
                <Icon name="plus" />
                {t("members.invite")}
              </button>
              {!offers.length && (
                <EmptyState message={t("invite.noInvitations")} />
              )}
              {offers.length > 0 && (
                <>
                  {offers.map((offer) => (
                    <div className="invitation-link-row" key={offer.id}>
                      <button
                        className="action-link"
                        onClick={() =>
                          setOutput({
                            link: offer.link,
                            kind: "invitation",
                            name: stream?.name,
                          })
                        }
                      >
                        <span>
                          {t(
                            offer.reusable
                              ? "invite.reusable"
                              : "invite.onePerson",
                          )}
                          <small>
                            {t(
                              !offer.active
                                ? "invite.off"
                                : offer.expires_at <= Date.now()
                                  ? "invite.expired"
                                  : "invite.active",
                            )}
                          </small>
                        </span>
                        <Icon name="qr" />
                      </button>
                      {offer.active && (
                        <button
                          className="quiet danger"
                          disabled={busy}
                          onClick={() => setDisable(offer.id)}
                        >
                          {t("invite.turnOff")}
                        </button>
                      )}
                      {disable === offer.id && (
                        <div className="invitation-confirm">
                          <p>{t("invite.turnOffHint")}</p>
                          <button
                            disabled={busy}
                            onClick={() =>
                              void perform(async () => {
                                await call({
                                  op: "invitation_disable",
                                  id: offer.id,
                                });
                                setDisable(null);
                                await load();
                              })
                            }
                          >
                            {t("invite.turnOff")}
                          </button>
                          <button
                            className="quiet"
                            onClick={() => setDisable(null)}
                          >
                            {t("invite.cancel")}
                          </button>
                        </div>
                      )}
                    </div>
                  ))}
                </>
              )}
            </>
          ) : page === "contact" ? (
            <>
              <p className="invitation-hint">{t("invite.myCodeHint")}</p>
              <label>
                {t("invite.yourName")}
                <input
                  autoComplete="nickname"
                  maxLength={120}
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                />
              </label>
              <button
                disabled={busy || !name.trim()}
                onClick={() =>
                  void perform(async () => {
                    const r = await call({ op: "contact_create", name });
                    if (r.link) setOutput({ link: r.link, kind: "contact" });
                  })
                }
              >
                {t("invite.showCode")}
              </button>
            </>
          ) : (
            <>
              {route.contacts && (
                <p className="invitation-hint">{t("contacts.addHelp")}</p>
              )}
              {mobile && (
                <button disabled={busy} onClick={() => void startScan()}>
                  <Icon name="qr" />
                  {t("invite.scan")}
                </button>
              )}
              <form
                onSubmit={(e) => {
                  e.preventDefault();
                  void perform(() => inspect(input));
                }}
              >
                <label>
                  <span className="invitation-paste-label">
                    {t("invite.paste")}
                  </span>
                  <textarea
                    rows={3}
                    maxLength={2 * 1024 * 1024}
                    value={input}
                    autoCapitalize="none"
                    autoCorrect="off"
                    spellCheck={false}
                    onChange={(e) => setInput(e.target.value)}
                  />
                </label>
                <button disabled={busy || !input.trim()}>
                  {t("invite.continue")}
                </button>
              </form>
            </>
          )}
        </PullToRefresh>
      )}
    </section>
  );
}
function Person({ name, identity }: { name: string; identity: string }) {
  return (
    <div className="invitation-person">
      <span className="avatar">{name.slice(0, 2).toUpperCase()}</span>
      <strong>{name}</strong>
      <code>
        {identity.slice(0, 8)} · {identity.slice(-8)}
      </code>
      <details>
        <summary>{t("members.identifiers")}</summary>
        <code>{identity}</code>
      </details>
    </div>
  );
}
function Permissions({
  post,
  history,
  onPost,
  onHistory,
  allowPost = true,
  allowHistory = true,
}: {
  post: boolean;
  history: boolean;
  onPost: (v: boolean) => void;
  onHistory: (v: boolean) => void;
  allowPost?: boolean;
  allowHistory?: boolean;
}) {
  return (
    <div className="invitation-permissions">
      <label>
        {t("invite.access")}
        <select
          value={post ? "post" : "read"}
          onChange={(e) => onPost(e.target.value === "post")}
        >
          <option value="read">{t("invite.readOnly")}</option>
          {allowPost && <option value="post">{t("invite.readWrite")}</option>}
        </select>
      </label>
      {allowHistory && (
        <label className="check">
          <input
            type="checkbox"
            checked={history}
            onChange={(e) => onHistory(e.target.checked)}
          />
          {t("invite.shareHistory")}
        </label>
      )}
    </div>
  );
}
function PermissionSummary({ capabilities }: { capabilities: string[] }) {
  return (
    <p className="invitation-hint">
      {t(
        capabilities.includes("POST") ? "invite.readWrite" : "invite.readOnly",
      )}
      {capabilities.includes("SHARE_HISTORY")
        ? ` · ${t("invite.shareHistory")}`
        : ""}
    </p>
  );
}
export function InvitationCode({
  link,
  mobile,
  showLink = true,
}: {
  link?: string;
  mobile: boolean;
  showLink?: boolean;
}) {
  const { reportError } = useToast();
  const [frames, setFrames] = useState<string[]>([]);
  const [index, setIndex] = useState(0);
  const [playing, setPlaying] = useState(
    !matchMedia("(prefers-reduced-motion: reduce)").matches,
  );
  const [qrError, setQrError] = useState(false);
  useEffect(() => {
    let active = true;
    setFrames([]);
    setIndex(0);
    setQrError(false);
    if (!link) return;
    void invoke<string[]>("invitation_qr", { link })
      .then((value) => {
        if (active)
          setFrames(
            value.map((svg) => `data:image/svg+xml,${encodeURIComponent(svg)}`),
          );
      })
      .catch(() => {
        if (active) setQrError(true);
      });
    return () => {
      active = false;
    };
  }, [link]);
  useEffect(() => {
    if (!playing || frames.length < 2) return;
    const timer = window.setInterval(
      () => setIndex((value) => (value + 1) % frames.length),
      1100,
    );
    return () => clearInterval(timer);
  }, [playing, frames.length]);
  return (
    <div className="invitation-code">
      {frames.length ? (
        <img src={frames[index]} alt={t("invite.code")} />
      ) : (
        <div
          className="invitation-qr-placeholder"
          role="status"
          aria-label={t(qrError ? "invite.qrUnavailable" : "invite.preparing")}
        >
          {qrError ? (
            <span>{t("invite.qrUnavailable")}</span>
          ) : (
            <span className="invitation-qr-loader" aria-hidden="true" />
          )}
        </div>
      )}
      {frames.length > 1 && (
        <>
          <p>{t("invite.animatedHint")}</p>
          <div className="qr-controls">
            <button
              className="icon"
              aria-label={t("invite.previousPart")}
              onClick={() => {
                setPlaying(false);
                setIndex((index + frames.length - 1) % frames.length);
              }}
            >
              <Icon name="back" />
            </button>
            <span>
              {t("invite.part", { current: index + 1, total: frames.length })}
            </span>
            <button
              className="icon"
              aria-label={t("invite.nextPart")}
              onClick={() => {
                setPlaying(false);
                setIndex((index + 1) % frames.length);
              }}
            >
              <Icon name="next" />
            </button>
            <button className="quiet" onClick={() => setPlaying(!playing)}>
              {t(playing ? "invite.pause" : "invite.play")}
            </button>
          </div>
        </>
      )}
      {mobile && (
        <>
          {!showLink && (
            <p className="invitation-code-alternative">{t("invite.or")}</p>
          )}
          <button
            disabled={!link}
            onClick={(e) => {
              if (!link) return;
              const r = e.currentTarget.getBoundingClientRect();
              void shareText(link, {
                position: { x: r.x + r.width / 2, y: r.bottom },
              }).catch((error) => {
                const message =
                  typeof error === "string" ? error : JSON.stringify(error);
                if (!/share cancel(?:led|ed)/i.test(message))
                  reportError(error);
              });
            }}
          >
            <Icon name="share" />
            {t("invite.shareLink")}
          </button>
        </>
      )}
      {showLink && (
        <>
          <button
            className="quiet"
            disabled={!link}
            onClick={() =>
              link &&
              void navigator.clipboard.writeText(link).catch(reportError)
            }
          >
            {t("invite.copy")}
          </button>
          <details>
            <summary>{t("invite.link")}</summary>
            <textarea
              readOnly
              rows={3}
              value={link}
              aria-label={t("invite.link")}
              onFocus={(e) => e.target.select()}
            />
          </details>
        </>
      )}
    </div>
  );
}
