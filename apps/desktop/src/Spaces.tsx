import { lazy, Suspense, useEffect, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import {
  scan,
  cancel,
  checkPermissions,
  requestPermissions,
  Format,
} from "@tauri-apps/plugin-barcode-scanner";
import { ScreenHeader } from "./ScreenHeader";
import { ActionDialog } from "./ActionDialog";
import { InvitationCode } from "./InvitationFlow";
import { Icon, NewIndicator } from "./Icon";
import { useToast } from "./Toast";
import { t, formatInvitationValidity } from "./i18n";
import { pauseBackgroundSync } from "./backgroundSyncPause";
import type { View, SpaceSummary } from "./model";
import "./spaces.css";
import { SpaceCreate } from "./SpaceCreate";
import { ServiceRequests } from "./ServiceRequests";
import { SpaceDetails } from "./SpaceDetails";
import { EmptyState } from "./EmptyState";
import { SpaceMembers, type SpaceManagement } from "./SpaceRoles";

const LicenseSettings = lazy(() => import("./LicenseSettings"));

type Offer = {
  id: string;
  link: string;
  issued_at?: number;
  expires_at: number;
  require_approval: boolean;
  revoked: boolean;
};
type Management = SpaceManagement & {
  offers: Offer[];
  requests: { id: string; name: string }[];
};
type Reply = {
  view: View;
  preview?: {
    name: string;
    require_approval: boolean;
    expires_at: number;
    message_lifetime_seconds: number;
  };
  result?: Management & { link?: string };
};

export function SpaceSetup({
  view,
  mobile,
  onView,
  onLock,
}: {
  view: View;
  mobile: boolean;
  onView: (view: View) => void;
  onLock: () => void;
}) {
  const [page, setPage] = useState<"choices" | "create" | "join" | "legal">(
    view.space_creation ? "create" : "choices",
  );
  const [busy, setBusy] = useState(false);
  const refreshing = useRef(false);
  const identityRef = useRef(view.identity);
  const onViewRef = useRef(onView);
  identityRef.current = view.identity;
  onViewRef.current = onView;
  useEffect(() => {
    identityRef.current = view.identity;
    return () => {
      identityRef.current = "";
    };
  }, [view.identity]);
  const { reportError } = useToast();
  const refresh = async () => {
    if (refreshing.current) return;
    refreshing.current = true;
    const identity = view.identity;
    setBusy(true);
    try {
      const reply = await invoke<Reply>("operate", {
        request: { op: "space_refresh", expected_identity: view.identity },
      });
      if (identityRef.current === identity) onViewRef.current(reply.view);
    } catch (error) {
      if (identityRef.current === identity) reportError(error);
    } finally {
      refreshing.current = false;
      if (identityRef.current === identity) setBusy(false);
    }
  };
  const hasPending = !!view.spaces?.some(
    (space) => space.status === "checking" || space.status === "pending",
  );
  useEffect(() => {
    if (!hasPending || page !== "choices") return;
    const timer = window.setInterval(() => {
      if (!document.hidden) void refresh();
    }, 15000);
    return () => window.clearInterval(timer);
  }, [view.identity, hasPending, page]);
  return (
    <main className="space-setup">
      {page === "legal" ? (
        <Suspense
          fallback={
            <ScreenHeader
              title={t("legal.title")}
              onBack={() => setPage("choices")}
            />
          }
        >
          <LicenseSettings
            onBack={() => setPage("choices")}
            backLabel={t("onboarding.back")}
            serviceRequests={<ServiceRequests view={view} mobile={mobile} />}
          />
        </Suspense>
      ) : page === "create" ? (
        <SpaceCreate
          view={view}
          mobile={mobile}
          onView={onView}
          onBack={() => setPage("choices")}
        />
      ) : page === "join" ? (
        <Spaces
          view={view}
          mobile={mobile}
          onView={onView}
          initialPage="join"
          onBack={() => setPage("choices")}
        />
      ) : (
        <>
          <ScreenHeader
            title={t("spaces.setupTitle")}
            onBack={onLock}
            actions={
              <button
                type="button"
                className="ghost space-setup-legal-link"
                onClick={() => setPage("legal")}
              >
                {t("legal.title")}
              </button>
            }
          />
          <div className="settings-page space-setup-choices">
            <p className="page-description">{t("spaces.setupHelp")}</p>
            <button onClick={() => setPage("create")}>
              {t(view.space_creation ? "spaces.resume" : "spaces.create")}
            </button>
            <p className="space-paste-label muted">{t("spaces.or")}</p>
            <button className="secondary" onClick={() => setPage("join")}>
              {t("spaces.join")}
            </button>
            {(view.spaces ?? [])
              .filter((space) => space.status !== "joined")
              .map((space) => (
                <div className="space-row" key={space.id}>
                  <strong>{space.name}</strong>
                  <p className="muted">
                    {t(
                      space.status === "checking"
                        ? "spaces.checking"
                        : space.status === "pending"
                          ? "spaces.pending"
                          : "spaces.declined",
                    )}
                  </p>
                </div>
              ))}
            {!!view.spaces?.length && (
              <button
                className="secondary"
                disabled={busy}
                aria-busy={busy}
                onClick={() => void refresh()}
              >
                {t("spaces.refresh")}
              </button>
            )}
          </div>
        </>
      )}
    </main>
  );
}
export function CurrentSpace({
  view,
  onManage,
}: {
  view: View;
  onManage: () => void;
}) {
  const current = view.spaces?.find(
    (space) => space.id === view.active_space && space.status === "joined",
  );
  return (
    <button
      type="button"
      className="current-space"
      onClick={onManage}
      aria-label={t("spaces.manage")}
    >
      <span className="current-space-label">
        {current
          ? t("spaces.inSpace", { name: current.name })
          : t("spaces.noCurrent")}
      </span>
      <span className="icon" aria-hidden="true">
        <Icon name="spaceSwitch" />
        {((view.space_requests ?? 0) > 0 ||
          view.spaces?.some((space) => (space.activity ?? 0) > 0)) && (
          <NewIndicator />
        )}
      </span>
    </button>
  );
}

export function Spaces({
  view,
  mobile,
  hideAvatars = false,
  onView,
  onBack,
  initialPage = "list",
}: {
  view: View;
  mobile: boolean;
  hideAvatars?: boolean;
  onView: (view: View) => void;
  onBack: () => void;
  initialPage?: "list" | "join";
}) {
  const { reportError, showError } = useToast();
  const [page, setPage] = useState<"list" | "join" | "manage" | "create">(
    initialPage,
  );
  const [selected, setSelected] = useState<SpaceSummary>();
  const [management, setManagement] = useState<Management>();
  const [managementTab, setManagementTab] = useState<
    "details" | "invitations" | "members"
  >("details");
  const [link, setLink] = useState("");
  const [preview, setPreview] = useState<Reply["preview"]>();
  const [joinNote, setJoinNote] = useState("");
  const [code, setCode] = useState<string>();
  const [disconnect, setDisconnect] = useState<SpaceSummary>();
  const [creatingInvitation, setCreatingInvitation] = useState(false);
  const [revokingInvitation, setRevokingInvitation] = useState<Offer>();
  const [approval, setApproval] = useState(true);
  const [lifetime, setLifetime] = useState(86400);
  const [busy, setBusy] = useState(false);
  const [switching, setSwitching] = useState<string>();
  const [scanning, setScanning] = useState(false);
  useEffect(() => {
    setRevokingInvitation(undefined);
  }, [page, selected?.id]);
  useEffect(() => {
    if (
      page === "manage" &&
      selected &&
      !view.spaces?.find((space) => space.id === selected.id)?.owner
    )
      setPage("list");
  }, [view.spaces, page, selected]);
  const scanningRef = useRef(false);
  useEffect(() => {
    if (page === "join" || page === "create") return pauseBackgroundSync();
  }, [page]);
  const stopScan = () => {
    scanningRef.current = false;
    setScanning(false);
    document.documentElement.classList.remove("elo-scanning");
    void cancel().catch(() => {});
  };
  useEffect(
    () => () => {
      scanningRef.current = false;
      document.documentElement.classList.remove("elo-scanning");
      if (mobile) void cancel().catch(() => {});
    },
    [mobile],
  );
  const call = async (request: Record<string, unknown>) => {
    const reply = await invoke<Reply>("operate", {
      request: { ...request, expected_identity: view.identity },
    });
    onView(reply.view);
    return reply;
  };
  const perform = async (action: () => Promise<void>) => {
    if (busy) return;
    setBusy(true);
    try {
      await action();
    } catch (error) {
      reportError(error);
    } finally {
      setSwitching(undefined);
      setBusy(false);
    }
  };
  const inspect = async (value: string) => {
    setLink(value);
    setJoinNote("");
    setPreview((await call({ op: "space_preview", link: value })).preview);
  };
  const manage = async (space: SpaceSummary) => {
    setSelected(space);
    setManagement(
      (await call({ op: "space_manage", id: space.id, body: {} })).result,
    );
    setPage("manage");
  };
  const share = async (space: SpaceSummary) => {
    const result = (await call({
      op: "space_manage",
      id: space.id,
      body: {},
    })).result;
    const newest = result?.offers
      .filter((offer) => !offer.revoked && offer.expires_at > Date.now())
      .sort(
        (a, b) =>
          (b.issued_at ?? 0) - (a.issued_at ?? 0) ||
          b.expires_at - a.expires_at,
      )[0];
    setSelected(space);
    setManagement(result);
    setManagementTab("invitations");
    setCode(newest?.link);
    setPage("manage");
  };
  const startScan = async () => {
    if (scanningRef.current) return;
    try {
      if (
        (await checkPermissions()) !== "granted" &&
        (await requestPermissions()) !== "granted"
      ) {
        showError(t("invite.cameraDenied"));
        return;
      }
      scanningRef.current = true;
      setScanning(true);
      document.documentElement.classList.add("elo-scanning");
      const result = await scan({ formats: [Format.QRCode], windowed: true });
      if (!scanningRef.current) return;
      stopScan();
      if (!result.content.trim().startsWith("elo://space/v1#")) {
        showError(t("spaces.invalidCode"));
        return;
      }
      await perform(() => inspect(result.content));
    } catch (error) {
      if (scanningRef.current) reportError(error);
      stopScan();
    }
  };
  const back = () => {
    if (scanning) stopScan();
    else if (code) setCode(undefined);
    else if (preview) setPreview(undefined);
    else if (page === "join" && initialPage === "join") onBack();
    else if (page !== "list") setPage("list");
    else onBack();
  };
  if (page === "create")
    return (
      <SpaceCreate
        view={view}
        mobile={mobile}
        onView={onView}
        onBack={() => setPage("list")}
      />
    );
  return (
    <section
      className={
        scanning ? "invitation-page invitation-scanner" : "spaces-page"
      }
    >
      <ScreenHeader
        desktopRoot={page === "list" && !scanning && !code && !preview}
        title={
          page === "join"
            ? t("spaces.join")
            : page === "manage"
              ? (selected?.name ?? t("spaces.title"))
              : t("spaces.title")
        }
        onBack={back}
        actions={
          page === "manage" && managementTab === "invitations" && !code ? (
            <button
              type="button"
              className="icon"
              disabled={busy}
              aria-label={t("spaces.createInvitation")}
              onClick={() => setCreatingInvitation(true)}
            >
              <Icon name="plus" />
            </button>
          ) : undefined
        }
      />
      {scanning ? (
        <>
          <div className="scan-window" aria-label={t("invite.camera")}>
            <span />
          </div>
          <div className="scan-controls">
            <p>{t("spaces.scanHint")}</p>
            <button onClick={stopScan}>{t("invite.cancel")}</button>
          </div>
        </>
      ) : (
        <div
          className={`settings-page${page === "manage" && !code ? " space-management-page" : ""}`}
        >
          {page === "list" && (
            <>
              <div>
                <p className="page-description">{t("spaces.help")}</p>
                <div className="space-list">
                  {(view.spaces ?? []).map((space) => (
                    <div
                      className="space-row"
                      key={space.id}
                      aria-current={
                        space.id === view.active_space ? "true" : undefined
                      }
                    >
                      <div className="space-row-header">
                        <span className="space-symbol" aria-hidden="true">
                          <Icon name="spaces" />
                          {space.requests > 0 && <NewIndicator />}
                        </span>
                        <div className="space-row-name">
                          <span>
                            {space.activity
                              ? t("spaces.withActivity", {
                                  name: space.name,
                                  count: space.activity,
                                })
                              : space.name}
                          </span>
                          {space.id === view.active_space ? (
                            <small className="muted">
                              {t("spaces.current")}
                            </small>
                          ) : (
                            space.status !== "joined" && (
                              <small className="muted">
                                {t(
                                  space.status === "checking"
                                    ? "spaces.checking"
                                    : space.status === "pending"
                                      ? "spaces.pending"
                                      : "spaces.declined",
                                )}
                              </small>
                            )
                          )}
                          {space.requests > 0 && (
                            <small className="muted">
                              {t("spaces.joinRequests", {
                                count: space.requests,
                              })}
                            </small>
                          )}
                        </div>
                        {space.owner && space.status === "joined" && (
                          <button
                            type="button"
                            className="icon"
                            aria-label={t("spaces.shareNamed", {
                              name: space.name,
                            })}
                            title={t("spaces.shareNamed", { name: space.name })}
                            disabled={busy}
                            onClick={() => void perform(() => share(space))}
                          >
                            <Icon name="share" />
                          </button>
                        )}
                        {space.owner && (
                          <button
                            className="icon"
                            aria-label={t("spaces.settingsNamed", {
                              name: space.name,
                            })}
                            disabled={busy}
                            onClick={() => {
                              setManagementTab("details");
                              void perform(() => manage(space));
                            }}
                          >
                            <Icon name="settings" />
                          </button>
                        )}
                        <button
                          className="icon"
                          aria-label={t("spaces.disconnectNamed", {
                            name: space.name,
                          })}
                          disabled={busy}
                          onClick={() => setDisconnect(space)}
                        >
                          <Icon name="close" />
                        </button>
                      </div>
                      {space.status === "joined" &&
                        space.id !== view.active_space && (
                          <button
                            className="secondary space-switch"
                            disabled={busy}
                            aria-busy={switching === space.id}
                            aria-label={t("spaces.switchNamed", {
                              name: space.name,
                            })}
                            onClick={() =>
                              void perform(async () => {
                                setSwitching(space.id);
                                await call({
                                  op: "space_select",
                                  id: space.id,
                                });
                                onBack();
                              })
                            }
                          >
                            {switching === space.id && (
                              <span
                                className="invitation-qr-loader space-switch-loader"
                                aria-hidden="true"
                              />
                            )}
                            <span className="space-switch-label">
                              {t("spaces.switch")}
                            </span>
                          </button>
                        )}
                    </div>
                  ))}
                </div>
              </div>
              <button disabled={busy} onClick={() => setPage("join")}>
                {t("spaces.join")}
              </button>
              <button
                className="secondary"
                disabled={busy}
                onClick={() => setPage("create")}
              >
                {t(view.space_creation ? "spaces.resume" : "spaces.create")}
              </button>
            </>
          )}
          {page === "join" &&
            (preview ? (
              <div className="space-join-preview">
                <h2>{preview.name}</h2>
                <p className="muted">
                  {t(
                    preview.require_approval
                      ? "spaces.joinApproval"
                      : "spaces.joinAutomatic",
                  )}
                </p>
                <p className="caption muted">
                  {t("spaces.messageLifetime.joinHelp", {
                    lifetime: t(
                      `spaces.messageLifetime.${preview.message_lifetime_seconds}` as "spaces.messageLifetime.21600",
                    ),
                  })}
                </p>
                {
                  <div className="space-join-note">
                    <label htmlFor="space-join-note">
                      {t("spaces.joinNote")}
                    </label>
                    <textarea
                      id="space-join-note"
                      rows={3}
                      maxLength={500}
                      value={joinNote}
                      disabled={busy}
                      onChange={(event) => setJoinNote(event.target.value)}
                      aria-describedby="space-join-note-help"
                    />
                    <p id="space-join-note-help" className="caption muted">
                      {t("spaces.joinNoteHelp")}
                    </p>
                  </div>
                }
                <button
                  className="space-switch"
                  disabled={busy}
                  aria-busy={busy}
                  onClick={() =>
                    void perform(async () => {
                      await call({
                        op: "space_join",
                        link,
                        note: joinNote.trim(),
                      });
                      setPreview(undefined);
                      setLink("");
                      if (initialPage === "join") onBack();
                      else setPage("list");
                    })
                  }
                >
                  {busy && (
                    <span
                      className="invitation-qr-loader space-switch-loader"
                      aria-hidden="true"
                    />
                  )}
                  <span className="space-switch-label">
                    {t(busy ? "spaces.joining" : "spaces.joinAction")}
                  </span>
                </button>
              </div>
            ) : (
              <>
                <p className="muted">{t("spaces.joinHelp")}</p>
                {mobile && (
                  <button
                    className="space-scan"
                    disabled={busy}
                    onClick={() => void startScan()}
                  >
                    <Icon name="qr" />
                    {t("invite.scan")}
                  </button>
                )}
                <label className="space-paste-label" htmlFor="space-link">
                  {t("spaces.paste")}
                </label>
                <textarea
                  id="space-link"
                  rows={4}
                  value={link}
                  spellCheck={false}
                  autoCapitalize="none"
                  autoCorrect="off"
                  onChange={(event) => setLink(event.target.value)}
                />
                <button
                  className="space-switch"
                  disabled={busy || !link.trim()}
                  aria-busy={busy}
                  onClick={() => void perform(() => inspect(link))}
                >
                  {busy && (
                    <span
                      className="invitation-qr-loader space-switch-loader"
                      aria-hidden="true"
                    />
                  )}
                  <span className="space-switch-label">
                    {t(busy ? "spaces.checkingInvitation" : "invite.continue")}
                  </span>
                </button>
              </>
            ))}
          {page === "manage" &&
            selected &&
            (code ? (
              <InvitationCode link={code} mobile={mobile} showLink={!mobile} />
            ) : (
              <>
                <div
                  className="space-management-tabs appearance"
                  role="group"
                  aria-label={t("spaces.settingsNamed", {
                    name: selected.name,
                  })}
                >
                  {(["details", "invitations", "members"] as const).map(
                    (tab) => (
                      <button
                        key={tab}
                        type="button"
                        aria-pressed={managementTab === tab}
                        onClick={() => setManagementTab(tab)}
                      >
                        {t(
                          tab === "details"
                            ? "spaces.manageDetails"
                            : tab === "invitations"
                              ? "spaces.manageInvitations"
                              : "spaces.manageMembers",
                        )}
                      </button>
                    ),
                  )}
                </div>
                <div className="space-management-viewport">
                  <div
                    className={`space-management-content${managementTab === "members" ? " space-management-list" : ""}`}
                  >
                    {managementTab === "details" && management && (
                      <SpaceDetails
                        key={`${view.identity}:${selected.id}`}
                        identity={view.identity}
                        space={selected}
                        management={management}
                        onChanged={() => manage(selected)}
                        onView={onView}
                      />
                    )}
                    {managementTab === "members" && management && (
                      <SpaceMembers
                        key={`${view.identity}:${selected.id}`}
                        identity={view.identity}
                        space={selected}
                        management={management}
                        hideAvatars={hideAvatars}
                        onChanged={() => manage(selected)}
                        onView={onView}
                      />
                    )}
                    {managementTab === "invitations" && (
                      <>
                        <ul
                          className="space-offers"
                          aria-label={t("spaces.manageInvitations")}
                        >
                          {management?.offers
                            .filter(
                              (offer) =>
                                !offer.revoked && offer.expires_at > Date.now(),
                            )
                            .map((offer) => (
                              <li className="space-offer" key={offer.id}>
                                <div className="space-offer-copy">
                                  <span className="space-offer-validity">
                                    {formatInvitationValidity(offer.expires_at)}
                                  </span>
                                  <small className="muted">
                                    {t(
                                      offer.require_approval
                                        ? "spaces.approvalRequired"
                                        : "spaces.joinAutomatic",
                                    )}
                                  </small>
                                </div>
                                <button
                                  type="button"
                                  className="secondary space-square-action"
                                  disabled={busy}
                                  aria-label={t("spaces.showCode")}
                                  onClick={() => setCode(offer.link)}
                                >
                                  <Icon name="qr" />
                                </button>
                                <button
                                  type="button"
                                  className="secondary space-square-action danger"
                                  disabled={busy}
                                  aria-label={t("spaces.revoke")}
                                  onClick={() => setRevokingInvitation(offer)}
                                >
                                  <Icon name="close" />
                                </button>
                              </li>
                            ))}
                        </ul>
                        {!management?.offers.some(
                          (offer) =>
                            !offer.revoked && offer.expires_at > Date.now(),
                        ) && <EmptyState message={t("spaces.noInvitations")} />}
                      </>
                    )}
                  </div>
                </div>
              </>
            ))}
        </div>
      )}
      {creatingInvitation && selected && (
        <ActionDialog
          page
          title={t("spaces.createInvitation")}
          className="space-invitation-dialog"
          onClose={() => {
            if (!busy) setCreatingInvitation(false);
          }}
        >
          <form
            onSubmit={(event) => {
              event.preventDefault();
              void perform(async () => {
                const reply = await call({
                  op: "space_invite",
                  id: selected.id,
                  body: { lifetime, require_approval: approval },
                });
                setCreatingInvitation(false);
                setCode(reply.result?.link);
                await manage(selected);
              });
            }}
          >
            <div className="space-form-field">
              <label htmlFor="space-expiry">{t("spaces.expires")}</label>
              <select
                id="space-expiry"
                value={lifetime}
                disabled={busy}
                onChange={(event) => setLifetime(Number(event.target.value))}
              >
                {[60, 600, 1800, 3600, 86400, 3153600000].map((seconds) => (
                  <option value={seconds} key={seconds}>
                    {t(`spaces.lifetime.${seconds}` as "spaces.lifetime.60")}
                  </option>
                ))}
              </select>
            </div>
            <label className="check">
              <input
                type="checkbox"
                checked={approval}
                disabled={busy}
                onChange={(event) => setApproval(event.target.checked)}
              />
              <span>{t("spaces.requireApproval")}</span>
            </label>
            <button type="submit" disabled={busy} aria-busy={busy}>
              {t("spaces.createInvitation")}
            </button>
          </form>
        </ActionDialog>
      )}
      {revokingInvitation && selected && page === "manage" && (
        <ActionDialog
          title={t("spaces.revokeTitle")}
          className="space-revoke-dialog"
          onClose={() => {
            if (!busy) setRevokingInvitation(undefined);
          }}
        >
          <p className="muted">{t("spaces.revokeHelp")}</p>
          <div className="space-choice">
            <button
              type="button"
              className="secondary"
              disabled={busy}
              onClick={() => setRevokingInvitation(undefined)}
            >
              {t("dialog.cancel")}
            </button>
            <button
              type="button"
              className="danger"
              disabled={busy}
              aria-busy={busy}
              onClick={() =>
                void perform(async () => {
                  await call({
                    op: "space_revoke",
                    id: selected.id,
                    body: { id: revokingInvitation.id },
                  });
                  setRevokingInvitation(undefined);
                  await manage(selected);
                })
              }
            >
              {t("spaces.revoke")}
            </button>
          </div>
        </ActionDialog>
      )}
      {disconnect && (
        <ActionDialog
          title={t("spaces.disconnectTitle", { name: disconnect.name })}
          onClose={() => {
            if (!busy) setDisconnect(undefined);
          }}
        >
          <p className="muted">{t("spaces.disconnectHelp")}</p>
          <div className="space-choice">
            <button
              className="secondary"
              disabled={busy}
              onClick={() => setDisconnect(undefined)}
            >
              {t("invite.cancel")}
            </button>
            <button
              disabled={busy}
              onClick={() =>
                void perform(async () => {
                  await call({
                    op: "space_disconnect",
                    id: disconnect.id,
                    confirmed: true,
                  });
                  setDisconnect(undefined);
                })
              }
            >
              {t("spaces.disconnect")}
            </button>
          </div>
        </ActionDialog>
      )}
    </section>
  );
}
