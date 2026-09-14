import { useEffect, useRef, useState } from "react";
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
import { t, formatTimestamp } from "./i18n";
import type { View, SpaceSummary } from "./model";
import "./spaces.css";

type Offer = {
  id: string;
  link: string;
  expires_at: number;
  require_approval: boolean;
  revoked: boolean;
};
type Management = { offers: Offer[]; requests: { id: string; name: string }[] };
type Reply = {
  view: View;
  preview?: { name: string; require_approval: boolean; expires_at: number };
  result?: Management & { link?: string };
};

function useDemoSpaceId() {
  const [id, setId] = useState<string>();
  useEffect(() => {
    let alive = true;
    void invoke<{ demo_space_id?: string }>("profile_environment")
      .then((environment) => {
        if (alive) setId(environment.demo_space_id);
      })
      .catch(() => {});
    return () => {
      alive = false;
    };
  }, []);
  return id;
}

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
  const [joining, setJoining] = useState(false);
  const demo = useDemoSpaceId();
  const [busy, setBusy] = useState(false);
  const { reportError } = useToast();
  if (joining)
    return (
      <main className="space-setup">
        <Spaces
          view={view}
          mobile={mobile}
          onView={onView}
          initialPage="join"
          onBack={() => setJoining(false)}
        />
      </main>
    );
  return (
    <main className="space-setup">
      <ScreenHeader title={t("spaces.setupTitle")} onBack={onLock} />
      <div className="settings-page space-setup-choices">
        <p className="muted">{t("spaces.setupHelp")}</p>
        {demo && (
          <button
            disabled={busy}
            onClick={async () => {
              setBusy(true);
              try {
                const result = await invoke<Reply>("operate", {
                  request: {
                    op: "space_join_demo",
                    expected_identity: view.identity,
                  },
                });
                onView(result.view);
              } catch (error) {
                reportError(error);
              } finally {
                setBusy(false);
              }
            }}
          >
            {t("spaces.joinDemo")}
          </button>
        )}
        {demo && <p className="space-paste-label muted">{t("spaces.or")}</p>}
        <button
          className="secondary"
          disabled={busy}
          onClick={() => setJoining(true)}
        >
          {t("spaces.company")}
        </button>
        <p className="muted">{t("spaces.companyHelp")}</p>
        <button
          className="quiet"
          disabled={busy}
          onClick={async () => {
            setBusy(true);
            try {
              const result = await invoke<Reply>("operate", {
                request: {
                  op: "space_setup_done",
                  expected_identity: view.identity,
                },
              });
              onView(result.view);
            } catch (error) {
              reportError(error);
            } finally {
              setBusy(false);
            }
          }}
        >
          {t("spaces.later")}
        </button>
      </div>
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
    <div className="current-space">
      <p className="muted">
        {current
          ? t("spaces.inSpace", { name: current.name })
          : t("spaces.noCurrent")}
      </p>
      <button
        type="button"
        className="icon"
        onClick={onManage}
        aria-label={t("spaces.manage")}
      >
        <Icon name="spaceSwitch" />
        {((view.space_requests ?? 0) > 0 ||
          view.spaces?.some((space) => (space.activity ?? 0) > 0)) && (
          <NewIndicator />
        )}
      </button>
    </div>
  );
}

export function Spaces({
  view,
  mobile,
  onView,
  onBack,
  initialPage = "list",
}: {
  view: View;
  mobile: boolean;
  onView: (view: View) => void;
  onBack: () => void;
  initialPage?: "list" | "join";
}) {
  const { reportError, showError } = useToast();
  const demoSpaceId = useDemoSpaceId();
  const [page, setPage] = useState<"list" | "join" | "manage">(initialPage);
  const [selected, setSelected] = useState<SpaceSummary>();
  const [management, setManagement] = useState<Management>();
  const [link, setLink] = useState("");
  const [preview, setPreview] = useState<Reply["preview"]>();
  const [code, setCode] = useState<string>();
  const [disconnect, setDisconnect] = useState<SpaceSummary>();
  const [approval, setApproval] = useState(true);
  const [lifetime, setLifetime] = useState(86400);
  const [busy, setBusy] = useState(false);
  const [switching, setSwitching] = useState<string>();
  const [scanning, setScanning] = useState(false);
  const scanningRef = useRef(false);
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
    setPreview((await call({ op: "space_preview", link: value })).preview);
  };
  const manage = async (space: SpaceSummary) => {
    setSelected(space);
    setManagement(
      (await call({ op: "space_manage", id: space.id, body: {} })).result,
    );
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
  return (
    <section
      className={
        scanning ? "invitation-page invitation-scanner" : "spaces-page"
      }
    >
      <ScreenHeader
        title={
          page === "join"
            ? t("spaces.join")
            : page === "manage"
              ? (selected?.name ?? t("spaces.title"))
              : t("spaces.title")
        }
        onBack={back}
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
        <div className="settings-page">
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
                                  space.status === "pending"
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
                        {space.owner && (
                          <button
                            className="icon"
                            aria-label={t("spaces.shareNamed", {
                              name: space.name,
                            })}
                            disabled={busy}
                            onClick={() => void perform(() => manage(space))}
                          >
                            <Icon name="share" />
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
              {demoSpaceId &&
                !view.spaces?.some((space) => space.id === demoSpaceId) && (
                  <button
                    className="secondary"
                    disabled={busy}
                    onClick={() =>
                      void perform(async () => {
                        await call({ op: "space_join_demo" });
                      })
                    }
                  >
                    {t("spaces.joinDemo")}
                  </button>
                )}
            </>
          )}
          {page === "join" &&
            (preview ? (
              <>
                <h3>{preview.name}</h3>
                <p className="muted">
                  {t(
                    preview.require_approval
                      ? "spaces.joinApproval"
                      : "spaces.joinAutomatic",
                  )}
                </p>
                <button
                  disabled={busy}
                  onClick={() =>
                    void perform(async () => {
                      await call({ op: "space_join", link });
                      setPreview(undefined);
                      setLink("");
                      setPage("list");
                    })
                  }
                >
                  {t("spaces.join")}
                </button>
              </>
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
                  disabled={busy || !link.trim()}
                  onClick={() => void perform(() => inspect(link))}
                >
                  {t("invite.continue")}
                </button>
              </>
            ))}
          {page === "manage" &&
            selected &&
            (code ? (
              <InvitationCode link={code} mobile={mobile} showLink={false} />
            ) : (
              <>
                <section>
                  <h3>{t("spaces.invitation")}</h3>
                  <label htmlFor="space-expiry">{t("spaces.expires")}</label>
                  <select
                    id="space-expiry"
                    value={lifetime}
                    disabled={busy}
                    onChange={(event) =>
                      setLifetime(Number(event.target.value))
                    }
                  >
                    {[60, 600, 1800, 3600, 86400, 3153600000].map((seconds) => (
                      <option value={seconds} key={seconds}>
                        {t(
                          `spaces.lifetime.${seconds}` as "spaces.lifetime.60",
                        )}
                      </option>
                    ))}
                  </select>
                  <label className="check">
                    <input
                      type="checkbox"
                      checked={approval}
                      disabled={busy}
                      onChange={(event) => setApproval(event.target.checked)}
                    />
                    <span>{t("spaces.requireApproval")}</span>
                  </label>
                  <button
                    disabled={busy}
                    onClick={() =>
                      void perform(async () => {
                        const reply = await call({
                          op: "space_invite",
                          id: selected.id,
                          body: { lifetime, require_approval: approval },
                        });
                        setCode(reply.result?.link);
                      })
                    }
                  >
                    {t("spaces.createInvitation")}
                  </button>
                </section>
                {management?.offers
                  .filter(
                    (offer) => !offer.revoked && offer.expires_at > Date.now(),
                  )
                  .map((offer) => (
                    <div className="space-offer" key={offer.id}>
                      <small className="muted">
                        {t("spaces.validUntil", {
                          date: formatTimestamp(
                            new Date(offer.expires_at).toISOString(),
                          ),
                        })}
                      </small>
                      <div className="space-choice">
                        <button
                          className="secondary"
                          disabled={busy}
                          onClick={() => setCode(offer.link)}
                        >
                          {t("spaces.showCode")}
                        </button>
                        <button
                          className="secondary"
                          disabled={busy}
                          onClick={() =>
                            void perform(async () => {
                              await call({
                                op: "space_revoke",
                                id: selected.id,
                                body: { id: offer.id },
                              });
                              await manage(selected);
                            })
                          }
                        >
                          {t("spaces.revoke")}
                        </button>
                      </div>
                    </div>
                  ))}
              </>
            ))}
        </div>
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
