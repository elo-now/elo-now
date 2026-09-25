import { ActionDialog } from "./ActionDialog";
import { ScreenHeader } from "./ScreenHeader";
import { ControlRecovery } from "./ControlRecovery";
import { LinkedDevices } from "./LinkedDevices";
import { cancelProfileReminders } from "./reminders";
import { PasswordInput } from "./PasswordInput";
import { useEffect, useRef, useState } from "react";
import { shareText } from "@choochmeque/tauri-plugin-sharekit-api";
import { invoke } from "@tauri-apps/api/core";
import { t } from "./i18n";
import { Icon } from "./Icon";
import { useToast } from "./Toast";
import { disableBiometricUnlock } from "./biometric";
import { profileTask, RecoveryQr } from "./ProfileRecovery";
import { RecoveryCodePanel } from "./RecoveryCodePanel";
import { parseRecoveryCode, recoveryCode } from "./recoveryCode";
import { pauseBackgroundSync } from "./backgroundSyncPause";

type Request = { id: string; name: string };
type AcceptedDevice = {
  id: string;
  credential: string;
  current: boolean;
  name: string;
};
export function DevicesSettings({ onBack }: { onBack: () => void }) {
  const [screen, setScreen] = useState<"list" | "qr" | "done">("list");
  const [svg, setSvg] = useState("");
  const [busy, setBusy] = useState(false);
  const [preparing, setPreparing] = useState(false);
  const startRevision = useRef(0);
  const [requests, setRequests] = useState<Request[]>([]);
  const [accepted, setAccepted] = useState<AcceptedDevice | null>(null);
  const [removing, setRemoving] = useState<Request | null>(null);
  const [accepting, setAccepting] = useState<Request | null>(null);
  const [expires, setExpires] = useState<number | null>(null);
  const [clock, setClock] = useState(Date.now);
  const [pollFailed, setPollFailed] = useState(false);
  const [canLink, setCanLink] = useState(true);
  const remaining = Math.max(0, Math.ceil(((expires ?? clock) - clock) / 1000));
  const expired = expires !== null && remaining === 0;
  const time = `${Math.floor(remaining / 60)
    .toString()
    .padStart(2, "0")}:${(remaining % 60).toString().padStart(2, "0")}`;
  const { reportError } = useToast();
  const perform = async (work: () => Promise<void>) => {
    if (busy) return;
    setBusy(true);
    try {
      await work();
    } catch (error) {
      reportError(error);
    } finally {
      setBusy(false);
    }
  };
  const start = async () => {
    const revision = ++startRevision.current;
    setPreparing(true);
    setSvg("");
    setExpires(null);
    setRequests([]);
    setAccepted(null);
    setPollFailed(false);
    setScreen("qr");
    try {
      const result = await profileTask<{ svg: string; expires: number }>(
        "pair_start",
      );
      if (revision !== startRevision.current) return;
      setSvg(result.svg);
      setExpires(result.expires);
      setClock(Date.now());
    } catch (error) {
      if (revision !== startRevision.current) return;
      setScreen("list");
      throw error;
    } finally {
      if (revision === startRevision.current) setPreparing(false);
    }
  };
  const close = async () => {
    ++startRevision.current;
    setPreparing(false);
    setSvg("");
    setExpires(null);
    setRequests([]);
    setPollFailed(false);
    setScreen("list");
    await profileTask("cancel");
  };
  useEffect(() => {
    if (preparing) return pauseBackgroundSync();
  }, [preparing]);
  useEffect(
    () => () => {
      ++startRevision.current;
      void profileTask("cancel").catch(() => {});
    },
    [],
  );
  useEffect(() => {
    if (!svg || accepted || expired) return;
    const timer = setInterval(() => setClock(Date.now()), 1000);
    return () => clearInterval(timer);
  }, [svg, accepted, expired]);
  useEffect(() => {
    if (!svg || accepted || expired || busy) return;
    let live = true;
    let timer: ReturnType<typeof setTimeout>;
    const poll = async () => {
      try {
        const result = await profileTask<{ requests: Request[] }>("pair_poll");
        if (live) {
          setRequests(result.requests);
          if (result.requests.length > 0) setScreen("list");
          setPollFailed(false);
        }
      } catch (error) {
        if (live) {
          reportError(error);
          setPollFailed(true);
        }
        return;
      }
      if (live) timer = setTimeout(() => void poll(), 3000);
    };
    timer = setTimeout(() => void poll(), 1000);
    return () => {
      live = false;
      clearTimeout(timer);
    };
  }, [svg, accepted, expired, busy]);
  return (
    <>
      <ScreenHeader
        title={t(screen === "qr" ? "devices.link" : "devices.title")}
        desktopRoot={screen === "list"}
        onBack={
          screen === "list" ? onBack : () => void close().catch(reportError)
        }
        backLabel={t(screen === "list" ? "settings.back" : "devices.back")}
        actions={
          screen === "list" && canLink && requests.length === 0 ? (
            <button
              type="button"
              className="icon device-link-action"
              aria-label={t("devices.link")}
              disabled={busy}
              onClick={() => (svg ? setScreen("qr") : void perform(start))}
            >
              <Icon name="plus" />
            </button>
          ) : undefined
        }
      />
      <div
        className="settings-page recovery-page devices-page"
        data-device-screen={screen}
      >
        {screen === "list" && (
          <>
            <LinkedDevices
              extraDevice={accepted}
              onDeleted={() => setAccepted(null)}
              onCanLink={setCanLink}
            />
            {requests
              .filter((request) => !accepted)
              .map((request) => (
                <div className="linked-device-row" key={request.id}>
                  <span>
                    {request.name}
                    <small className={expired ? "error" : undefined}>
                      {t(expired ? "devices.expired" : "devices.pending")}
                    </small>
                  </span>
                  <div className="linked-device-actions">
                    <button
                      type="button"
                      className="icon"
                      aria-label={t("devices.accept")}
                      title={t("devices.accept")}
                      disabled={busy || expired}
                      onClick={() => setAccepting(request)}
                    >
                      <Icon name="check" />
                    </button>
                    <button
                      type="button"
                      className="icon"
                      aria-label={t("devices.delete")}
                      title={t("devices.delete")}
                      disabled={busy}
                      onClick={() => setRemoving(request)}
                    >
                      <Icon name="delete" />
                    </button>
                  </div>
                </div>
              ))}
          </>
        )}
        {screen === "done" && (
          <>
            <p className="device-link-help" role="status">
              {t("devices.sent")}
            </p>
            <button disabled={busy} onClick={() => void perform(close)}>
              {t("devices.done")}
            </button>
          </>
        )}
        {screen === "qr" &&
          (preparing ? (
            <p className="page-description device-list-loading" role="status">
              {t("devices.preparing")}
            </p>
          ) : svg && (expired || pollFailed) ? (
            <>
              <p className="error device-link-help" role="status">
                {t(expired ? "devices.expired" : "devices.requestFailed")}
              </p>
              <button disabled={busy} onClick={() => void perform(start)}>
                {t("devices.newCode")}
              </button>
            </>
          ) : svg ? (
            <>
              <p className="device-link-help">{t("devices.codeHelp")}</p>
              <div
                className="private-qr"
                role="img"
                aria-label={t("devices.qrLabel")}
                dangerouslySetInnerHTML={{ __html: svg }}
              />
              <p
                className="muted device-link-waiting"
                role="timer"
                aria-live="off"
              >
                {t("devices.noRequests", { time })}
              </p>
              <button
                className="secondary"
                disabled={busy}
                onClick={() => void perform(close)}
              >
                {t("dialog.cancel")}
              </button>
            </>
          ) : null)}
        {accepting && (
          <ActionDialog
            title={t("devices.acceptTitle")}
            onClose={() => !busy && setAccepting(null)}
          >
            <p>{t("devices.acceptHelp", { name: accepting.name })}</p>
            {expired && <p className="error">{t("devices.expired")}</p>}
            <div className="space-choice">
              <button
                className="secondary"
                disabled={busy}
                onClick={() => setAccepting(null)}
              >
                {t("dialog.cancel")}
              </button>
              <button
                disabled={busy || expired}
                onClick={() =>
                  void perform(async () => {
                    await profileTask("pair_approve", { id: accepting.id });
                    const result = await profileTask<{
                      credential: string;
                      device_id: string;
                    }>("pair_poll");
                    setAccepted({
                      id: result.device_id,
                      credential: result.credential,
                      name: accepting.name,
                      current: false,
                    });
                    setAccepting(null);
                    setRequests([]);
                    setSvg("");
                    setExpires(null);
                    setScreen("done");
                  })
                }
              >
                {t(busy ? "sync.busy" : "devices.accept")}
              </button>
            </div>
          </ActionDialog>
        )}
        {removing && (
          <ActionDialog
            title={t("devices.deleteRequestTitle")}
            onClose={() => !busy && setRemoving(null)}
          >
            <p>{t("devices.deleteRequestHelp", { name: removing.name })}</p>
            <div className="space-choice">
              <button
                className="secondary"
                disabled={busy}
                onClick={() => setRemoving(null)}
              >
                {t("dialog.cancel")}
              </button>
              <button
                className="danger"
                disabled={busy}
                onClick={() =>
                  void perform(async () => {
                    await profileTask("pair_reject", { id: removing.id });
                    setRemoving(null);
                    setRequests([]);
                    setSvg("");
                    setExpires(null);
                  })
                }
              >
                {t("devices.delete")}
              </button>
            </div>
          </ActionDialog>
        )}
      </div>
    </>
  );
}

export function RecoverySettings({
  onBack,
  mobile,
  identity,
  demoProfile,
}: {
  onBack: () => void;
  mobile: boolean;
  identity: string;
  demoProfile?: string;
}) {
  const [controlRecovery, setControlRecovery] = useState(false);
  const [menuAnchor, setMenuAnchor] = useState<DOMRect | null>(null);
  const [material, setMaterial] = useState(""),
    [busy, setBusy] = useState(false),
    [saved, setSaved] = useState(false),
    [omitted, setOmitted] = useState(0);
  const [removing, setRemoving] = useState(false),
    [password, setPassword] = useState(""),
    [confirmed, setConfirmed] = useState(false);
  const { reportError, onInvalid } = useToast();
  const verify = async () => {
    const parsed = parseRecoveryCode(material);
    if (material.includes("|") && !parsed) throw t("recover.error.words");
    if (parsed && parsed.identity_id !== identity)
      throw t("recover.error.identity");
    const card = await profileTask<{ identity_id: string; phrase: string }>(
      "recovery_material",
      {
        words: parsed?.phrase ?? material.replaceAll(",", " "),
      },
    );
    setMaterial(recoveryCode(card));
    return card;
  };
  const prepare = async () => {
    setBusy(true);
    try {
      return await verify();
    } finally {
      setBusy(false);
    }
  };
  const perform = async (work: () => Promise<void>) => {
    setBusy(true);
    try {
      await work();
    } catch (e) {
      if (!/cancel/i.test(String(e))) reportError(e);
    } finally {
      setBusy(false);
    }
  };
  useEffect(
    () => () => {
      void profileTask("cancel").catch(() => {});
    },
    [],
  );
  const cancelRemoval = () => {
    setRemoving(false);
    setPassword("");
    setMaterial("");
    setConfirmed(false);
  };
  if (controlRecovery)
    return (
      <ControlRecovery
        mobile={mobile}
        onClose={() => setControlRecovery(false)}
      />
    );
  return (
    <>
      <ScreenHeader
        title={t(removing ? "recover.removeDevice" : "recover.settingsTitle")}
        desktopRoot={!removing}
        onBack={busy ? undefined : removing ? cancelRemoval : onBack}
        actions={
          !removing &&
          !demoProfile && (
            <button
              type="button"
              className="icon"
              aria-label={t("nav.more")}
              aria-haspopup="menu"
              aria-expanded={!!menuAnchor}
              disabled={busy}
              onClick={(event) =>
                setMenuAnchor(event.currentTarget.getBoundingClientRect())
              }
            >
              <Icon name="more" />
            </button>
          )
        }
      />
      <div className="settings-page recovery-page">
        {!removing ? (
          <>
            <h3>{t("recover.qrTitle")}</h3>
            <p className="page-description">{t("recover.settingsHelp")}</p>
            <p className="page-description">{t("recover.settingsCodeHelp")}</p>
            <RecoveryCodePanel
              value={material}
              onChange={(value) => {
                setMaterial(value);
                setSaved(false);
                setOmitted(0);
              }}
              disabled={busy}
            >
              <RecoveryQr
                mobile={mobile}
                disabled={busy || !material.trim()}
                onPrepare={async () => (await prepare()).phrase}
              />
            </RecoveryCodePanel>
            <section className="recovery-backup-section">
              <h3>{t("recover.backupTitle")}</h3>
              <p className="page-description">
                {t(
                  mobile
                    ? "recover.backupMobileHelp"
                    : "recover.backupDesktopHelp",
                )}
              </p>
              <p className="page-description">{t("recover.backupSizeHelp")}</p>
              <button
                className="secondary"
                disabled={busy || !material.trim()}
                onClick={() => {
                  void perform(async () => {
                    setSaved(false);
                    setOmitted(0);
                    const card = await verify();
                    const result = await profileTask<{
                      saved: boolean;
                      shared?: boolean;
                      omitted_messages?: number;
                    }>("backup", {
                      words: card.phrase,
                    });
                    setSaved(result.saved);
                    setOmitted(
                      result.saved || result.shared
                        ? (result.omitted_messages ?? 0)
                        : 0,
                    );
                  });
                }}
              >
                {busy ? t("sync.busy") : t("recover.saveBackup")}
              </button>
              <p className="page-description">
                {t("recover.restoreBackupHelp")}
              </p>
              {saved && <p className="muted">{t("recover.saved")}</p>}
              {omitted > 0 && (
                <p className="muted" role="status">
                  {t("recover.backupOmitted", { count: omitted })}
                </p>
              )}
            </section>
          </>
        ) : (
          <form
            onInvalid={onInvalid}
            onSubmit={(e) => {
              e.preventDefault();
              void perform(async () => {
                // Verify first; biometric deletion must not run after a mistyped password.
                await invoke("verify_password", { password });
                await cancelProfileReminders(identity, mobile);
                if (mobile) await disableBiometricUnlock();
                await profileTask("remove", { password, identity, confirmed });
                window.location.reload();
              });
            }}
          >
            <p>{t("recover.removeHelp")}</p>
            <label>
              {t("unlock.password")}
              <PasswordInput
                required
                autoComplete="off"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                maxLength={1024}
              />
            </label>
            <label className="check">
              <input
                type="checkbox"
                checked={confirmed}
                onChange={(e) => setConfirmed(e.target.checked)}
              />
              {t("recover.removeConfirm")}
            </label>
            <button className="danger-outline" disabled={busy || !confirmed}>
              {t("recover.removeDevice")}
            </button>
          </form>
        )}
      </div>
      {menuAnchor && (
        <ActionDialog
          title={t("nav.actions")}
          anchor={menuAnchor}
          menu
          onClose={() => setMenuAnchor(null)}
        >
          <button
            type="button"
            role="menuitem"
            onClick={() => {
              setMenuAnchor(null);
              setMaterial("");
              setControlRecovery(true);
            }}
          >
            {t("control.title")}
          </button>
          <button
            type="button"
            role="menuitem"
            className="danger-action"
            onClick={() => {
              setMenuAnchor(null);
              setMaterial("");
              setRemoving(true);
            }}
          >
            {t("recover.removeDevice")}
          </button>
        </ActionDialog>
      )}
    </>
  );
}
