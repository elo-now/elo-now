import { cancelProfileReminders } from "./reminders";
import { PasswordInput } from "./PasswordInput";
import { useEffect, useState } from "react";
import { shareText } from "@choochmeque/tauri-plugin-sharekit-api";
import { invoke } from "@tauri-apps/api/core";
import { t } from "./i18n";
import { Icon } from "./Icon";
import { useToast } from "./Toast";
import { disableBiometricUnlock } from "./biometric";
import { profileTask, RecoveryQr } from "./ProfileRecovery";
import { RecoveryCodePanel } from "./RecoveryCodePanel";
import { parseRecoveryCode, recoveryCode } from "./recoveryCode";

type Request = { id: string; name: string; code: string };
export function DevicesSettings({ mobile }: { mobile: boolean }) {
  const [svg, setSvg] = useState(""),
    [link, setLink] = useState(""),
    [busy, setBusy] = useState(false);
  const [requests, setRequests] = useState<Request[]>([]),
    [selected, setSelected] = useState<Request | null>(null);
  const [approved, setApproved] = useState(false),
    [confirmed, setConfirmed] = useState(false),
    [password, setPassword] = useState("");
  const [retry, setRetry] = useState(0);
  const [pollFailed, setPollFailed] = useState(false);
  const [expires, setExpires] = useState<number | null>(null);
  const [clock, setClock] = useState(Date.now);
  const remaining = Math.max(0, Math.ceil(((expires ?? clock) - clock) / 1000));
  const expired = expires !== null && remaining === 0;
  const time = `${Math.floor(remaining / 60)
    .toString()
    .padStart(2, "0")}:${(remaining % 60).toString().padStart(2, "0")}`;
  const { reportError, onInvalid, notify } = useToast();
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
  const start = async () => {
    const result = await profileTask<{
      svg: string;
      code: string;
      expires: number;
    }>("pair_start");
    setSvg(result.svg);
    setLink(result.code);
    setExpires(result.expires);
    setClock(Date.now());
    setPollFailed(false);
    setRequests([]);
    setSelected(null);
    setPassword("");
    setConfirmed(false);
    setApproved(false);
  };
  const close = async () => {
    await profileTask("cancel");
    setSvg("");
    setLink("");
    setExpires(null);
    setRequests([]);
    setSelected(null);
    setPassword("");
    setConfirmed(false);
    setApproved(false);
  };
  useEffect(
    () => () => {
      void profileTask("cancel").catch(() => {});
    },
    [],
  );
  useEffect(() => {
    if (!svg || approved || expired) return;
    const timer = setInterval(() => setClock(Date.now()), 1000);
    return () => clearInterval(timer);
  }, [svg, approved, expired]);
  useEffect(() => {
    if (!svg || approved || expired) return;
    let live = true;
    let timer: ReturnType<typeof setTimeout>;
    const poll = async () => {
      if (expires !== null && Date.now() >= expires) return;
      try {
        const result = await profileTask<{ requests: Request[] }>("pair_poll");
        if (live) setRequests(result.requests);
      } catch (e) {
        if (live && (expires === null || Date.now() < expires)) {
          reportError(e);
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
  }, [svg, approved, retry, expires, expired]);
  return (
    <div className="settings-page recovery-page devices-page">
      {!svg && <p className="page-description">{t("devices.help")}</p>}
      {!svg ? (
        <button disabled={busy} onClick={() => void perform(start)}>
          {!busy && <Icon name="plus" />}
          {t(busy ? "devices.preparing" : "devices.link")}
        </button>
      ) : approved ? (
        <>
          <p>{t("devices.sent")}</p>
          <p className="muted">{t("devices.companionHelp")}</p>
          <button
            className="secondary"
            disabled={busy}
            onClick={() => void perform(close)}
          >
            {t("devices.done")}
          </button>
        </>
      ) : expired ? (
        <>
          <p className="muted device-link-help" role="status">
            {t("devices.expired")}
          </p>
          <button disabled={busy} onClick={() => void perform(start)}>
            {t("devices.newCode")}
          </button>
        </>
      ) : selected ? (
        <form
          onInvalid={onInvalid}
          onSubmit={(e) => {
            e.preventDefault();
            void perform(async () => {
              await profileTask("pair_approve", {
                id: selected.id,
                code: selected.code,
                confirmed,
                password,
              });
              setApproved(true);
              setPassword("");
              setSvg("sent");
              setLink("");
            });
          }}
        >
          <h3>{selected.name}</h3>
          <p className="muted">{t("devices.compare")}</p>
          <p className="pair-comparison">{selected.code}</p>
          <label className="check">
            <input
              type="checkbox"
              checked={confirmed}
              onChange={(e) => setConfirmed(e.target.checked)}
            />
            {t("devices.confirmCode")}
          </label>
          <label>
            {t("unlock.password")}
            <PasswordInput
              required
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              autoComplete="off"
              maxLength={1024}
            />
          </label>
          <p className="muted">{t("devices.approveHelp")}</p>
          <button disabled={busy || !confirmed}>
            {busy ? t("sync.busy") : t("devices.approve")}
          </button>
          <button
            type="button"
            className="ghost"
            disabled={busy}
            onClick={() => {
              setSelected(null);
              setPassword("");
              setConfirmed(false);
            }}
          >
            {t("onboarding.back")}
          </button>
        </form>
      ) : (
        <>
          <p className="muted device-link-help">{t("devices.codeHelp")}</p>
          {requests.length === 0 && !pollFailed && (
            <p
              className="muted device-link-waiting"
              role="timer"
              aria-live="off"
            >
              {t("devices.noRequests", { time })}
            </p>
          )}
          <div
            className="private-qr"
            role="img"
            aria-label={t("devices.qrLabel")}
            dangerouslySetInnerHTML={{ __html: svg }}
          />
          <p className="invitation-code-alternative">{t("invite.or")}</p>
          <button
            type="button"
            disabled={busy}
            onClick={(event) => {
              const box = event.currentTarget.getBoundingClientRect();
              void perform(async () => {
                if (mobile)
                  await shareText(link, {
                    position: { x: box.x + box.width / 2, y: box.bottom },
                  });
                else {
                  await navigator.clipboard.writeText(link);
                  notify(t("devices.copied"));
                }
              });
            }}
          >
            <Icon name={mobile ? "share" : "copy"} />
            {t(mobile ? "invite.shareLink" : "invite.copy")}
          </button>
          {pollFailed && (
            <button
              type="button"
              className="ghost"
              onClick={() => {
                setPollFailed(false);
                setRetry((v) => v + 1);
              }}
            >
              {t("devices.retry")}
            </button>
          )}
          {requests.map((request) => (
            <button
              className="recovery-choice"
              key={request.id}
              onClick={() => setSelected(request)}
            >
              <Icon name="device" />
              <span>{request.name}</span>
              <Icon name="next" />
            </button>
          ))}
        </>
      )}
    </div>
  );
}

export function RecoverySettings({
  mobile,
  identity,
  demoProfile,
}: {
  mobile: boolean;
  identity: string;
  demoProfile?: string;
}) {
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
  return (
    <div className="settings-page recovery-page">
      {!removing ? (
        <>
          <p className="page-description">{t("recover.settingsHelp")}</p>
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
            <p className="page-description">{t("recover.restoreBackupHelp")}</p>
            {saved && <p className="muted">{t("recover.saved")}</p>}
            {omitted > 0 && (
              <p className="muted" role="status">
                {t("recover.backupOmitted", { count: omitted })}
              </p>
            )}
          </section>
          {!demoProfile && (
            <button
              className="danger-outline recovery-remove"
              disabled={busy}
              onClick={() => setRemoving(true)}
            >
              {t("recover.removeDevice")}
            </button>
          )}
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
              localStorage.removeItem("elo.biometricOffer.v1");
              window.location.reload();
            });
          }}
        >
          <h3>{t("recover.removeDevice")}</h3>
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
          <button
            className="ghost"
            type="button"
            disabled={busy}
            onClick={() => {
              setRemoving(false);
              setPassword("");
              setConfirmed(false);
            }}
          >
            {t("onboarding.back")}
          </button>
        </form>
      )}
    </div>
  );
}
