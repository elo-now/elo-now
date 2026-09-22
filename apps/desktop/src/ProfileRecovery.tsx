import { PasswordInput } from "./PasswordInput";
import { useEffect, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import {
  RecoveryProgress,
  acceptsRecoveryStep,
  type RecoveryStep,
} from "./RecoveryProgress";
import {
  cancel,
  checkPermissions,
  requestPermissions,
  scan,
  Format,
} from "@tauri-apps/plugin-barcode-scanner";
import { t } from "./i18n";
import { ScreenHeader } from "./ScreenHeader";
import { ActionDialog } from "./ActionDialog";
import { parseRecoveryCode, recoveryCode } from "./recoveryCode";
import { Icon } from "./Icon";
import { useToast } from "./Toast";
import type { View } from "./model";
import { acceptLegal, LegalNotice } from "./LegalInfo";
import { checkedProfileName } from "./ProfileName";

export const profileTask = <T,>(
  op: string,
  fields: Record<string, unknown> = {},
) => invoke<T>("profile_task", { request: { op, ...fields } });
type Card = { phrase: string; identity_id: string };
type PairStatus = { identity: string; code: string; ready: boolean };

export function RecoveryWords({
  value,
  onChange,
}: {
  value: string;
  onChange: (value: string) => void;
}) {
  const count = value.trim() ? value.trim().split(/\s+/u).length : 0;
  return (
    <label>
      {t("recover.words")}
      <textarea
        className="recovery-input"
        required
        value={value}
        onChange={(e) => onChange(e.target.value)}
        maxLength={2048}
        rows={4}
        autoCapitalize="none"
        autoCorrect="off"
        autoComplete="off"
        spellCheck={false}
      />
      <small>{t("recover.wordCount", { count })}</small>
    </label>
  );
}

export function RecoveryQr({
  words,
  mobile,
  onPrepare,
  disabled = false,
}: {
  words?: string;
  mobile: boolean;
  onPrepare?: () => Promise<string>;
  disabled?: boolean;
}) {
  const [open, setOpen] = useState(false),
    [password, setPassword] = useState("");
  const [preparedWords, setPreparedWords] = useState<string>();
  const [svg, setSvg] = useState(""),
    [busy, setBusy] = useState(false),
    [saved, setSaved] = useState(false);
  const { reportError, onInvalid } = useToast();
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
  const close = () => {
    if (busy) return;
    void profileTask("clear_qr").catch(reportError);
    setSaved(false);
    setOpen(false);
    setSvg("");
    setPassword("");
    setPreparedWords(undefined);
  };
  return (
    <div className="recovery-qr-panel">
      <button
        type="button"
        className="secondary"
        disabled={busy || disabled}
        onClick={() =>
          void perform(async () => {
            if (onPrepare) setPreparedWords(await onPrepare());
            setOpen(true);
          })
        }
      >
        <Icon name="qr" />
        {t("onboarding.saveQr")}
      </button>
      {open && (
        <ActionDialog
          page
          title={t(svg ? "recover.encryptedQr" : "recover.protectQr")}
          onClose={close}
          className="recovery-qr-dialog"
        >
          {!svg ? (
            <form
              onInvalid={onInvalid}
              onSubmit={(event) => {
                event.preventDefault();
                if (busy || Array.from(password).length < 12) return;
                void perform(async () => {
                  const result = await profileTask<{ svg: string }>(
                    "recovery_qr",
                    { password, words: preparedWords ?? words },
                  );
                  setSvg(result.svg);
                  setPassword("");
                });
              }}
            >
              <p className="muted">{t("recover.qrHelp")}</p>
              <label>
                {t("unlock.password")}
                <PasswordInput
                  required
                  autoComplete="new-password"
                  disabled={busy}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  minLength={12}
                  maxLength={1024}
                />
              </label>
              <button disabled={busy || Array.from(password).length < 12}>
                {t("recover.generateQr")}
              </button>
            </form>
          ) : (
            <>
              <div
                className="private-qr"
                role="img"
                aria-label={t("recover.encryptedQr")}
                dangerouslySetInnerHTML={{ __html: svg }}
              />
              <button
                type="button"
                disabled={busy}
                onClick={() =>
                  void perform(async () => {
                    if (mobile) {
                      await profileTask("share_recovery_qr");
                    } else {
                      const result = await profileTask<{ saved: boolean }>(
                        "save_recovery_qr",
                      );
                      setSaved(result.saved);
                    }
                  })
                }
              >
                {t("recover.saveImage")}
              </button>
              {saved && <p className="muted">{t("recover.saved")}</p>}
            </>
          )}
        </ActionDialog>
      )}
    </div>
  );
}

export function CodeInput({
  mobile,
  code,
  onChange,
  disabled = false,
}: {
  mobile: boolean;
  code: string;
  onChange: (code: string) => void;
  disabled?: boolean;
}) {
  const { reportError } = useToast();
  const [scanning, setScanning] = useState(false);
  const [captured, setCaptured] = useState(false);
  const live = useRef(true);
  const gallery = useRef<HTMLInputElement>(null);
  useEffect(() => {
    live.current = true;
    return () => {
      live.current = false;
      if (mobile) void cancel().catch(() => {});
    };
  }, [mobile]);
  const read = async () => {
    setScanning(true);
    try {
      if (
        (await checkPermissions()) !== "granted" &&
        (await requestPermissions()) !== "granted"
      )
        throw t("invite.cameraDenied");
      const result = await scan({ formats: [Format.QRCode], windowed: false });
      if (live.current) {
        onChange(result.content);
        setCaptured(true);
      }
    } catch (e) {
      if (live.current && !/cancel/i.test(String(e))) reportError(e);
    } finally {
      if (live.current) setScanning(false);
    }
  };
  const choose = async (input: HTMLInputElement) => {
    const file = input.files?.[0];
    input.value = "";
    if (!file) return;
    setScanning(true);
    try {
      if (file.size > 12 * 1024 * 1024) throw t("recover.imageTooLarge");
      const image = await new Promise<string>((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = () => resolve(String(reader.result));
        reader.onerror = () => reject(t("recover.imageInvalid"));
        reader.readAsDataURL(file);
      });
      const result = await profileTask<{ code: string }>("read_qr_image", {
        image,
      });
      if (live.current) {
        onChange(result.code);
        setCaptured(true);
      }
    } catch (e) {
      if (live.current) reportError(e);
    } finally {
      if (live.current) setScanning(false);
    }
  };
  return (
    <>
      <input
        hidden
        type="file"
        accept="image/png,image/jpeg"
        ref={gallery}
        aria-label={t("recover.chooseImage")}
        onChange={(e) => void choose(e.currentTarget)}
      />
      <div className="recovery-actions">
        {mobile && (
          <button
            type="button"
            className="ghost"
            disabled={disabled || scanning}
            onClick={() => void read()}
          >
            <Icon name="qr" />
            {t("invite.scan")}
          </button>
        )}
        <button
          type="button"
          className="ghost"
          disabled={disabled || scanning}
          onClick={() => gallery.current?.click()}
        >
          {t("recover.chooseImage")}
        </button>
      </div>
      {captured && code ? (
        <div className="recovery-captured">
          <p>{t("recover.codeReady")}</p>
          <button
            type="button"
            className="ghost"
            disabled={disabled}
            onClick={() => {
              onChange("");
              setCaptured(false);
            }}
          >
            {t("recover.changeCode")}
          </button>
        </div>
      ) : (
        <label>
          {t("recover.pasteCode")}
          <textarea
            rows={2}
            maxLength={4096}
            value={code}
            onChange={(e) => onChange(e.target.value)}
            autoCapitalize="none"
            autoComplete="off"
            autoCorrect="off"
            spellCheck={false}
          />
        </label>
      )}
    </>
  );
}

export function ProfileRecovery({
  mobile,
  hasProfile,
  onBack,
  onOpen,
}: {
  mobile: boolean;
  hasProfile: boolean;
  onBack: () => void;
  onOpen: (view: View, password: string) => void;
}) {
  const [step, setStep] = useState<
    "choose" | "words" | "qr" | "password" | "device"
  >("choose");
  const [recoveryInput, setRecoveryInput] = useState("");
  const [separateWords, setSeparateWords] = useState(false);
  const [method, setMethod] = useState<"words" | "qr">("words");
  const [words, setWords] = useState(""),
    [identity, setIdentity] = useState(""),
    [name, setName] = useState("");
  const [password, setPassword] = useState(""),
    [repeat, setRepeat] = useState(""),
    [code, setCode] = useState("");
  const [qrPassword, setQrPassword] = useState(""),
    [deviceName, setDeviceName] = useState("");
  const [backup, setBackup] = useState(false),
    [busy, setBusy] = useState(false),
    [confirmed, setConfirmed] = useState(false);
  const [pair, setPair] = useState<PairStatus | null>(null);
  const [retry, setRetry] = useState(0);
  const [progress, setProgress] = useState<RecoveryStep | null>(null);
  const [paused, setPaused] = useState(false);
  const [pausing, setPausing] = useState(false);
  const [resuming, setResuming] = useState(false);
  const recoveryPaused = paused || (resuming && !busy);
  const recoveryRequest = useRef<string | undefined>(undefined);
  const [pollFailed, setPollFailed] = useState(false);
  const { reportError, onInvalid } = useToast();
  const perform = async (work: () => Promise<void>) => {
    setBusy(true);
    try {
      await work();
    } catch (e) {
      reportError(e);
    } finally {
      setBusy(false);
    }
  };
  useEffect(() => {
    if (!pair || pair.ready || step !== "device") return;
    let live = true;
    let timer: ReturnType<typeof setTimeout>;
    const poll = async () => {
      try {
        const status = await profileTask<PairStatus>("pair_receive");
        if (live) setPair(status);
      } catch (e) {
        if (live) {
          reportError(e);
          setPollFailed(true);
          return;
        }
      }
      if (live) timer = setTimeout(() => void poll(), 3000);
    };
    timer = setTimeout(() => void poll(), 1000);
    return () => {
      live = false;
      clearTimeout(timer);
    };
  }, [pair?.ready, !!pair, step, retry]);
  const back = () =>
    void perform(async () => {
      setPassword("");
      setRepeat("");
      setQrPassword("");
      setProgress(null);
      setPaused(false);
      setPausing(false);
      if (step === "choose") {
        await profileTask("cancel");
        onBack();
      } else if (step === "password") setStep(method);
      else {
        await profileTask("cancel");
        setPair(null);
        setBackup(false);
        setCode("");
        setPollFailed(false);
        setStep("choose");
      }
    });
  const newPassword = (
    <>
      <label>
        {t("recover.newPassword")}
        <PasswordInput
          required
          minLength={12}
          maxLength={1024}
          autoComplete="new-password"
          disabled={busy}
          value={password}
          onChange={(e) => setPassword(e.target.value)}
        />
      </label>
      <label>
        {t("onboarding.confirmPassword")}
        <PasswordInput
          required
          minLength={12}
          maxLength={1024}
          autoComplete="new-password"
          disabled={busy}
          value={repeat}
          onChange={(e) => setRepeat(e.target.value)}
        />
      </label>
    </>
  );
  const finish = async (op: "recover" | "pair_finish") => {
    if (password !== repeat) throw t("onboarding.passwordMismatch");
    const recoveryName = name.trim();
    if (op === "recover" && (!backup || recoveryName))
      checkedProfileName(recoveryName);
    const request = crypto.randomUUID();
    recoveryRequest.current = request;
    setPaused(false);
    setPausing(false);
    let unlisten: (() => void) | undefined;
    let view: View;
    try {
      if (op === "recover" && backup) {
        setProgress({ request, stage: "unlocking", done: 0, total: 0 });
        unlisten = await listen<RecoveryStep>(
          "recovery-progress",
          ({ payload }) => {
            if (
              recoveryRequest.current === request &&
              acceptsRecoveryStep(payload, request)
            )
              setProgress(payload);
          },
        );
      }
      view = await profileTask<View>(op, {
        password,
        name: recoveryName,
        code: pair?.code,
        confirmed,
        request_id: request,
      });
    } catch (error) {
      if (String(error).startsWith("Recovery paused.")) {
        setPaused(true);
        setResuming(true);
        return;
      }
      setProgress(null);
      throw error;
    } finally {
      unlisten?.();
      recoveryRequest.current = undefined;
    }
    const verified = password;
    setWords("");
    setPassword("");
    setRepeat("");
    setCode("");
    setQrPassword("");
    acceptLegal(view.identity);
    onOpen(view, verified);
  };
  return (
    <main className="profile-recovery-screen">
      <ScreenHeader
        title={t(
          step === "words"
            ? "recover.codeTitle"
            : step === "qr"
              ? "recover.qrTitle"
              : step === "device"
                ? "recover.useDevice"
                : step === "password"
                  ? "recover.finishTitle"
                  : "recover.entryTitle",
        )}
        onBack={() => {
          if (!busy) back();
        }}
      />
      <div className="settings-page recovery-page">
        {step === "choose" && (
          <>
            <p className="muted">{t("recover.chooseHelp")}</p>
            {(
              [
                ["words", "lock", "recover.useWords", "recover.codeChoiceHelp"],
                ["qr", "qr", "recover.useQr", "recover.qrChoiceHelp"],
                [
                  "device",
                  "device",
                  "recover.useDevice",
                  "recover.deviceChoiceHelp",
                ],
              ] as const
            ).map(([next, icon, label, help]) => (
              <button
                key={next}
                className="secondary recovery-choice"
                onClick={() => {
                  if (next !== "device") setMethod(next);
                  setStep(next);
                }}
              >
                <Icon name={icon} />
                <span>
                  {t(label)}
                  <small>{t(help)}</small>
                </span>
                <Icon name="next" />
              </button>
            ))}
            {hasProfile && <p className="muted">{t("recover.preserve")}</p>}
          </>
        )}
        {step === "words" && (
          <form
            onInvalid={onInvalid}
            onSubmit={(e) => {
              e.preventDefault();
              void perform(async () => {
                const parsed = separateWords
                  ? {
                      phrase: words.replaceAll(",", " "),
                      identity_id: identity.trim(),
                    }
                  : parseRecoveryCode(recoveryInput);
                if (!parsed) throw t("recover.error.codeFormat");
                const card = await profileTask<Card>("check_recovery", {
                  words: parsed.phrase,
                  identity: parsed.identity_id,
                });
                setWords(card.phrase);
                setIdentity(card.identity_id);
                setStep("password");
              });
            }}
          >
            <p className="muted">{t("recover.codeHelp")}</p>
            {separateWords ? (
              <>
                <RecoveryWords
                  value={words}
                  onChange={(value) => {
                    const parsed = parseRecoveryCode(value);
                    setWords(parsed?.phrase ?? value);
                    if (parsed) setIdentity(parsed.identity_id);
                  }}
                />
                <label>
                  {t("recover.identity")}
                  <textarea
                    aria-label={t("recover.identity")}
                    required
                    rows={2}
                    value={identity}
                    maxLength={256}
                    onChange={(e) => setIdentity(e.target.value)}
                    autoCapitalize="none"
                    autoCorrect="off"
                    autoComplete="off"
                    spellCheck={false}
                  />
                </label>
              </>
            ) : (
              <label>
                {t("recover.codeTitle")}
                <textarea
                  className="recovery-input"
                  required
                  rows={5}
                  maxLength={2048}
                  value={recoveryInput}
                  onChange={(e) => setRecoveryInput(e.target.value)}
                  autoCapitalize="none"
                  autoCorrect="off"
                  autoComplete="off"
                  spellCheck={false}
                  placeholder="identity|word1,word2,…"
                />
              </label>
            )}
            <button
              type="button"
              className="ghost"
              disabled={busy}
              onClick={() => {
                if (separateWords && words && identity)
                  setRecoveryInput(
                    recoveryCode({ phrase: words, identity_id: identity }),
                  );
                setSeparateWords(!separateWords);
              }}
            >
              {t(
                separateWords
                  ? "recover.pasteFullCode"
                  : "recover.enterSeparateWords",
              )}
            </button>
            <button disabled={busy}>
              {busy ? t("sync.busy") : t("invite.continue")}
            </button>
          </form>
        )}
        {step === "qr" && (
          <form
            onInvalid={onInvalid}
            onSubmit={(e) => {
              e.preventDefault();
              void perform(async () => {
                const card = await profileTask<Card>("read_recovery_qr", {
                  code,
                  password: qrPassword,
                });
                setWords(card.phrase);
                setIdentity(card.identity_id);
                setCode("");
                setQrPassword("");
                setRecoveryInput(recoveryCode(card));
                setStep("password");
              });
            }}
          >
            <p className="muted">{t("recover.qrReadHelp")}</p>
            <CodeInput
              mobile={mobile}
              code={code}
              onChange={setCode}
              disabled={busy}
            />
            <label>
              {t("unlock.password")}
              <PasswordInput
                required
                value={qrPassword}
                onChange={(e) => setQrPassword(e.target.value)}
                minLength={12}
                maxLength={1024}
                autoComplete="off"
              />
            </label>
            <p className="muted">{t("recover.qrPasswordHelp")}</p>
            <button disabled={busy || !code}>{t("invite.continue")}</button>
          </form>
        )}
        {step === "password" && (
          <form
            onInvalid={onInvalid}
            onSubmit={(e) => {
              e.preventDefault();
              void perform(() => finish("recover"));
            }}
          >
            {!busy && !resuming && !paused && (
              <p className="muted">{t("recover.passwordHelp")}</p>
            )}
            <RecoveryProgress
              value={progress}
              paused={recoveryPaused}
              pausing={pausing}
              onPause={
                busy && backup
                  ? () => {
                      setPausing(true);
                      void profileTask("pause_recovery", {
                        request_id: recoveryRequest.current,
                      }).catch(reportError);
                    }
                  : undefined
              }
            />
            <label>
              {t(backup ? "recover.backupName" : "profile.name")}
              <input
                required={!backup}
                disabled={busy}
                value={name}
                onChange={(e) => setName(e.target.value)}
                maxLength={120}
                autoComplete="nickname"
                autoCapitalize="words"
                autoCorrect="off"
                spellCheck={false}
              />
              {backup && <small>{t("recover.backupNameHelp")}</small>}
            </label>
            {newPassword}
            <div className="recovery-backup-option">
              <p className="muted">
                {t(
                  backup ? "recover.backupHelp" : "recover.optionalBackupHelp",
                )}
              </p>
              <button
                type="button"
                className="secondary"
                disabled={busy}
                onClick={() =>
                  void perform(async () => {
                    if (backup) {
                      await profileTask("clear_backup");
                      setBackup(false);
                      setResuming(false);
                      setPaused(false);
                      setProgress(null);
                    } else {
                      const result = await profileTask<{
                        selected: boolean;
                        resume?: boolean;
                      }>("choose_backup");
                      setBackup(result.selected);
                      setResuming(result.resume === true);
                    }
                  })
                }
              >
                {t(backup ? "recover.removeBackup" : "recover.chooseBackup")}
              </button>
            </div>
            <LegalNotice
              action={t(
                recoveryPaused ? "recover.progressContinue" : "recover.finish",
              )}
            />
            <button disabled={busy}>
              {busy
                ? t("sync.busy")
                : t(
                    recoveryPaused
                      ? "recover.progressContinue"
                      : "recover.finish",
                  )}
            </button>
          </form>
        )}
        {step === "device" && (
          <>
            {!pair ? (
              <form
                onInvalid={onInvalid}
                onSubmit={(e) => {
                  e.preventDefault();
                  void perform(async () => {
                    setPair(
                      await profileTask<PairStatus>("pair_request", {
                        code,
                        name: deviceName,
                      }),
                    );
                    setCode("");
                  });
                }}
              >
                <p className="muted">{t("devices.scanHelp")}</p>
                <CodeInput
                  mobile={mobile}
                  code={code}
                  onChange={setCode}
                  disabled={busy}
                />
                <label>
                  {t("devices.name")}
                  <input
                    required
                    value={deviceName}
                    onChange={(e) => setDeviceName(e.target.value)}
                    maxLength={120}
                    autoComplete="off"
                  />
                </label>
                <button disabled={busy || !code}>{t("devices.connect")}</button>
              </form>
            ) : (
              <form
                onInvalid={onInvalid}
                onSubmit={(e) => {
                  e.preventDefault();
                  void perform(() => finish("pair_finish"));
                }}
              >
                <p className="muted">{t("devices.compare")}</p>
                <p className="pair-comparison">{pair.code}</p>
                <p className="muted">
                  {pair.ready ? t("devices.approved") : t("devices.waiting")}
                </p>
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
                {pair.ready && (
                  <>
                    {newPassword}
                    <label className="check">
                      <input
                        type="checkbox"
                        checked={confirmed}
                        onChange={(e) => setConfirmed(e.target.checked)}
                      />
                      {t("devices.confirmCode")}
                    </label>
                    <p className="muted">{t("devices.companionHelp")}</p>
                    <LegalNotice action={t("devices.connect")} />
                    <button disabled={busy || !confirmed}>
                      {busy ? t("sync.busy") : t("devices.connect")}
                    </button>
                  </>
                )}
              </form>
            )}
          </>
        )}
      </div>
    </main>
  );
}
