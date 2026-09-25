import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { shareText } from "@choochmeque/tauri-plugin-sharekit-api";
import { t } from "./i18n";
import { useToast } from "./Toast";
import { RecoveryCodePanel } from "./RecoveryCodePanel";
import { parseRecoveryCode } from "./recoveryCode";
import { PasswordInput } from "./PasswordInput";
import { ScreenHeader } from "./ScreenHeader";

type Chat = { space: string; stream: string; name: string };
type Permission = "READ" | "POST" | "SHARE_HISTORY" | "MANAGE" | "REPLICATE";
type Preview = Chat & {
  kind: "recover" | "adopt";
  package_id: string;
  known_chat: boolean;
  forked: boolean;
  controller: string;
  new_device: string;
  names: Record<string, string>;
  members: {
    identity_id: string;
    capabilities: Permission[];
    credential_ids: string[];
  }[];
};
type Choices = { identity: string; device: string; chats: Chat[] };
const task = <T,>(op: string, fields: Record<string, unknown> = {}) =>
  invoke<T>("control_task", { request: { op, ...fields } });
const permissions = {
  READ: "control.permission.read",
  POST: "control.permission.post",
  SHARE_HISTORY: "control.permission.history",
  MANAGE: "control.permission.manage",
  REPLICATE: "control.permission.replicate",
} as const;

export function ControlRecovery({
  mobile,
  onClose,
}: {
  mobile: boolean;
  onClose: () => void;
}) {
  const [step, setStep] = useState<
    "start" | "request" | "help" | "review" | "done"
  >("start");
  const [busy, setBusy] = useState(false);
  const [code, setCode] = useState("");
  const [device, setDevice] = useState("");
  const [choices, setChoices] = useState<Choices | null>(null);
  const [preview, setPreview] = useState<Preview | null>(null);
  const [confirmed, setConfirmed] = useState(false);
  const [password, setPassword] = useState("");
  const [words, setWords] = useState("");
  const [saved, setSaved] = useState(false);
  const { reportError, notify, onInvalid } = useToast();
  useEffect(
    () => () => {
      void task("cancel").catch(() => {});
    },
    [],
  );
  const perform = async (work: () => Promise<void>) => {
    setBusy(true);
    try {
      await work();
    } catch (error) {
      reportError(error);
    } finally {
      setBusy(false);
    }
  };
  const load = async () => {
    setPreview(null);
    setConfirmed(false);
    setPassword("");
    setWords("");
    const result = await task<Preview | null>("preview");
    if (result) {
      setPreview(result);
      setStep("review");
    }
  };
  const back = () => {
    setCode("");
    setChoices(null);
    setPreview(null);
    setPassword("");
    setWords("");
    setConfirmed(false);
    setSaved(false);
    void task("cancel").catch(reportError);
    if (step === "start" || step === "done") onClose();
    else setStep("start");
  };
  return (
    <>
      <ScreenHeader
        title={t("control.title")}
        onBack={busy ? undefined : back}
      />
      <section className="settings-page recovery-page control-recovery">
        {step === "start" && (
          <>
            <p className="page-description">{t("control.help")}</p>
            <button
              className="recovery-choice"
              disabled={busy}
              onClick={() =>
                void perform(async () => {
                  const result = await task<{ code: string; device: string }>(
                    "request",
                  );
                  setCode(result.code);
                  setDevice(result.device);
                  setStep("request");
                })
              }
            >
              <span>
                {t("control.start")}
                <small>{t("control.startChoiceHelp")}</small>
              </span>
            </button>
            <button
              className="secondary recovery-choice"
              disabled={busy}
              onClick={() => {
                setCode("");
                setStep("help");
              }}
            >
              <span>
                {t("control.assist")}
                <small>{t("control.assistChoiceHelp")}</small>
              </span>
            </button>
            <button
              className="secondary recovery-choice"
              disabled={busy}
              onClick={() => void perform(load)}
            >
              <span>
                {t("control.open")}
                <small>{t("control.openChoiceHelp")}</small>
              </span>
            </button>
          </>
        )}
        {step === "request" && (
          <>
            <p className="page-description">{t("control.requestHelp")}</p>
            <p className="page-description">{t("control.deviceId")}</p>
            <code className="control-fingerprint">{device}</code>
            <label>
              {t("control.requestCode")}
              <textarea readOnly value={code} rows={4} />
            </label>
            <button
              className="secondary"
              disabled={busy}
              onClick={() =>
                void perform(async () => {
                  if (mobile) await shareText(code);
                  else {
                    await navigator.clipboard.writeText(code);
                    notify(t("devices.copied"));
                  }
                })
              }
            >
              {t(mobile ? "invite.shareLink" : "invite.copy")}
            </button>
            <button disabled={busy} onClick={() => void perform(load)}>
              {t("control.open")}
            </button>
          </>
        )}
        {step === "help" && (
          <>
            <p className="page-description">{t("control.assistHelp")}</p>
            <label>
              {t("control.requestCode")}
              <textarea
                disabled={busy}
                value={code}
                maxLength={16384}
                rows={4}
                onChange={(e) => {
                  setCode(e.target.value);
                  setChoices(null);
                  setConfirmed(false);
                  setSaved(false);
                }}
              />
            </label>
            {!choices && (
              <button
                disabled={busy || !code.trim()}
                onClick={() =>
                  void perform(async () => {
                    setChoices(
                      await task<Choices>("choices", { code: code.trim() }),
                    );
                  })
                }
              >
                {t("control.find")}
              </button>
            )}
            {choices && (
              <>
                <p className="page-description">{t("control.compareDevice")}</p>
                <code className="control-fingerprint">{choices.device}</code>
                <label className="check">
                  <input
                    type="checkbox"
                    disabled={busy}
                    checked={confirmed}
                    onChange={(e) => setConfirmed(e.target.checked)}
                  />
                  {t("control.deviceConfirmed")}
                </label>
                {choices.chats.length === 0 && (
                  <p className="page-description">{t("control.noChats")}</p>
                )}
                {choices.chats.map((chat) => (
                  <button
                    className="secondary"
                    key={`${chat.space}:${chat.stream}`}
                    disabled={busy || !confirmed}
                    onClick={() =>
                      void perform(async () => {
                        const result = await task<{ saved: boolean }>(
                          "export",
                          {
                            code: code.trim(),
                            ...chat,
                            device: choices.device,
                          },
                        );
                        setSaved(result.saved);
                      })
                    }
                  >
                    {t("control.saveFor", { name: chat.name })}
                  </button>
                ))}
                {saved && (
                  <p role="status" className="page-description">
                    {t("control.saved")}
                  </p>
                )}
              </>
            )}
          </>
        )}
        {step === "review" && preview && (
          <form
            onInvalid={onInvalid}
            onSubmit={(e) => {
              e.preventDefault();
              void perform(async () => {
                try {
                  await task("confirm", {
                    package_id: preview.package_id,
                    confirmed,
                    password,
                    words:
                      parseRecoveryCode(words)?.phrase ??
                      words.replaceAll(",", " "),
                  });
                  setStep("done");
                  setConfirmed(false);
                } finally {
                  setWords("");
                  setPassword("");
                }
              });
            }}
          >
            <h4>{preview.name}</h4>
            <p className="page-description">
              {t(
                preview.kind === "recover"
                  ? "control.reviewHelp"
                  : "control.adoptHelp",
              )}
            </p>
            {!preview.known_chat && (
              <p className="control-warning">{t("control.unknownChat")}</p>
            )}
            <p className="page-description">{t("control.spaceId")}</p>
            <code className="control-fingerprint">{preview.space}</code>
            <p className="page-description">
              {t(
                preview.kind === "recover"
                  ? "control.deviceId"
                  : "control.managingDevice",
              )}
            </p>
            <code className="control-fingerprint">
              {preview.kind === "recover"
                ? preview.new_device
                : preview.controller}
            </code>
            <h4>{t("control.members")}</h4>
            <ul className="control-members">
              {preview.members.map((member) => (
                <li key={member.identity_id}>
                  {preview.names?.[member.identity_id] && (
                    <strong>{preview.names[member.identity_id]}</strong>
                  )}
                  <code className="control-fingerprint">
                    {member.identity_id}
                  </code>
                  <span>
                    {member.capabilities
                      .map((capability) => t(permissions[capability]))
                      .join(", ")}
                  </span>
                  <small>
                    {t("control.deviceCount", {
                      count: member.credential_ids.length,
                    })}
                  </small>
                </li>
              ))}
            </ul>
            {preview.forked ? (
              <p className="control-warning" role="alert">
                {t("control.conflict")}
              </p>
            ) : (
              <>
                {preview.kind === "recover" && (
                  <RecoveryCodePanel
                    value={words}
                    onChange={setWords}
                    disabled={busy}
                  >
                    {null}
                  </RecoveryCodePanel>
                )}
                <label>
                  {t("unlock.password")}
                  <PasswordInput
                    required
                    autoComplete="off"
                    disabled={busy}
                    value={password}
                    maxLength={1024}
                    onChange={(e) => setPassword(e.target.value)}
                  />
                </label>
                <label className="check">
                  <input
                    type="checkbox"
                    disabled={busy}
                    checked={confirmed}
                    onChange={(e) => setConfirmed(e.target.checked)}
                  />
                  {t("control.confirm")}
                </label>
                <button
                  disabled={
                    busy ||
                    !confirmed ||
                    (preview.kind === "recover" && !words.trim())
                  }
                >
                  {t(
                    busy
                      ? "sync.busy"
                      : preview.kind === "recover"
                        ? "control.restore"
                        : "control.accept",
                  )}
                </button>
              </>
            )}
          </form>
        )}
        {step === "done" && preview && (
          <>
            <p role="status">
              {t(
                preview.kind === "recover"
                  ? "control.restored"
                  : "control.accepted",
              )}
            </p>
            {preview.kind === "recover" && (
              <>
                <p className="page-description">{t("control.shareHelp")}</p>
                <button
                  disabled={busy}
                  onClick={() =>
                    void perform(async () => {
                      const result = await task<{ saved: boolean }>("share", {
                        space: preview.space,
                        stream: preview.stream,
                      });
                      setSaved(result.saved);
                    })
                  }
                >
                  {t("control.share")}
                </button>
                {saved && (
                  <p role="status" className="page-description">
                    {t("control.saved")}
                  </p>
                )}
              </>
            )}
          </>
        )}
        {step === "done" && (
          <button type="button" disabled={busy} onClick={back}>
            {t("devices.done")}
          </button>
        )}
      </section>
    </>
  );
}
