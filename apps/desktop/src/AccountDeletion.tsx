import { useEffect, useRef, useState } from "react";
import { ActionDialog } from "./ActionDialog";
import { PasswordInput } from "./PasswordInput";
import { profileTask } from "./ProfileRecovery";
import { cancelProfileReminders } from "./reminders";
import { t } from "./i18n";
import { useToast } from "./Toast";

/** Completion feedback also works after sign-out; no profile keys are retained. */
export function AccountDeletionNotice() {
  const { notify } = useToast();
  const notice = useRef(notify);
  notice.current = notify;
  useEffect(() => {
    let alive = true;
    let timer: ReturnType<typeof setTimeout>;
    const check = async () => {
      try {
        const result = await profileTask<{ status: string }>(
          "account_deletion_status",
        );
        if (!alive) return;
        if (result.status === "completed")
          notice.current(t("accountDeletion.completed"));
        else if (result.status === "pending") timer = setTimeout(check, 15_000);
      } catch {
        if (alive) timer = setTimeout(check, 30_000);
      }
    };
    // Delay until after the initial render; StrictMode cleanup cancels the first call.
    timer = setTimeout(check, 500);
    return () => {
      alive = false;
      clearTimeout(timer);
    };
  }, []);
  return null;
}

type Check = {
  status: "ready" | "blocked" | "pending" | "completed";
  owned_spaces: { name: string; other_members: boolean }[];
};

function DeleteDialog({
  identity,
  mobile,
  onClose,
}: {
  identity: string;
  mobile: boolean;
  onClose: () => void;
}) {
  const [check, setCheck] = useState<Check>();
  const [failed, setFailed] = useState(false);
  const [attempt, setAttempt] = useState(0);
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    let alive = true;
    setCheck(undefined);
    setFailed(false);
    void profileTask<Check>("account_deletion_check", { identity })
      .then((value) => {
        if (alive) setCheck(value);
      })
      .catch(() => {
        if (alive) setFailed(true);
      });
    return () => {
      alive = false;
    };
  }, [identity, attempt]);
  const blocked = check?.status === "blocked";
  return (
    <ActionDialog
      title={t("accountDeletion.title")}
      onClose={() => {
        if (!busy) onClose();
      }}
      className="service-request-dialog account-deletion-dialog"
    >
      {!check ? (
        <>
          <p className="muted" role="status">
            {t(
              failed
                ? "accountDeletion.unavailable"
                : "accountDeletion.checking",
            )}
          </p>
          {failed && (
            <div className="space-choice">
              <button
                className="secondary"
                onClick={() => setAttempt((n) => n + 1)}
              >
                {t("accountDeletion.retry")}
              </button>
            </div>
          )}
        </>
      ) : blocked ? (
        <>
          {check.owned_spaces.map((space, index) => (
            <p className="muted" key={index}>
              {t(
                space.other_members
                  ? "accountDeletion.transferFirst"
                  : "accountDeletion.deleteSpaceFirst",
                { name: space.name },
              )}
            </p>
          ))}
          <div className="space-choice">
            <button className="secondary" onClick={onClose}>
              {t("accountDeletion.close")}
            </button>
          </div>
        </>
      ) : (
        <form
          onSubmit={(event) => {
            event.preventDefault();
            if (busy) return;
            setBusy(true);
            setFailed(false);
            void (async () => {
              try {
                const result = await profileTask<Check | { ok: true }>(
                  "delete_account",
                  { identity, password, confirmed: true },
                );
                if (!("ok" in result)) {
                  setCheck(result);
                  setBusy(false);
                  return;
                }
                // Account erasure and local key removal were acknowledged by native code.
                // Opaque scheduled OS reminders are separate from profile storage.
                await cancelProfileReminders(identity, mobile).catch(() => {});
                localStorage.removeItem(`elo.legal.${identity}`);
                window.location.reload();
              } catch {
                setFailed(true);
                setBusy(false);
              }
            })();
          }}
        >
          <p className="muted">{t("accountDeletion.explanation")}</p>
          <div className="space-form-field">
            <label htmlFor="account-deletion-password">
              {t("unlock.password")}
            </label>
            <PasswordInput
              id="account-deletion-password"
              required
              autoComplete="current-password"
              maxLength={1024}
              value={password}
              disabled={busy}
              onChange={(event) => setPassword(event.target.value)}
            />
          </div>
          {failed && (
            <p className="account-deletion-error" role="alert">
              {t("accountDeletion.failed")}
            </p>
          )}
          <div className="space-choice">
            <button
              type="button"
              className="secondary"
              disabled={busy}
              onClick={onClose}
            >
              {t("accountDeletion.cancel")}
            </button>
            <button
              type="submit"
              className="danger-outline"
              disabled={busy || !password}
              aria-busy={busy}
            >
              {t(busy ? "accountDeletion.sending" : "accountDeletion.confirm")}
            </button>
          </div>
        </form>
      )}
    </ActionDialog>
  );
}

export function AccountDeletion({
  identity,
  mobile,
}: {
  identity: string;
  mobile: boolean;
}) {
  const [open, setOpen] = useState(false);
  return (
    <>
      <button
        className="danger-outline account-deletion-button"
        onClick={() => setOpen(true)}
      >
        {t("accountDeletion.title")}
      </button>
      {open && (
        <DeleteDialog
          identity={identity}
          mobile={mobile}
          onClose={() => setOpen(false)}
        />
      )}
    </>
  );
}
