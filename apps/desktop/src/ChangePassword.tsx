import { useEffect, useRef, useState, type FormEvent } from "react";
import { changeProfilePassword } from "./biometric";
import { PasswordInput } from "./PasswordInput";
import { useToast } from "./Toast";
import { t } from "./i18n";

export function ChangePassword({
  identity,
  busy,
  onBusyChange,
  onDone,
  onLockRequired,
}: {
  identity: string;
  busy: boolean;
  onBusyChange: (busy: boolean) => void;
  onDone: () => void;
  onLockRequired: () => void;
}) {
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [repeatPassword, setRepeatPassword] = useState("");
  const [saving, setSaving] = useState(false);
  const inFlight = useRef(false);
  const alive = useRef(true);
  const { notify, showError, reportError, onInvalid } = useToast();
  useEffect(() => {
    alive.current = true;
    return () => {
      alive.current = false;
    };
  }, []);

  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (busy || inFlight.current) return;
    if (!currentPassword || !newPassword || !repeatPassword) {
      showError(t("error.required"));
      return;
    }
    if (Array.from(newPassword).length < 12) {
      showError(t("error.passwordShort"));
      return;
    }
    if (newPassword !== repeatPassword) {
      showError(t("onboarding.passwordMismatch"));
      return;
    }
    if (currentPassword === newPassword) {
      showError(t("password.unchanged"));
      return;
    }
    inFlight.current = true;
    setSaving(true);
    onBusyChange(true);
    try {
      const result = await changeProfilePassword(
        currentPassword,
        newPassword,
        identity,
      );
      if (!alive.current) return;
      setCurrentPassword("");
      setNewPassword("");
      setRepeatPassword("");
      notify(
        t(
          result.biometricNeedsSetup
            ? "password.changedBiometricSetup"
            : "password.changed",
        ),
      );
      onDone();
    } catch (error) {
      const code = error instanceof Error ? error.message : String(error);
      if (code === "password_change_recovery_required") onLockRequired();
      else if (alive.current) reportError(error);
    } finally {
      inFlight.current = false;
      if (alive.current) setSaving(false);
      onBusyChange(false);
    }
  };
  const disabled = busy || saving;
  return (
    <div className="settings-page">
      <form
        className="change-password-form"
        aria-label={t("password.change")}
        aria-busy={saving}
        onSubmit={(event) => void submit(event)}
        onInvalid={onInvalid}
      >
        <label>
          {t("password.current")}
          <PasswordInput
            name="current-password"
            autoComplete="current-password"
            required
            disabled={disabled}
            value={currentPassword}
            onChange={(event) => setCurrentPassword(event.target.value)}
          />
        </label>
        <label>
          {t("password.new")}
          <PasswordInput
            name="new-password"
            autoComplete="new-password"
            required
            minLength={12}
            maxLength={1024}
            disabled={disabled}
            value={newPassword}
            onChange={(event) => setNewPassword(event.target.value)}
          />
        </label>
        <label>
          {t("password.repeatNew")}
          <PasswordInput
            name="repeat-password"
            autoComplete="new-password"
            required
            minLength={12}
            maxLength={1024}
            disabled={disabled}
            value={repeatPassword}
            onChange={(event) => setRepeatPassword(event.target.value)}
          />
        </label>
        <button type="submit" disabled={disabled}>
          {t("password.change")}
        </button>
      </form>
    </div>
  );
}
