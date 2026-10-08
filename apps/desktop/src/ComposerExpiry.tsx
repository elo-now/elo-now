import { useState } from "react";
import { ActionDialog } from "./ActionDialog";
import { ExpiryChoices } from "./ExpiryChoices";
import { t } from "./i18n";
import type { MessageExpiryHours } from "./messageExpiry";

export function ComposerExpiry({
  value,
  onChange,
  disabled,
}: {
  value?: MessageExpiryHours;
  onChange: (value?: MessageExpiryHours) => void;
  disabled?: boolean;
}) {
  const [open, setOpen] = useState(false);
  const [draft, setDraft] = useState<MessageExpiryHours | null>(null);
  const close = () => setOpen(false);
  return (
    <>
      <button
        type="button"
        className="composer-expiry-link"
        disabled={disabled}
        onClick={() => {
          setDraft(value ?? null);
          setOpen(true);
        }}
      >
        {value === undefined
          ? t("composer.noExpiry")
          : t("composer.expireIn", { hours: value })}
      </button>
      {open && (
        <ActionDialog title={t("messageActions.expiry")} onClose={close}>
          <div className="message-expiry-picker">
            <p>{t("composer.expiryDescription")}</p>
            <ExpiryChoices value={draft} onChange={setDraft} />
            <div className="dialog-buttons">
              <button type="button" className="secondary" onClick={close}>
                {t("dialog.cancel")}
              </button>
              <button
                type="button"
                onClick={() => {
                  onChange(draft ?? undefined);
                  close();
                }}
              >
                {t("messageActions.saveExpiry")}
              </button>
            </div>
          </div>
        </ActionDialog>
      )}
    </>
  );
}
