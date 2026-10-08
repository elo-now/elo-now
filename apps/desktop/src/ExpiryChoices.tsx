import { t } from "./i18n";
import type { MessageExpiryHours } from "./messageExpiry";

export function ExpiryChoices({
  value,
  onChange,
  disabled,
}: {
  value: MessageExpiryHours | null;
  onChange: (value: MessageExpiryHours | null) => void;
  disabled?: boolean;
}) {
  return (
    <div
      className="message-expiry-options"
      role="group"
      aria-label={t("messageActions.expiry")}
    >
      {([null, 1, 24] as const).map((hours) => (
        <button
          key={hours ?? "none"}
          type="button"
          className="secondary"
          disabled={disabled}
          aria-pressed={value === hours}
          onClick={() => onChange(hours)}
        >
          {hours === null
            ? t("messageActions.noExpiry")
            : t("composer.expiryHours", { hours })}
        </button>
      ))}
    </div>
  );
}
