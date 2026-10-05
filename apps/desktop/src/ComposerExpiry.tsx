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
  return (
    <div
      className="composer-expiry"
      role="group"
      aria-label={t("composer.deleteAfter")}
    >
      <span>{t("composer.deleteAfter")}</span>
      <div className="composer-expiry-options">
        {([undefined, 1, 24] as const).map((hours) => (
          <button
            key={hours ?? "none"}
            type="button"
            aria-pressed={value === hours}
            aria-label={hours === undefined ? t("composer.noExpiry") : undefined}
            title={hours === undefined ? t("composer.noExpiry") : undefined}
            disabled={disabled}
            // Cover both pointer events and WebKit's compatibility mouse events.
            onPointerDown={(event) => event.preventDefault()}
            onMouseDown={(event) => event.preventDefault()}
            onClick={(event) => {
              // Refocus synchronously within the tap so iOS keeps its keyboard.
              // Keyboard/assistive activation must retain focus on the button.
              if (event.detail > 0)
                event.currentTarget.form
                  ?.querySelector<HTMLTextAreaElement>("textarea")
                  ?.focus({ preventScroll: true });
              onChange(value === hours ? undefined : hours);
            }}
          >
            {hours === undefined
              ? t("composer.expiryNone")
              : t("composer.expiryHours", { hours })}
          </button>
        ))}
      </div>
    </div>
  );
}
