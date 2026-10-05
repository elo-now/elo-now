import { t } from "./i18n";
import { Icon } from "./Icon";
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
            aria-label={
              hours === undefined ? t("composer.noExpiry") : undefined
            }
            title={hours === undefined ? t("composer.noExpiry") : undefined}
            disabled={disabled}
            // Cancel mousedown, not pointerdown: iOS can otherwise blur the
            // textarea while suppressing the mousedown that preserves focus.
            // https://bugs.webkit.org/show_bug.cgi?id=322721
            onMouseDown={(event) => event.preventDefault()}
            onClick={(event) => {
              // Refocus synchronously within the tap so iOS keeps its keyboard.
              // Keyboard/assistive activation must retain focus on the button.
              if (event.detail > 0) {
                const input =
                  event.currentTarget.form?.querySelector<HTMLTextAreaElement>(
                    "textarea",
                  );
                // WebKit can reveal the caret again even with preventScroll.
                // Keep an already-focused composer in place when changing time.
                if (input && document.activeElement !== input)
                  input.focus({ preventScroll: true });
              }
              onChange(value === hours ? undefined : hours);
            }}
          >
            {hours === undefined ? (
              <span className="composer-expiry-symbol">
                <Icon name="infinity" />
              </span>
            ) : (
              t("composer.expiryHours", { hours })
            )}
          </button>
        ))}
      </div>
    </div>
  );
}
