import { useState, type ReactNode } from "react";
import { t } from "./i18n";
import { useToast } from "./Toast";

/** The same recovery material layout during registration and in settings. */
export function RecoveryCodePanel({
  value,
  onChange,
  disabled = false,
  children,
}: {
  value: string;
  onChange?: (value: string) => void;
  disabled?: boolean;
  children: ReactNode;
}) {
  const [copying, setCopying] = useState(false);
  const { notify, reportError } = useToast();
  return (
    <div className="recovery-code-panel">
      <textarea
        aria-label={t("onboarding.code")}
        value={value}
        onChange={
          onChange ? (event) => onChange(event.target.value) : undefined
        }
        readOnly={!onChange}
        placeholder={onChange ? t("recover.codePlaceholder") : undefined}
        rows={6}
        maxLength={2048}
        spellCheck={false}
        autoCapitalize="none"
        autoCorrect="off"
        autoComplete="off"
      />
      {!onChange && (
        <button
          type="button"
          className="secondary"
          disabled={disabled || copying || !value.trim()}
          onClick={() => {
            setCopying(true);
            void (async () => {
              try {
                await navigator.clipboard.writeText(value);
                notify(t("onboarding.codeCopied"));
              } catch (error) {
                reportError(error);
              } finally {
                setCopying(false);
              }
            })();
          }}
        >
          {t("onboarding.copyCode")}
        </button>
      )}
      {children}
    </div>
  );
}
