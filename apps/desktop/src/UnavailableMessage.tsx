import { useEffect, useRef, useState } from "react";
import { t } from "./i18n";

const REQUEST_TIMEOUT_MS = 55_000;

export function UnavailableMessage({
  disabled,
  onRequest,
  onUnavailable,
}: {
  disabled: boolean;
  onRequest: () => Promise<void>;
  onUnavailable: () => void;
}) {
  const [requesting, setRequesting] = useState(false);
  const timer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);
  const mounted = useRef(true);
  useEffect(
    () => () => {
      mounted.current = false;
      clearTimeout(timer.current);
    },
    [],
  );
  const request = async () => {
    if (disabled || requesting) return;
    setRequesting(true);
    try {
      await onRequest();
      if (!mounted.current) return;
      timer.current = setTimeout(() => {
        if (!mounted.current) return;
        setRequesting(false);
        onUnavailable();
      }, REQUEST_TIMEOUT_MS);
    } catch {
      if (!mounted.current) return;
      setRequesting(false);
      onUnavailable();
    }
  };
  return (
    <div
      className="unavailable-message"
      data-requesting={requesting || undefined}
    >
      <div
        className="unavailable-message-action"
        aria-hidden={requesting || undefined}
      >
        <span>{t("messageUnavailable.title")}</span>
        <button
          type="button"
          aria-label={t("messageUnavailable.requestLabel")}
          disabled={disabled || requesting}
          onClick={() => void request()}
        >
          {t("messageUnavailable.request")}
        </button>
      </div>
      <span
        className="unavailable-message-status"
        role="status"
        aria-live="polite"
        aria-hidden={!requesting || undefined}
      >
        {t("messageUnavailable.requesting")}
      </span>
    </div>
  );
}
