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
      {requesting ? (
        <strong role="status" aria-live="polite">
          {t("messageUnavailable.requesting")}
        </strong>
      ) : (
        <>
          <strong>{t("messageUnavailable.title")}</strong>
          <button
            type="button"
            className="secondary"
            disabled={disabled}
            onClick={() => void request()}
          >
            {t("messageUnavailable.request")}
          </button>
        </>
      )}
    </div>
  );
}
