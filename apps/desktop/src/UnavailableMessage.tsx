import { useEffect, useRef, useState } from "react";
import { t } from "./i18n";
import { RETRIEVE_WINDOW_MS } from "./liveSync";

export function UnavailableMessage({
  active = true,
  disabled,
  onRequest,
  onUnavailable,
}: {
  active?: boolean;
  disabled: boolean;
  onRequest: () => Promise<void | (() => void)>;
  onUnavailable: () => void;
}) {
  const [requesting, setRequesting] = useState(false);
  const timer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);
  const stopRequest = useRef<(() => void) | undefined>(undefined);
  const generation = useRef(0);
  const stop = () => {
    clearTimeout(timer.current);
    timer.current = undefined;
    stopRequest.current?.();
    stopRequest.current = undefined;
  };
  useEffect(() => {
    if (!active) setRequesting(false);
    return () => {
      generation.current++;
      stop();
    };
  }, [active]);
  const request = async () => {
    if (!active || disabled || timer.current !== undefined) return;
    const current = ++generation.current;
    setRequesting(true);
    timer.current = setTimeout(() => {
      if (generation.current !== current) return;
      generation.current++;
      stop();
      setRequesting(false);
      onUnavailable();
    }, RETRIEVE_WINDOW_MS);
    try {
      const release = await onRequest();
      if (generation.current !== current) {
        release?.();
        return;
      }
      stopRequest.current = release || undefined;
    } catch {
      if (generation.current !== current) return;
      generation.current++;
      stop();
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
          disabled={!active || disabled || requesting}
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
