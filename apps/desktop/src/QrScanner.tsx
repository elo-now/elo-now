import { useLayoutEffect, useRef } from "react";
import { createPortal } from "react-dom";
import { ScreenHeader } from "./ScreenHeader";
import { t } from "./i18n";
import "./invitations.css";

/** Keep camera controls above onboarding pages and any already open dialog. */
export function QrScanner({
  title = t("invite.scan"),
  hint = t("invite.scanHint"),
  onCancel,
}: {
  title?: string;
  hint?: string;
  onCancel: () => void;
}) {
  const dialog = useRef<HTMLDialogElement>(null);
  useLayoutEffect(() => {
    const node = dialog.current!;
    const opener = document.activeElement;
    document.documentElement.classList.add("elo-scanning");
    node.showModal();
    return () => {
      node.close();
      document.documentElement.classList.remove("elo-scanning");
      if (opener instanceof HTMLElement && opener.isConnected)
        opener.focus({ preventScroll: true });
    };
  }, []);
  return createPortal(
    <dialog
      ref={dialog}
      className="qr-scanner"
      aria-label={title}
      onCancel={(event) => {
        event.preventDefault();
        event.stopPropagation();
        onCancel();
      }}
    >
      <ScreenHeader title={title} onBack={onCancel} />
      <div className="scan-window" aria-label={t("invite.camera")}>
        <span />
      </div>
      <div className="scan-controls">
        <p aria-live="polite">{hint}</p>
        <button type="button" className="secondary" onClick={onCancel}>
          {t("invite.cancel")}
        </button>
      </div>
    </dialog>,
    document.body,
  );
}
