import { useEffect, useRef } from "react";
import { t } from "./i18n";

const offerKey = "elo.notificationOffer.v1";

export function notificationOfferHandled(): boolean {
  return localStorage.getItem(offerKey) === "handled";
}

export function markNotificationOfferHandled(): void {
  localStorage.setItem(offerKey, "handled");
}

export function shouldOfferNotifications(
  ready: boolean,
  status: { available: boolean; enabled: boolean },
  handled: boolean,
): boolean {
  return ready && status.available && !status.enabled && !handled;
}

export function NotificationOffer({
  onAccept,
  onDecline,
}: {
  onAccept: () => void;
  onDecline: () => void;
}) {
  const dialog = useRef<HTMLDialogElement>(null);
  useEffect(() => {
    const element = dialog.current;
    element?.showModal();
    return () => element?.close();
  }, []);
  return (
    <dialog
      ref={dialog}
      className="dialog notification-offer-dialog"
      aria-labelledby="notification-offer-title"
      onCancel={(event) => {
        event.preventDefault();
        onDecline();
      }}
    >
      <h2 id="notification-offer-title">{t("notifications.offerTitle")}</h2>
      <p>{t("notifications.offerHelp")}</p>
      <div className="dialog-buttons">
        <button type="button" className="secondary" onClick={onDecline}>
          {t("notifications.notNow")}
        </button>
        <button type="button" onClick={onAccept}>
          {t("notifications.enable")}
        </button>
      </div>
    </dialog>
  );
}
