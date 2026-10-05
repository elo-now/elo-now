import { useEffect, useId, useState } from "react";
import { t } from "./i18n";
import {
  notificationSounds,
  parseNotificationSound,
  playNotificationSound,
  readNotificationSound,
  saveNotificationSound,
  stopNotificationSound,
} from "./notificationSounds";

const labels = {
  default: "notifications.sound.default",
  soft: "notifications.sound.soft",
  "elo-male": "notifications.sound.eloMale",
  "elo-female": "notifications.sound.eloFemale",
  none: "notifications.sound.none",
} as const;

export function NotificationSoundSettings({
  nativeSupport,
}: {
  nativeSupport?: "supported" | "server_dependent" | "system_default";
}) {
  const [sound, setSound] = useState(readNotificationSound);
  const [failed, setFailed] = useState(false);
  const help = useId();
  useEffect(() => stopNotificationSound, []);
  return (
    <div className="notification-sound-settings">
      <label>
        <span>{t("notifications.sound.label")}</span>
        <select
          value={sound}
          aria-describedby={help}
          onChange={(event) => {
            const next = parseNotificationSound(event.target.value);
            saveNotificationSound(next);
            setSound(next);
            setFailed(false);
            void playNotificationSound(next).catch(() => setFailed(true));
          }}
        >
          {notificationSounds.map((value) => (
            <option key={value} value={value}>
              {t(labels[value])}
            </option>
          ))}
        </select>
      </label>
      <p id={help} className="muted" role="status">
        {t(
          failed
            ? "notifications.sound.previewFailed"
            : "notifications.sound.help",
        )}
      </p>
      {nativeSupport && nativeSupport !== "supported" && (
        <p className="muted">
          {t(
            nativeSupport === "system_default"
              ? "notifications.sound.systemDefault"
              : "notifications.sound.serverDependent",
          )}
        </p>
      )}
    </div>
  );
}
