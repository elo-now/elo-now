import { useEffect } from "react";
import { invoke, isTauri } from "../diagnosticInvoke";
import { readNotificationSound } from "../notificationSounds";

type Options = {
  identity: string;
  ringKey?: string;
  /** Invitation expiry in Unix seconds. */
  expiresAt?: number;
  nativePresented?: boolean;
  answering?: boolean;
  activeCall: boolean;
};

/** One alert owner, independent of ordinary message-notification audio. */
export function useIncomingRingtone({
  identity,
  ringKey,
  expiresAt,
  nativePresented,
  answering,
  activeCall,
}: Options) {
  useEffect(() => {
    if (!identity || !ringKey || nativePresented || answering) return;
    const mobile = /Android|iPhone|iPad|iPod/.test(navigator.userAgent);
    const native = mobile && isTauri();
    let disposed = false;
    let token: string | undefined;
    let revision = 0;
    let heartbeat: ReturnType<typeof setInterval> | undefined;
    let player: HTMLAudioElement | undefined;
    let nextDesktopSound = 0;
    let pending: string | undefined;
    let leaseExpires = 0;
    const eligible = () =>
      !disposed &&
      document.visibilityState === "visible" &&
      (mobile || document.hasFocus()) &&
      (!expiresAt || Date.now() < expiresAt * 1000);
    const request = (id: string, active: boolean) =>
      invoke("native_call_ringtone", {
        identity,
        request: {
          token: id,
          revision: ++revision,
          active,
          expires: active
            ? Math.min(Date.now() + 4000, (expiresAt ?? Infinity) * 1000)
            : 0,
        },
      });
    const stop = () => {
      if (heartbeat) clearInterval(heartbeat);
      heartbeat = undefined;
      player?.pause();
      player = undefined;
      const current = token;
      token = undefined;
      leaseExpires = 0;
      if (native && current) void request(current, false).catch(() => {});
    };
    const pulse = () => {
      if (!eligible()) {
        stop();
        return;
      }
      // A stalled WebView may outlive its native lease. Retired tokens cannot
      // restart audio, so renew ownership as well as the expiry after a pause.
      if (native && token && leaseExpires && Date.now() >= leaseExpires) {
        void request(token, false).catch(() => {});
        token = crypto.randomUUID();
        leaseExpires = 0;
      }
      const current = token;
      if (!current) return;
      if (native) {
        if (pending === current) return;
        pending = current;
        leaseExpires = Math.min(
          Date.now() + 4000,
          (expiresAt ?? Infinity) * 1000,
        );
        void request(current, true)
          .catch(() => {})
          .finally(() => {
            if (pending === current) pending = undefined;
          });
      } else if (!mobile && Date.now() >= nextDesktopSound) {
        nextDesktopSound = Date.now() + 8000;
        player?.pause();
        const choice = readNotificationSound();
        if (choice === "none") {
          player = undefined;
          return;
        }
        const audio = new Audio(`/sounds/${choice}.wav`);
        audio.volume = activeCall ? 0.25 : 0.75;
        player = audio;
        void audio
          .play()
          .then(() => {
            if (token !== current || !eligible() || player !== audio)
              audio.pause();
          })
          .catch(() => {});
      }
    };
    const refresh = () => {
      if (!eligible()) {
        stop();
        return;
      }
      if (token) return;
      token = crypto.randomUUID();
      nextDesktopSound = 0;
      pulse();
      heartbeat = setInterval(pulse, native ? 1500 : 250);
    };
    const hide = () => stop();
    const focus = () => {
      stop();
      refresh();
    };
    document.addEventListener("visibilitychange", refresh);
    window.addEventListener("focus", focus);
    window.addEventListener("blur", hide);
    window.addEventListener("pageshow", refresh);
    window.addEventListener("pagehide", hide);
    refresh();
    return () => {
      disposed = true;
      stop();
      document.removeEventListener("visibilitychange", refresh);
      window.removeEventListener("focus", focus);
      window.removeEventListener("blur", hide);
      window.removeEventListener("pageshow", refresh);
      window.removeEventListener("pagehide", hide);
    };
  }, [identity, ringKey, expiresAt, nativePresented, answering, activeCall]);
}
