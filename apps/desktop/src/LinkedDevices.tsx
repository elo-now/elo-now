import { useEffect, useState } from "react";
import { ActionDialog } from "./ActionDialog";
import { profileTask } from "./ProfileRecovery";
import { useToast } from "./Toast";
import { t } from "./i18n";
import { Icon } from "./Icon";

type Device = {
  id: string;
  credential: string;
  current: boolean;
  name?: string;
};
type Devices = {
  devices: Device[];
  pending: number;
  unavailable: number;
  can_link?: boolean;
};

export function LinkedDevices({
  extraDevice,
  onDeleted,
  onCanLink,
}: {
  extraDevice?: Device | null;
  onDeleted?: () => void;
  onCanLink?: (allowed: boolean) => void;
} = {}) {
  const [data, setData] = useState<Devices | null>(null);
  const [selected, setSelected] = useState<Device | null>(null);
  const [busy, setBusy] = useState(false);
  const [failed, setFailed] = useState(false);
  const [retry, setRetry] = useState(0);
  const { reportError } = useToast();
  useEffect(() => {
    if (busy) return;
    let live = true;
    let timer: ReturnType<typeof setTimeout> | undefined;
    let attempts = 0;
    const refresh = async () => {
      try {
        const value = await profileTask<Devices>("device_list");
        if (!live) return;
        setData(value);
        setFailed(false);
        onCanLink?.(value.can_link !== false);
        if (
          extraDevice &&
          !value.devices.some(
            (device) => device.credential === extraDevice.credential,
          ) &&
          ++attempts < 20
        ) {
          timer = setTimeout(() => void refresh(), 3000);
          return;
        }
        if (value.pending > 0) timer = setTimeout(() => void refresh(), 15000);
      } catch (error) {
        if (live) {
          setFailed(true);
          reportError(error);
        }
      }
    };
    void refresh();
    return () => {
      live = false;
      clearTimeout(timer);
    };
  }, [busy, retry, extraDevice, onCanLink]);
  const devices = data?.devices ?? [];
  const visibleDevices =
    extraDevice &&
    !devices.some((device) => device.credential === extraDevice.credential)
      ? [...devices, extraDevice]
      : devices;
  const close = () => {
    if (!busy) {
      setSelected(null);
    }
  };
  return (
    <section className="linked-devices">
      {!data && !failed && (
        <p className="page-description device-list-loading" role="status">
          {t("devices.loading")}
        </p>
      )}
      {failed && (
        <p className="error" role="status">
          {t("devices.loadFailed")}
        </p>
      )}
      {failed && (
        <button
          className="secondary"
          onClick={() => {
            setFailed(false);
            setRetry((value) => value + 1);
          }}
        >
          {t("devices.retry")}
        </button>
      )}
      {data && (
        <>
          {data.pending > 0 && (
            <p className="error" role="status">
              {t("devices.pendingRevocation")}
            </p>
          )}
          {visibleDevices.length === 0 && data.unavailable === 0 && (
            <p className="empty">{t("devices.none")}</p>
          )}
          {visibleDevices.map((device) => (
            <div className="linked-device-row" key={device.id}>
              <span title={device.id}>
                {device.name ||
                  t("devices.deviceName", {
                    fingerprint: device.id.slice(0, 16),
                  })}
                <small>
                  {t(
                    device.current ? "devices.thisDevice" : "devices.accepted",
                  )}
                </small>
              </span>
              {!device.current && (
                <button
                  type="button"
                  className="icon"
                  disabled={busy}
                  aria-label={t("devices.delete")}
                  title={t("devices.delete")}
                  onClick={() => setSelected(device)}
                >
                  <Icon name="delete" />
                </button>
              )}
            </div>
          ))}
        </>
      )}
      {selected && (
        <ActionDialog
          title={t("devices.revokeTitle")}
          onClose={close}
          className="device-revoke-dialog"
        >
          <form
            onSubmit={(event) => {
              event.preventDefault();
              setBusy(true);
              void profileTask<Devices>("device_revoke", {
                credential: selected.credential,
                confirmed: true,
              })
                .then((value) => {
                  setData(value);
                  setSelected(null);
                  onDeleted?.();
                })
                .catch(reportError)
                .finally(() => setBusy(false));
            }}
          >
            <p>{t("devices.revokeHelp")}</p>
            <div className="space-choice">
              <button
                className="secondary"
                type="button"
                disabled={busy}
                onClick={close}
              >
                {t("dialog.cancel")}
              </button>
              <button className="danger" disabled={busy}>
                {t(busy ? "sync.busy" : "devices.delete")}
              </button>
            </div>
          </form>
        </ActionDialog>
      )}
    </section>
  );
}
