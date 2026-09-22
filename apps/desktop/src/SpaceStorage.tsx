import { useEffect, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { ActionDialog } from "./ActionDialog";
import { locale, t } from "./i18n";
import type { SpaceSummary } from "./model";
import { useToast } from "./Toast";

type Storage = {
  used_bytes: number;
  quota_bytes: number;
  before_ms: number;
  removable_bytes: number;
  removable_copies: number;
};
const size = (bytes: number) => {
  const gib = bytes >= 1024 ** 3;
  return `${new Intl.NumberFormat(locale, { maximumFractionDigits: 2 }).format(bytes / 1024 ** (gib ? 3 : 2))} ${gib ? "GiB" : "MiB"}`;
};

export function SpaceStorage({
  identity,
  space,
}: {
  identity: string;
  space: SpaceSummary;
}) {
  const [days, setDays] = useState("100");
  const [storage, setStorage] = useState<Storage>();
  const [preview, setPreview] = useState<{ storage: Storage; days: number }>();
  const [busy, setBusy] = useState(false);
  const [clearing, setClearing] = useState(false);
  const [confirm, setConfirm] = useState(false);
  const mounted = useRef(false);
  const pending = useRef(false);
  const { reportError, notify, onInvalid } = useToast();
  const request = async (op: string, body: object) =>
    (
      await invoke<{ result: Storage }>("operate", {
        request: { op, id: space.id, expected_identity: identity, body },
      })
    ).result;

  const inspect = async (showPreview: boolean) => {
    if (pending.current) return;
    const number = Number(days);
    if (!Number.isInteger(number) || number < 1 || number > 36500) return;
    pending.current = true;
    setBusy(true);
    setPreview(undefined);
    try {
      const result = await request("space_storage", { days: number });
      if (!mounted.current) return;
      setStorage(result);
      if (showPreview) setPreview({ storage: result, days: number });
    } catch (error) {
      if (mounted.current) reportError(error);
    } finally {
      pending.current = false;
      if (mounted.current) setBusy(false);
    }
  };
  useEffect(() => {
    mounted.current = true;
    void inspect(false);
    return () => {
      mounted.current = false;
    };
  }, []);

  const clear = async () => {
    if (!preview || pending.current) return;
    pending.current = true;
    setBusy(true);
    setClearing(true);
    try {
      const result = await request("space_storage_prune", {
        days: preview.days,
        before_ms: preview.storage.before_ms,
        confirmed: true,
      });
      if (!mounted.current) return;
      setConfirm(false);
      setPreview(undefined);
      notify(
        t("spaces.storage.cleared", { size: size(result.removable_bytes) }),
      );
      const refreshed = await request("space_storage", { days: Number(days) });
      if (mounted.current) setStorage(refreshed);
    } catch (error) {
      if (mounted.current) reportError(error);
    } finally {
      pending.current = false;
      if (mounted.current) {
        setBusy(false);
        setClearing(false);
      }
    }
  };
  const percent = storage
    ? Math.min(
        100,
        Math.round((storage.used_bytes / storage.quota_bytes) * 100),
      )
    : 0;
  return (
    <>
      <section className="space-details-section space-storage" aria-busy={busy}>
        <h3>{t("spaces.storage.title")}</h3>
        {storage && (
          <div className="space-storage-usage">
            <p>
              {t("spaces.storage.usage", {
                used: size(storage.used_bytes),
                quota: size(storage.quota_bytes),
              })}
            </p>
            <progress
              value={storage.used_bytes}
              max={storage.quota_bytes}
              aria-label={t("spaces.storage.percent", { percent })}
            />
          </div>
        )}
        <p className="muted">{t("spaces.storage.help")}</p>
        <p className="caption muted">
          {t("spaces.messageLifetime.details", {
            lifetime: t(
              `spaces.messageLifetime.${space.message_lifetime_seconds ?? 86_400}` as "spaces.messageLifetime.21600",
            ),
          })}
        </p>
      </section>
      {!space.message_lifetime_seconds && (
        <section
          className="space-details-section space-maintenance"
          aria-busy={busy}
        >
          <h3>{t("spaces.maintenance")}</h3>
          <form
            onSubmit={(event) => {
              event.preventDefault();
              void inspect(true);
            }}
            onInvalid={onInvalid}
          >
            <div className="space-form-field">
              <label htmlFor="space-storage-days">
                {t("spaces.storage.days")}
              </label>
              <input
                id="space-storage-days"
                type="number"
                inputMode="numeric"
                min="1"
                max="36500"
                step="1"
                required
                value={days}
                disabled={busy}
                onChange={(event) => {
                  setDays(event.target.value);
                  setPreview(undefined);
                }}
              />
              <small className="muted">{t("spaces.storage.ageHelp")}</small>
            </div>
            <button disabled={busy} type="submit">
              {t(busy ? "spaces.storage.previewing" : "spaces.storage.preview")}
            </button>
          </form>
          {preview && (
            <div className="space-storage-preview" role="status">
              <p className="muted">
                {t(
                  preview.storage.removable_copies
                    ? "spaces.storage.available"
                    : "spaces.storage.empty",
                  { size: size(preview.storage.removable_bytes) },
                )}
              </p>
              {!!preview.storage.removable_copies && (
                <button
                  className="secondary danger"
                  disabled={busy}
                  onClick={() => setConfirm(true)}
                >
                  {t("spaces.storage.clear")}
                </button>
              )}
            </div>
          )}
          {confirm && preview && (
            <ActionDialog
              title={t("spaces.storage.confirmTitle")}
              onClose={() => {
                if (!clearing) setConfirm(false);
              }}
            >
              <p>
                {t("spaces.storage.confirm", {
                  days: preview.days,
                  size: size(preview.storage.removable_bytes),
                })}
              </p>
              <div className="space-choice">
                <button
                  className="secondary"
                  disabled={clearing}
                  onClick={() => setConfirm(false)}
                >
                  {t("dialog.cancel")}
                </button>
                <button
                  className="danger"
                  disabled={clearing}
                  onClick={() => void clear()}
                >
                  {t(
                    clearing
                      ? "spaces.storage.clearing"
                      : "spaces.storage.clear",
                  )}
                </button>
              </div>
            </ActionDialog>
          )}
        </section>
      )}
    </>
  );
}
