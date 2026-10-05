import { useEffect, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { ActionDialog } from "./ActionDialog";
import type { SpaceSummary } from "./model";
import type { SpaceManagement } from "./SpaceRoles";
import { formatFileSize, locale, t } from "./i18n";
import { useToast } from "./Toast";
import {
  AttachmentStorageForm,
  saveAttachmentStorage,
  saveAttachmentRetention,
  emptyAttachmentStorage,
  type AttachmentStorageStatus,
} from "./AttachmentStorageForm";

type AttachmentSettings = NonNullable<SpaceManagement["attachments"]>;
type Cleanup = {
  files: number;
  bytes: number;
  before_ms: number;
  days: number;
};

const size = (bytes: number) =>
  `${new Intl.NumberFormat(locale, { maximumFractionDigits: 2 }).format(bytes / 1024 ** 2)} MiB`;

export function SpaceAttachments({
  identity,
  space,
  value,
  storageAvailable = false,
  onChanged,
}: {
  identity: string;
  space: SpaceSummary;
  value: AttachmentSettings;
  storageAvailable?: boolean;
  onChanged: () => Promise<void>;
}) {
  const [days, setDays] = useState("100");
  const [preview, setPreview] = useState<Cleanup>();
  const [confirm, setConfirm] = useState(false);
  const [busy, setBusy] = useState(false);
  const [storageStatus, setStorageStatus] = useState<AttachmentStorageStatus>();
  const [storageRefresh, setStorageRefresh] = useState(0);
  const { reportError, notify } = useToast();
  const request = async <T,>(op: string, body: object) =>
    (
      await invoke<{ result: T }>("operate", {
        request: { op, id: space.id, expected_identity: identity, body },
      })
    ).result;
  const run = async (operation: () => Promise<void>) => {
    if (busy) return;
    setBusy(true);
    try {
      await operation();
    } catch (error) {
      reportError(error);
    } finally {
      setBusy(false);
    }
  };
  const used = storageAvailable
    ? (storageStatus?.used_bytes ?? 0)
    : value.used_bytes + value.reserved_bytes;
  const quota = storageAvailable
    ? (storageStatus?.max_space_bytes ?? 0)
    : value.policy.max_space_bytes;
  const percent = Math.min(
    100,
    quota > 0 ? Math.round((used / quota) * 100) : 0,
  );
  return (
    <section className="space-details-section space-storage" aria-busy={busy}>
      <h3>{t("spaces.attachments.title")}</h3>
      {storageAvailable && space.owner && (
        <SpaceAttachmentStorage
          identity={identity}
          space={space.id}
          onChanged={onChanged}
          onStatus={setStorageStatus}
          refresh={storageRefresh}
        />
      )}
      {(!storageAvailable || storageStatus?.available) && (
        <>
          <div className="space-storage-usage">
            <p>
              {t("spaces.attachments.usage", {
                used: size(used),
                quota: size(quota),
              })}
            </p>
            <progress
              value={used}
              max={quota}
              aria-label={t("spaces.storage.percent", { percent })}
            />
          </div>
          <p className="caption muted">
            {storageAvailable && storageStatus
              ? t("spaces.attachments.storageLimits", {
                  fileSize: formatFileSize(storageStatus.max_file_bytes),
                  spaceSize: formatFileSize(storageStatus.max_space_bytes),
                })
              : t("spaces.attachments.limits")}
          </p>
        </>
      )}
      <div className="space-attachment-controls">
        <div className="space-form-field">
          <label htmlFor="space-attachment-retention">
            {t("spaces.attachments.retention")}
          </label>
          <select
            id="space-attachment-retention"
            value={
              storageAvailable
                ? storageStatus?.configured &&
                  storageStatus.retention_hours == null
                  ? ""
                  : (storageStatus?.retention_hours ?? 1)
                : value.policy.retention.hours
            }
            disabled={
              busy ||
              (storageAvailable && (!storageStatus?.configured || !space.owner))
            }
            onChange={(event) => {
              const selected = event.target.value;
              setPreview(undefined);
              void run(async () => {
                if (storageAvailable) {
                  if (!storageStatus) return;
                  try {
                    const next = await saveAttachmentRetention(
                      Number(selected),
                      storageStatus,
                      (op, body = {}) =>
                        request<AttachmentStorageStatus>(op, body),
                    );
                    setStorageStatus(next);
                  } finally {
                    // Reload both policy and provider editors after a CAS change
                    // or conflict; the user's provider draft remains in memory.
                    setStorageRefresh((current) => current + 1);
                  }
                } else {
                  await request("space_attachment_retention", {
                    hours: Number(selected),
                  });
                }
                await onChanged();
                notify(t("spaces.attachments.retentionSaved"));
              });
            }}
          >
            {storageAvailable &&
              storageStatus?.configured &&
              storageStatus.retention_hours == null && (
                <option value="" disabled>
                  {t("spaces.attachments.chooseRetention")}
                </option>
              )}
            {[1, 12, 24].map((option) => (
              <option key={option} value={option}>
                {option === 1
                  ? t("spaces.attachments.oneHour")
                  : t("spaces.attachments.hours", { hours: option })}
              </option>
            ))}
          </select>
        </div>
        {!storageAvailable && (
          <>
            <div className="space-form-field">
              <label htmlFor="space-attachment-cleanup-days">
                {t("spaces.attachments.cleanupAge")}
              </label>
              <input
                id="space-attachment-cleanup-days"
                type="number"
                min="1"
                max="36500"
                step="1"
                value={days}
                disabled={busy}
                onChange={(event) => {
                  setDays(event.target.value);
                  setPreview(undefined);
                }}
              />
            </div>
            <div className="space-attachment-cleanup">
              {preview?.files === 0 && (
                <p className="space-attachment-cleanup-status" role="status">
                  {t("spaces.attachments.nothingToClean")}
                </p>
              )}
              <button
                type="button"
                className="secondary"
                disabled={
                  busy ||
                  !Number.isInteger(Number(days)) ||
                  Number(days) < 1 ||
                  Number(days) > 36500
                }
                onClick={() =>
                  void run(async () => {
                    const result = await request<Cleanup>(
                      "space_attachment_cleanup_preview",
                      { days: Number(days) },
                    );
                    setPreview(result);
                    if (result.files) setConfirm(true);
                  })
                }
              >
                {t("spaces.attachments.preview")}
              </button>
            </div>
          </>
        )}
      </div>
      {!storageAvailable && confirm && preview && (
        <ActionDialog
          title={t("spaces.attachments.cleanupTitle")}
          onClose={() => {
            if (!busy) setConfirm(false);
          }}
        >
          <p>
            {t("spaces.attachments.cleanupConfirm", {
              files: preview.files,
              size: size(preview.bytes),
              days: preview.days,
            })}
          </p>
          <div className="space-choice">
            <button
              type="button"
              className="secondary"
              disabled={busy}
              onClick={() => setConfirm(false)}
            >
              {t("dialog.cancel")}
            </button>
            <button
              type="button"
              className="danger"
              disabled={busy}
              onClick={() =>
                void run(async () => {
                  await request("space_attachment_cleanup", {
                    before_ms: preview.before_ms,
                    confirmed: true,
                  });
                  setConfirm(false);
                  setPreview(undefined);
                  await onChanged();
                  notify(t("spaces.attachments.cleanupScheduled"));
                })
              }
            >
              {t("spaces.attachments.clean")}
            </button>
          </div>
        </ActionDialog>
      )}
    </section>
  );
}

function SpaceAttachmentStorage({
  identity,
  space,
  onChanged,
  onStatus,
  refresh,
}: {
  identity: string;
  space: string;
  onChanged: () => Promise<void>;
  onStatus: (status: AttachmentStorageStatus) => void;
  refresh: number;
}) {
  const [status, setStatus] = useState<AttachmentStorageStatus>();
  const [draft, setDraft] = useState(emptyAttachmentStorage);
  const [editing, setEditing] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<"load" | "save">();
  const [busy, setBusy] = useState(false);
  const [confirm, setConfirm] = useState(false);
  const alive = useRef(true);
  const pending = useRef(false);
  const { notify, onInvalid } = useToast();
  const request = async (op: string, body = {}) =>
    (
      await invoke<{ result: AttachmentStorageStatus }>("operate", {
        request: { op, id: space, expected_identity: identity, body },
      })
    ).result;
  const load = async () => {
    setLoading(true);
    try {
      const next = await request("space_external_storage_status");
      if (!alive.current) return;
      setStatus(next);
      onStatus(next);
      setError(undefined);
    } catch {
      if (alive.current) setError("load");
    } finally {
      if (alive.current) setLoading(false);
    }
  };
  useEffect(() => {
    alive.current = true;
    void load();
    return () => {
      alive.current = false;
    };
  }, [identity, space, refresh]);

  const save = async () => {
    if (pending.current || !status?.available) return;
    pending.current = true;
    setBusy(true);
    setError(undefined);
    try {
      const next = await saveAttachmentStorage(
        draft,
        status.revision,
        request,
        status.retention_hours ?? 1,
      );
      if (!alive.current) return;
      setStatus(next);
      onStatus(next);
      setDraft(emptyAttachmentStorage());
      setEditing(false);
      setConfirm(false);
      await onChanged();
      if (alive.current)
        notify(
          t(
            next.enabled
              ? "spaces.attachments.saved"
              : "spaces.attachments.disabled",
          ),
        );
    } catch {
      if (alive.current) {
        setConfirm(false);
        setError("save");
        // Refresh the revision for an explicit retry without reflecting any secrets.
        await request("space_external_storage_status")
          .then((next) => {
            if (alive.current) {
              setStatus(next);
              onStatus(next);
            }
          })
          .catch(() => {});
      }
    } finally {
      pending.current = false;
      if (alive.current) setBusy(false);
    }
  };
  if (status && !status.available) return null;
  return (
    <div
      className="space-attachment-controls space-attachment-configuration"
      aria-busy={busy || loading}
    >
      {loading && (
        <p className="caption muted" role="status">
          {t("spaces.attachments.loading")}
        </p>
      )}
      {error && (
        <p className="caption muted" role="alert">
          {t(
            error === "load"
              ? "spaces.attachments.loadFailed"
              : "spaces.attachments.saveFailed",
          )}
        </p>
      )}
      {!status && error === "load" && (
        <button
          type="button"
          className="secondary"
          disabled={loading}
          onClick={() => void load()}
        >
          {t("spaces.attachments.retry")}
        </button>
      )}
      {status && !loading && (
        <>
          {status.enabled && !editing ? (
            <>
              <p className="caption muted">
                {t("spaces.attachments.connected", {
                  provider: t(
                    status.provider === "s3_compatible"
                      ? "spaces.attachments.s3"
                      : "spaces.attachments.mega",
                  ),
                })}
              </p>
              <button
                type="button"
                className="secondary"
                disabled={busy}
                onClick={() => {
                  setDraft(
                    emptyAttachmentStorage(true, status.provider ?? undefined),
                  );
                  setEditing(true);
                  setError(undefined);
                }}
              >
                {t("spaces.attachments.change")}
              </button>
            </>
          ) : (
            <form
              className="attachment-storage-form"
              onInvalid={onInvalid}
              onSubmit={(event) => {
                event.preventDefault();
                if (pending.current) return;
                if (status.configured || status.enabled) setConfirm(true);
                else void save();
              }}
            >
              <AttachmentStorageForm
                value={draft}
                onChange={setDraft}
                disabled={busy}
              />
              {(draft.enabled || status.enabled) && (
                <button type="submit" disabled={busy} aria-busy={busy}>
                  {t(
                    busy
                      ? "spaces.attachments.saving"
                      : draft.enabled
                        ? "spaces.attachments.save"
                        : "spaces.attachments.disable",
                  )}
                </button>
              )}
              {editing && (
                <button
                  type="button"
                  className="secondary"
                  disabled={busy}
                  onClick={() => {
                    setDraft(emptyAttachmentStorage());
                    setEditing(false);
                    setError(undefined);
                  }}
                >
                  {t("dialog.cancel")}
                </button>
              )}
            </form>
          )}
        </>
      )}
      {confirm && (
        <ActionDialog
          title={t(
            draft.enabled
              ? "spaces.attachments.replaceTitle"
              : "spaces.attachments.disableTitle",
          )}
          onClose={() => {
            if (!busy) setConfirm(false);
          }}
        >
          <p className="muted">
            {t(
              draft.enabled
                ? "spaces.attachments.replaceHelp"
                : "spaces.attachments.disableHelp",
            )}
          </p>
          <div className="space-choice">
            <button
              type="button"
              className="secondary"
              disabled={busy}
              onClick={() => setConfirm(false)}
            >
              {t("dialog.cancel")}
            </button>
            <button
              type="button"
              disabled={busy}
              aria-busy={busy}
              onClick={() => void save()}
            >
              {t(
                draft.enabled
                  ? "spaces.attachments.save"
                  : "spaces.attachments.disable",
              )}
            </button>
          </div>
        </ActionDialog>
      )}
    </div>
  );
}
