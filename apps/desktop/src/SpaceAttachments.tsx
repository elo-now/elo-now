import { useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { ActionDialog } from "./ActionDialog";
import type { SpaceSummary } from "./model";
import type { SpaceManagement } from "./SpaceRoles";
import { locale, t } from "./i18n";
import { useToast } from "./Toast";

type AttachmentSettings = NonNullable<SpaceManagement["attachments"]>;
type Cleanup = {
  files: number;
  bytes: number;
  before_ms: number;
  days: number;
};

const size = (bytes: number) =>
  `${new Intl.NumberFormat(locale, { maximumFractionDigits: 2 }).format(bytes / 1024 ** 2)} MiB`;

const retentionValue = (
  retention: AttachmentSettings["policy"]["retention"],
) => (retention === "never" ? "never" : String(retention.days));

export function SpaceAttachments({
  identity,
  space,
  value,
  onChanged,
}: {
  identity: string;
  space: SpaceSummary;
  value: AttachmentSettings;
  onChanged: () => Promise<void>;
}) {
  const [days, setDays] = useState("100");
  const [preview, setPreview] = useState<Cleanup>();
  const [confirm, setConfirm] = useState(false);
  const [busy, setBusy] = useState(false);
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
  const used = value.used_bytes + value.reserved_bytes;
  const percent = Math.min(
    100,
    Math.round((used / value.policy.max_space_bytes) * 100),
  );
  return (
    <section className="space-details-section space-storage" aria-busy={busy}>
      <h3>{t("spaces.attachments.title")}</h3>
      <div className="space-storage-usage">
        <p>
          {t("spaces.attachments.usage", {
            used: size(used),
            quota: size(value.policy.max_space_bytes),
          })}
        </p>
        <progress
          value={used}
          max={value.policy.max_space_bytes}
          aria-label={t("spaces.storage.percent", { percent })}
        />
      </div>
      <p className="caption muted">{t("spaces.attachments.limits")}</p>
      <div className="space-attachment-controls">
        <div className="space-form-field">
          <label htmlFor="space-attachment-retention">
            {t("spaces.attachments.retention")}
          </label>
          <select
            id="space-attachment-retention"
            value={retentionValue(value.policy.retention)}
            disabled={busy}
            onChange={(event) => {
              const selected = event.target.value;
              setPreview(undefined);
              void run(async () => {
                await request("space_attachment_retention", {
                  days: selected === "never" ? null : Number(selected),
                });
                await onChanged();
                notify(t("spaces.attachments.retentionSaved"));
              });
            }}
          >
            <option value="never">{t("spaces.attachments.never")}</option>
            {[1, 7, 30, 90, 365].map((option) => (
              <option key={option} value={option}>
                {t("spaces.attachments.days", { days: option })}
              </option>
            ))}
          </select>
        </div>
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
      </div>
      {confirm && preview && (
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
