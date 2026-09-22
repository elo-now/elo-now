import { formatFileSize, t } from "./i18n";
import type { MessageRow } from "./messageThreads";

export type AttachmentProgress = {
  received: number;
  total: number;
  cancelling: boolean;
};

export function AttachmentButton({
  row,
  disabled,
  expired = false,
  download,
  onDownload,
  onCancel,
}: {
  row: MessageRow;
  disabled?: boolean;
  expired?: boolean;
  download?: AttachmentProgress;
  onDownload: () => void;
  onCancel: () => void;
}) {
  const filename = row.body.attachment?.name ?? row.body.filename ?? "";
  const size = formatFileSize(
    row.body.attachment?.plaintext_size ?? row.body.size_bytes ?? 0,
  );
  const unavailable =
    expired ||
    (row.body.attachment?.expires_at_ms != null &&
      row.body.attachment.expires_at_ms <= Date.now());
  const percent =
    download && download.total > 0
      ? Math.min(100, Math.round((download.received / download.total) * 100))
      : undefined;
  const content = (
    <>
      <span className="attachment-name">
        {unavailable ? t("file.expired", { filename }) : filename}
      </span>
      <small>{size}</small>
      {unavailable && <small>{t("file.serverCopyUnavailable")}</small>}
    </>
  );
  if (download) {
    return (
      <div
        className="attachment attachment-active"
        aria-label={t("file.downloadLabel", { filename, size })}
      >
        {content}
        <span className="attachment-progress" role="status">
          <span className="attachment-progress-label">
            <span>
              {download.cancelling
                ? t("file.cancelling")
                : percent == null
                  ? t("file.downloading")
                  : t("file.downloadingPercent", { percent })}
            </span>
            <button
              type="button"
              className="attachment-cancel"
              disabled={download.cancelling}
              onClick={onCancel}
            >
              {t("file.cancelTransfer")}
            </button>
          </span>
          <progress
            aria-label={t("file.downloadProgress", { filename })}
            value={percent == null ? undefined : download.received}
            max={percent == null ? undefined : download.total}
          />
        </span>
      </div>
    );
  }
  return (
    <button
      className="attachment"
      disabled={disabled || unavailable}
      aria-label={t("file.downloadLabel", { filename, size })}
      onClick={onDownload}
    >
      {content}
    </button>
  );
}
