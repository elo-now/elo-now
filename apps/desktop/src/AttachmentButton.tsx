import { formatFileSize, t } from "./i18n";
import type { MessageRow } from "./messageThreads";
import { useEffect, useRef, useState } from "react";
import {
  cachedAttachmentPreview,
  loadAttachmentPreview,
  shareAttachment,
  type AttachmentContext,
} from "./attachmentPreview";
import { useToast } from "./Toast";
import { presentError } from "./errors";

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
  context,
}: {
  row: MessageRow;
  disabled?: boolean;
  expired?: boolean;
  download?: AttachmentProgress;
  onDownload: () => void;
  onCancel: () => void;
  context?: AttachmentContext;
}) {
  const { showError } = useToast();
  const [preview, setPreview] = useState<{
    key: string;
    url: string | null;
  } | null>(null);
  const container = useRef<HTMLDivElement>(null);
  const press = useRef<{
    timer?: number;
    x: number;
    y: number;
    fired: boolean;
  }>({ x: 0, y: 0, fired: false });
  const sharing = useRef(false);
  const lastShared = useRef(0);
  const request = context ? { ...context, record: row.id } : undefined;
  const key = JSON.stringify(request);
  const cachedPreview = request ? cachedAttachmentPreview(request) : undefined;
  const previewUrl =
    cachedPreview ?? (preview && preview.key === key ? preview.url : null);
  const previewResolved =
    cachedPreview !== undefined || (preview !== null && preview.key === key);
  const active = !!download;
  useEffect(() => {
    if (!request || active) return;
    let cancelled = false;
    const load = () => {
      void loadAttachmentPreview(request)
        .then((url) => {
          if (!cancelled) setPreview({ key, url });
        })
        .catch(() => {
          if (!cancelled) setPreview({ key, url: null });
        });
    };
    if (!container.current || typeof IntersectionObserver === "undefined")
      load();
    const observer =
      typeof IntersectionObserver !== "undefined"
        ? new IntersectionObserver(
            (entries) => {
              if (entries.some((entry) => entry.isIntersecting)) {
                observer?.disconnect();
                load();
              }
            },
            { rootMargin: "100px" },
          )
        : undefined;
    if (container.current) observer?.observe(container.current);
    return () => {
      cancelled = true;
      observer?.disconnect();
      window.clearTimeout(press.current.timer);
    };
  }, [key, active]);
  const share = () => {
    if (!request || sharing.current) return;
    sharing.current = true;
    lastShared.current = Date.now();
    void shareAttachment(request)
      .catch((error) => {
        const message = presentError(error);
        showError(message.message, message.detail);
      })
      .finally(() => {
        sharing.current = false;
      });
  };
  const clearPress = () => window.clearTimeout(press.current.timer);
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
  if (previewUrl) {
    return (
      <div ref={container} className="attachment-preview">
        <img
          src={previewUrl}
          alt={filename}
          draggable={false}
          role="button"
          tabIndex={0}
          aria-label={t("file.shareImage", { filename })}
          onPointerDown={(event) => {
            if (event.button !== 0) return;
            clearPress();
            press.current = {
              x: event.clientX,
              y: event.clientY,
              fired: false,
            };
            press.current.timer = window.setTimeout(() => {
              press.current.fired = true;
              share();
            }, 500);
          }}
          onPointerMove={(event) => {
            if (
              Math.hypot(
                event.clientX - press.current.x,
                event.clientY - press.current.y,
              ) > 10
            )
              clearPress();
          }}
          onPointerUp={clearPress}
          onPointerCancel={clearPress}
          onPointerLeave={clearPress}
          onContextMenu={(event) => {
            event.preventDefault();
            clearPress();
            if (Date.now() - lastShared.current > 800) share();
          }}
          onKeyDown={(event) => {
            if (!event.repeat && (event.key === "Enter" || event.key === " ")) {
              event.preventDefault();
              share();
            }
          }}
        />
      </div>
    );
  }
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
  if (request && !previewResolved) {
    // A pending local read does not mean the attachment needs downloading.
    return (
      <div
        ref={container}
        className="attachment-preview-pending"
        aria-busy="true"
      />
    );
  }
  return (
    <div ref={container} className="attachment-container">
      <button
        className="attachment"
        disabled={disabled || unavailable}
        aria-label={t("file.downloadLabel", { filename, size })}
        onClick={onDownload}
      >
        {content}
      </button>
    </div>
  );
}
