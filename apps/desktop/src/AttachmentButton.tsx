import { formatAttachmentExpiry, formatFileSize, t } from "./i18n";
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

export type AttachmentUnavailable = "expired" | "removed" | "unavailable";
export function attachmentFailure(
  error: unknown,
): AttachmentUnavailable | undefined {
  const message = String(error);
  if (message.includes("This attachment has expired on the server."))
    return "expired";
  if (message.includes("This attachment was removed from the server."))
    return "removed";
  if (message.includes("This attachment is no longer available on the server."))
    return "unavailable";
}

export function AttachmentButton({
  row,
  disabled,
  serverState,
  download,
  onDownload,
  onCancel,
  context,
}: {
  row: MessageRow;
  disabled?: boolean;
  serverState?: AttachmentUnavailable;
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
  const expiresAt = row.body.attachment?.expires_at_ms;
  const [now, setNow] = useState(Date.now);
  useEffect(() => {
    if (expiresAt == null) return;
    let timer: ReturnType<typeof setTimeout>;
    const update = () => {
      clearTimeout(timer);
      const current = Date.now();
      setNow(current);
      if (expiresAt > current)
        timer = setTimeout(
          update,
          Math.min(expiresAt - current, 2_147_483_647),
        );
    };
    update();
    document.addEventListener("visibilitychange", update);
    return () => {
      clearTimeout(timer);
      document.removeEventListener("visibilitychange", update);
    };
  }, [expiresAt]);
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
    serverState ??
    (expiresAt != null && expiresAt <= now ? "expired" : undefined);
  const expiry = unavailable ? (
    <small
      className="attachment-expiry"
      title={t("file.serverCopyUnavailable")}
    >
      {t(`file.${unavailable}`)}
    </small>
  ) : expiresAt != null && Number.isFinite(new Date(expiresAt).getTime()) ? (
    <small className="attachment-expiry">
      <time dateTime={new Date(expiresAt).toISOString()}>
        {t("file.expiresAt", { date: formatAttachmentExpiry(expiresAt) })}
      </time>
    </small>
  ) : null;
  const percent =
    download && download.total > 0
      ? Math.min(100, Math.round((download.received / download.total) * 100))
      : undefined;
  const content = (
    <>
      <span className="attachment-name">{filename}</span>
      <small>{size}</small>
      {expiry}
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
        {expiry}
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
        disabled={disabled || !!unavailable}
        aria-label={t("file.downloadLabel", { filename, size })}
        onClick={onDownload}
      >
        {content}
      </button>
    </div>
  );
}
