import { formatAttachmentExpiry, formatFileSize, t } from "./i18n";
import { isExpiryTimestamp, timestampIso } from "./timestamps";
import type { MessageRow } from "./messageThreads";
import { useEffect, useLayoutEffect, useRef, useState } from "react";
import {
  cachedAttachmentPreviewState,
  loadAttachmentPreview,
  previewDimensions,
  rememberAttachmentPreviewDecoded,
  shareAttachment,
  type AttachmentContext,
} from "./attachmentPreview";
import { useToast } from "./Toast";
import { presentError } from "./errors";
import "./attachmentMotion.css";

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
  const image = useRef<HTMLImageElement>(null);
  const measured = useRef<{ key: string; height: number } | null>(null);
  const [decoded, setDecoded] = useState<{ key: string; url: string } | null>(
    null,
  );
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
  const cached = request ? cachedAttachmentPreviewState(request) : undefined;
  const previewUrl =
    cached?.url ?? (preview && preview.key === key ? preview.url : null);
  const previewResolved =
    cached !== undefined || (preview !== null && preview.key === key);
  const dimensions =
    cached?.dimensions ??
    (previewUrl ? previewDimensions(previewUrl) : undefined);
  const imageReady =
    cached?.decoded === true ||
    (decoded !== null && decoded.key === key && decoded.url === previewUrl);
  const active = !!download;
  const deadline = row.body.attachment?.expires_at_ms;
  const expiresAt = isExpiryTimestamp(deadline) ? deadline : undefined;
  const [now, setNow] = useState(Date.now);
  useLayoutEffect(() => {
    // Preserve the actual download tile during the next local preview lookup.
    // Static photos do not need a layout read on unrelated chat updates.
    if (!active) return;
    const element = container.current;
    if (!element) return;
    const remember = (height: number) => {
      if (Number.isFinite(height) && height > 0)
        measured.current = { key, height };
    };
    remember(element.getBoundingClientRect().height);
    const observer =
      typeof ResizeObserver === "undefined"
        ? undefined
        : new ResizeObserver(([entry]) => {
            remember(
              entry.borderBoxSize?.[0]?.blockSize ??
                element.getBoundingClientRect().height,
            );
          });
    observer?.observe(element);
    return () => observer?.disconnect();
  }, [key, active, previewUrl]);
  useEffect(() => {
    const element = image.current;
    if (!element || !previewUrl || imageReady) return;
    let cancelled = false;
    const reveal = async () => {
      if (!element.complete || element.naturalWidth === 0) return;
      try {
        await element.decode?.();
      } catch {
        // Some WebViews reject decode() after load even though the bitmap exists.
      }
      if (
        cancelled ||
        image.current !== element ||
        element.getAttribute("src") !== previewUrl ||
        !element.complete ||
        element.naturalWidth === 0
      )
        return;
      if (request) rememberAttachmentPreviewDecoded(request, previewUrl);
      setDecoded({ key, url: previewUrl });
    };
    element.addEventListener("load", reveal);
    void reveal();
    return () => {
      cancelled = true;
      element.removeEventListener("load", reveal);
    };
  }, [key, previewUrl, imageReady]);
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
    if (active) {
      // The pre-download cache miss is no longer a resolved local lookup.
      setPreview(null);
      return;
    }
    if (!request) return;
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
  ) : expiresAt != null ? (
    <small className="attachment-expiry">
      <time dateTime={timestampIso(expiresAt)}>
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
          ref={image}
          className="attachment-image"
          data-preview-ready={imageReady || undefined}
          width={dimensions?.width}
          height={dimensions?.height}
          style={
            dimensions
              ? {
                  width: Math.min(
                    dimensions.width,
                    360,
                    (dimensions.width * 360) / dimensions.height,
                  ),
                  aspectRatio: `${dimensions.width} / ${dimensions.height}`,
                }
              : undefined
          }
          decoding="async"
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
        ref={container}
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
        style={
          measured.current !== null && measured.current.key === key
            ? { minHeight: measured.current.height }
            : undefined
        }
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
