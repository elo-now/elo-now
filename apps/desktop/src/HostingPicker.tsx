import { useEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";
import {
  scan,
  cancel,
  checkPermissions,
  requestPermissions,
  Format,
} from "@tauri-apps/plugin-barcode-scanner";
import { ActionDialog } from "./ActionDialog";
import { Icon } from "./Icon";
import { QrScanner } from "./QrScanner";
import { useToast } from "./Toast";
import { t } from "./i18n";
import {
  hostingCatalog,
  hostingErrorMessage,
  messageLifetimeLabel,
  type HostingCatalogReply,
  type HostingCatalogRequest,
  type HostingProfileSummary,
} from "./Hosting";
import "./hosting.css";

export function HostingPreview({ host }: { host: HostingProfileSummary }) {
  return (
    <div className="hosting-preview">
      <strong>{host.name}</strong>
      <p className="hosting-address">{host.url}</p>
      <dl>
        <div>
          <dt>{t("spaces.messageLifetime.label")}</dt>
          <dd>{host.message_lifetimes.map(messageLifetimeLabel).join(", ")}</dd>
        </div>
        <div>
          <dt>{t("hosting.attachments")}</dt>
          <dd>
            {t(
              host.attachment_storage_managed
                ? "hosting.managedAttachments"
                : host.attachment_storage_available
                  ? "hosting.ownAttachments"
                  : "hosting.noAttachments",
            )}
          </dd>
        </div>
        {host.storage_provider && (
          <div>
            <dt>{t("spaces.attachments.provider")}</dt>
            <dd>
              {t(
                host.storage_provider === "mega"
                  ? "spaces.attachments.mega"
                  : "spaces.attachments.s3",
              )}
            </dd>
          </div>
        )}
      </dl>
    </div>
  );
}

function AddHosting({
  mobile,
  onAdd,
  onClose,
}: {
  mobile: boolean;
  onAdd: (link: string, id: string) => Promise<void>;
  onClose: () => void;
}) {
  const [link, setLink] = useState("");
  const [preview, setPreview] = useState<HostingProfileSummary>();
  const [busy, setBusy] = useState<"preview" | "add">();
  const [scanning, setScanning] = useState(false);
  const mounted = useRef(true);
  const pending = useRef(false);
  const scanGeneration = useRef(0);
  const scanningRef = useRef(false);
  const { showError, reportError, onInvalid } = useToast();
  const stopScan = () => {
    scanGeneration.current += 1;
    scanningRef.current = false;
    if (mounted.current) setScanning(false);
    void cancel().catch(() => {});
  };
  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
      if (scanningRef.current) stopScan();
    };
  }, []);
  const inspect = async (value: string) => {
    if (pending.current) return;
    pending.current = true;
    setBusy("preview");
    setPreview(undefined);
    const candidate = value.trim();
    setLink(candidate);
    try {
      const result = await hostingCatalog({ op: "preview", link: candidate });
      if (mounted.current) {
        if (result.preview) setPreview(result.preview);
        else showError(t("hosting.invalidLink"));
      }
    } catch (error) {
      if (mounted.current)
        showError(hostingErrorMessage(error, "hosting.previewFailed"));
    } finally {
      pending.current = false;
      if (mounted.current) setBusy(undefined);
    }
  };
  const startScan = async () => {
    if (pending.current || scanningRef.current) return;
    const generation = ++scanGeneration.current;
    scanningRef.current = true;
    setScanning(true);
    const current = () =>
      mounted.current &&
      scanningRef.current &&
      scanGeneration.current === generation;
    try {
      let permission = await checkPermissions();
      if (!current()) return;
      if (permission !== "granted") permission = await requestPermissions();
      if (!current()) return;
      if (permission !== "granted") {
        showError(t("invite.cameraDenied"));
        return;
      }
      const result = await scan({ formats: [Format.QRCode], windowed: true });
      if (!current()) return;
      stopScan();
      await inspect(result.content);
    } catch (error) {
      if (current()) reportError(error);
    } finally {
      if (current()) stopScan();
    }
  };
  return (
    <>
      <ActionDialog
        title={t("hosting.addTitle")}
        className="hosting-dialog"
        onClose={() => {
          if (busy !== "add") onClose();
        }}
      >
        <form
          className="hosting-add-form"
          onInvalid={onInvalid}
          onSubmit={(event) => {
            event.preventDefault();
            event.stopPropagation();
            if (pending.current || scanning) return;
            if (!preview) {
              void inspect(link);
              return;
            }
            pending.current = true;
            setBusy("add");
            void onAdd(link, preview.id)
              .catch((error) => {
                if (mounted.current)
                  showError(hostingErrorMessage(error, "hosting.addFailed"));
              })
              .finally(() => {
                pending.current = false;
                if (mounted.current) setBusy(undefined);
              });
          }}
        >
          <p className="caption muted">{t("hosting.addHelp")}</p>
          {mobile && !preview && (
            <button
              type="button"
              className="secondary"
              disabled={!!busy || scanning}
              onClick={() => void startScan()}
            >
              <Icon name="qr" /> {t("hosting.scan")}
            </button>
          )}
          <div className="space-form-field">
            <label htmlFor="hosting-link">{t("hosting.link")}</label>
            <textarea
              id="hosting-link"
              value={link}
              required
              rows={3}
              maxLength={32768}
              autoComplete="off"
              autoCapitalize="none"
              spellCheck={false}
              disabled={!!busy || scanning}
              onChange={(event) => {
                setLink(event.target.value);
                setPreview(undefined);
              }}
            />
          </div>
          {preview && <HostingPreview host={preview} />}
          <div className="space-choice">
            <button
              type="button"
              className="secondary"
              disabled={busy === "add"}
              onClick={onClose}
            >
              {t("dialog.cancel")}
            </button>
            <button type="submit" disabled={!!busy || scanning || !link.trim()}>
              {t(
                busy === "preview"
                  ? "hosting.checking"
                  : busy === "add"
                    ? "hosting.adding"
                    : preview
                      ? "hosting.add"
                      : "hosting.preview",
              )}
            </button>
          </div>
        </form>
      </ActionDialog>
      {scanning && (
        <QrScanner
          title={t("hosting.scan")}
          hint={t("hosting.scanHint")}
          onCancel={stopScan}
        />
      )}
    </>
  );
}

export function HostingPicker({
  entries,
  selectedId,
  onSelect,
  status,
  request,
  refresh,
  disabled,
  pendingCreation,
  mobile,
}: {
  entries: HostingProfileSummary[];
  selectedId?: string;
  onSelect: (id: string) => void;
  status: "loading" | "ready" | "failed";
  request: (request: HostingCatalogRequest) => Promise<HostingCatalogReply>;
  refresh: () => Promise<void>;
  disabled: boolean;
  pendingCreation: boolean;
  mobile: boolean;
}) {
  const [adding, setAdding] = useState(false);
  const [removing, setRemoving] = useState<HostingProfileSummary>();
  const [busy, setBusy] = useState(false);
  const pending = useRef(false);
  const { showError } = useToast();
  const selected = entries.find((entry) => entry.id === selectedId);
  const mutate = async (input: HostingCatalogRequest) => {
    if (pending.current) return;
    pending.current = true;
    setBusy(true);
    try {
      const result = await request(input);
      if (input.op === "remove" && input.id === selectedId)
        onSelect(result.entries[0]?.id ?? "");
      setRemoving(undefined);
    } catch (error) {
      showError(hostingErrorMessage(error, "hosting.saveFailed"));
    } finally {
      pending.current = false;
      setBusy(false);
    }
  };
  return (
    <div className="hosting-picker space-form-field">
      <label htmlFor="space-hosting">{t("hosting.label")}</label>
      <div className="hosting-select-row">
        <select
          id="space-hosting"
          value={selected?.id ?? ""}
          disabled={disabled || busy || status !== "ready" || !entries.length}
          onChange={(event) => onSelect(event.target.value)}
          aria-describedby="hosting-help"
        >
          {!selected && (
            <option value="">
              {t(
                pendingCreation
                  ? "hosting.saved"
                  : status === "loading"
                    ? "hosting.loading"
                    : "hosting.choose",
              )}
            </option>
          )}
          {entries.map((host) => (
            <option key={host.id} value={host.id}>
              {host.name}
            </option>
          ))}
        </select>
        <button
          type="button"
          className="icon secondary"
          aria-label={t("hosting.addTitle")}
          title={t("hosting.addTitle")}
          disabled={disabled || busy || status !== "ready"}
          onClick={() => setAdding(true)}
        >
          <Icon name="plus" />
        </button>
        {selected && (
          <button
            type="button"
            className="icon secondary"
            aria-label={t("hosting.removeTitle", { name: selected.name })}
            title={t("hosting.removeTitle", { name: selected.name })}
            disabled={disabled || busy}
            onClick={() => setRemoving(selected)}
          >
            <Icon name="delete" />
          </button>
        )}
      </div>
      {selected && (
        <p className="caption muted hosting-address">{selected.url}</p>
      )}
      <p id="hosting-help" className="caption muted">
        {t(pendingCreation ? "hosting.savedHelp" : "hosting.localHelp")}
      </p>
      {!pendingCreation && status === "failed" && (
        <div className="hosting-status" role="status">
          <p>{t("hosting.loadFailed")}</p>
          <button
            type="button"
            className="secondary"
            onClick={() => void refresh()}
          >
            {t("hosting.retry")}
          </button>
        </div>
      )}
      {!pendingCreation && status === "ready" && !entries.length && (
        <p className="caption muted" role="status">
          {t("hosting.empty")}
        </p>
      )}
      {!pendingCreation &&
        status === "ready" &&
        !entries.some((entry) => entry.builtin) && (
          <button
            type="button"
            className="secondary"
            disabled={disabled || busy}
            onClick={() => void mutate({ op: "restore_default" })}
          >
            {t("hosting.restore")}
          </button>
        )}
      {adding &&
        createPortal(
          <AddHosting
            mobile={mobile}
            onClose={() => setAdding(false)}
            onAdd={async (link, id) => {
              const result = await request({ op: "add", link });
              if (!result.entries.some((entry) => entry.id === id))
                throw new Error("Added hosting was not confirmed.");
              onSelect(id);
              setAdding(false);
            }}
          />,
          document.body,
        )}
      {removing &&
        createPortal(
          <ActionDialog
            title={t("hosting.removeTitle", { name: removing.name })}
            onClose={() => {
              if (!busy) setRemoving(undefined);
            }}
          >
            <p>{t("hosting.removeHelp", { name: removing.name })}</p>
            <div className="space-choice">
              <button
                type="button"
                className="secondary"
                disabled={busy}
                onClick={() => setRemoving(undefined)}
              >
                {t("dialog.cancel")}
              </button>
              <button
                type="button"
                className="danger"
                disabled={busy}
                onClick={() => void mutate({ op: "remove", id: removing.id })}
              >
                {t("hosting.remove")}
              </button>
            </div>
          </ActionDialog>,
          document.body,
        )}
    </div>
  );
}
