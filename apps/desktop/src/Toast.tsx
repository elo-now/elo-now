import { Icon } from "./Icon";
import { createPortal } from "react-dom";
import {
  createContext,
  useContext,
  useRef,
  useState,
  useEffect,
  useLayoutEffect,
  type ReactNode,
  type FormEvent,
  type RefObject,
} from "react";
import { errorText, t } from "./i18n";
import { distinctErrorDetail, presentError } from "./errors";
import { useToastSwipe } from "./useToastSwipe";

const ToastContext = createContext({
  showError: (_message: string, _detail?: string) => {},
  setHost: (_host: HTMLElement | null) => {},
  showNotice: (_message: string) => {},
  showMessage: (_message: string, _open: () => void) => {},
  clearMessages: () => {},
});

/** A native form dialog must host its toast inside the browser's top layer. */
export function useToastHost(ref: RefObject<HTMLElement | null>) {
  const { setHost } = useContext(ToastContext);
  useEffect(() => {
    const element = ref.current;
    setHost(element);
    return () =>
      setHost(
        [...document.querySelectorAll<HTMLDialogElement>("dialog[open]")]
          .filter((dialog) => dialog !== element)
          .at(-1) ?? null,
      );
  }, [ref, setHost]);
}

export function useToast() {
  const { showError, showNotice, showMessage, clearMessages } =
    useContext(ToastContext);
  const onInvalid = (event: FormEvent<HTMLFormElement>) => {
    // Keep native constraint checks and focus behavior, but suppress their bubbles.
    event.preventDefault();
    const field = event.target as HTMLInputElement;
    if (event.currentTarget.querySelector(":invalid") !== field) return;
    field.focus();
    showError(
      field.validity.valueMissing
        ? t("error.required")
        : field.validity.tooShort
          ? t("error.tooShort", { count: field.minLength })
          : t("error.invalidField"),
    );
  };
  const reportError = (error: unknown, passwordBytes?: number) => {
    const result = presentError(error, passwordBytes);
    showError(result.message, result.detail);
  };
  return {
    showError,
    notify: showNotice,
    showMessage,
    clearMessages,
    reportError,
    onInvalid,
  };
}

export function ToastProvider({ children }: { children: ReactNode }) {
  const [host, setHost] = useState<HTMLElement | null>(null);
  const [toast, setToast] = useState<{
    message: string;
    detail?: string;
    id: number;
    tone: "error" | "notice" | "message";
    open?: () => void;
  } | null>(null);
  const [leaving, setLeaving] = useState(false);
  const [detailsOpen, setDetailsOpen] = useState(false);
  const [hovered, setHovered] = useState<number | null>(null);
  const [focused, setFocused] = useState<number | null>(null);
  const serial = useRef(0);
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);
  useEffect(
    () => () => {
      if (timer.current !== null) clearTimeout(timer.current);
    },
    [],
  );
  const showError = (
    message: string,
    detail?: string,
    tone: "error" | "notice" = "error",
  ) => {
    if (timer.current !== null) clearTimeout(timer.current);
    setLeaving(false);
    setDetailsOpen(false);
    setToast(
      message
        ? {
            message: tone === "error" ? errorText(message) : message,
            detail: distinctErrorDetail(message, detail),
            id: ++serial.current,
            tone,
          }
        : null,
    );
  };
  const dismiss = () => {
    if (leaving) return;
    setDetailsOpen(false);
    setLeaving(true);
    const id = toast?.id;
    timer.current = setTimeout(
      () => setToast((current) => (current?.id === id ? null : current)),
      160,
    );
  };
  useEffect(() => {
    if (!toast || detailsOpen || hovered === toast.id || focused === toast.id)
      return;
    const id = toast.id;
    const timeout = setTimeout(
      () => setToast((current) => (current?.id === id ? null : current)),
      toast.tone === "error" ? 10000 : 4000,
    );
    return () => clearTimeout(timeout);
  }, [toast, detailsOpen, hovered, focused]);
  const content = toast && (
    <>
      <ToastLayer
        key={toast.id}
        onDismiss={dismiss}
        data-leaving={leaving}
        data-tone={toast.tone}
        onMouseEnter={() => setHovered(toast.id)}
        onMouseLeave={() => setHovered(null)}
        onFocusCapture={() => setFocused(toast.id)}
        onBlurCapture={(event) => {
          if (!event.currentTarget.contains(event.relatedTarget))
            setFocused(null);
        }}
      >
        {toast.open ? (
          <button
            type="button"
            className="toast-message"
            onClick={() => {
              const open = toast.open;
              setToast(null);
              open?.();
            }}
          >
            <span className="toast-text" role="status">
              {toast.message}
            </span>
            <span className="toast-details-label">
              {t("notifications.read")}
            </span>
          </button>
        ) : (
          <ToastMessage
            tone={toast.tone === "error" ? "error" : "notice"}
            message={toast.message}
            detail={toast.detail}
            disabled={leaving}
            onOpen={() => setDetailsOpen(true)}
          />
        )}
        <button
          type="button"
          className="icon"
          aria-label={t("toast.dismiss")}
          disabled={leaving}
          onClick={dismiss}
        >
          <Icon name="close" />
        </button>
      </ToastLayer>
      {detailsOpen && (
        <ToastDetails
          message={toast.message}
          detail={toast.detail}
          onClose={() => setDetailsOpen(false)}
        />
      )}
    </>
  );
  return (
    <ToastContext.Provider
      value={{
        showError,
        setHost,
        showNotice: (message) => showError(message, undefined, "notice"),
        showMessage: (message, open) => {
          setLeaving(false);
          const id = ++serial.current;
          setToast((current) =>
            current?.tone === "error"
              ? current
              : { message, open, id, tone: "message" },
          );
        },
        clearMessages: () =>
          setToast((current) => (current?.tone === "message" ? null : current)),
      }}
    >
      {children}
      {host ? createPortal(content, host) : content}
    </ToastContext.Provider>
  );
}

/** A manual popover stays in the top layer without trapping focus or inheriting
 * a dialog's containing block. Keep it inside the modal for inertness rules. */
function ToastLayer({
  children,
  onDismiss,
  ...props
}: React.ComponentProps<"aside"> & { onDismiss: () => void }) {
  const ref = useRef<HTMLElement>(null);
  useToastSwipe(ref, onDismiss);
  useLayoutEffect(() => {
    const element = ref.current;
    // A keyed dialog can disappear one commit before its toast host changes.
    if (element?.isConnected) element.showPopover();
    return () => {
      if (element?.matches(":popover-open")) element.hidePopover();
    };
  }, []);
  return (
    <aside
      {...props}
      ref={ref}
      className="toast"
      popover="manual"
      data-no-back-swipe
    >
      {children}
    </aside>
  );
}

function ToastMessage({
  tone,
  message,
  detail,
  disabled,
  onOpen,
}: {
  tone: "error" | "notice";
  message: string;
  detail?: string;
  disabled: boolean;
  onOpen: () => void;
}) {
  const content = (
    <>
      <span className="toast-text" role={tone === "error" ? "alert" : "status"}>
        {message}
      </span>
      {detail && (
        <span className="toast-details-label">{t("toast.details")}</span>
      )}
    </>
  );
  return detail ? (
    <button
      type="button"
      className="toast-message"
      aria-haspopup="dialog"
      disabled={disabled}
      onClick={onOpen}
    >
      {content}
    </button>
  ) : (
    <div className="toast-message">{content}</div>
  );
}

function ToastDetails({
  message,
  detail,
  onClose,
}: {
  message: string;
  detail?: string;
  onClose: () => void;
}) {
  const ref = useRef<HTMLDialogElement>(null);
  useEffect(() => {
    const dialog = ref.current;
    dialog?.showModal();
    return () => dialog?.close();
  }, []);
  return (
    <dialog
      ref={ref}
      className="dialog toast-detail-dialog"
      aria-labelledby="toast-detail-title"
      onCancel={(event) => {
        event.preventDefault();
        onClose();
      }}
    >
      <button
        autoFocus
        className="icon close"
        type="button"
        aria-label={t("dialog.close")}
        onClick={onClose}
      >
        <Icon name="close" />
      </button>
      <h2 id="toast-detail-title">{t("toast.details")}</h2>
      <p>{message}</p>
      {detail && <p>{detail}</p>}
    </dialog>
  );
}
