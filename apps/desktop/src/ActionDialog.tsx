import { PageContent } from "./PageContent";
import { PageSurface, useDesktopLayout } from "./PageSurface";
import { ScreenHeader } from "./ScreenHeader";
import { useEffect, useRef, type ReactNode } from "react";
import { useToastHost } from "./Toast";
import { Icon } from "./Icon";
import { t } from "./i18n";

type ActionDialogProps = {
  title: string;
  anchor?: DOMRect;
  onClose: () => void;
  children: ReactNode;
  menu?: boolean;
  compact?: boolean;
  className?: string;
  closeIcon?: ReactNode;
  closeLabel?: string;
  page?: boolean;
};

export function ActionDialog(props: ActionDialogProps) {
  const desktop = useDesktopLayout();
  if (props.page && desktop && document.getElementById("desktop-page-outlet"))
    return (
      <PageSurface
        title={props.title}
        className={props.className}
        onClose={props.onClose}
      >
        <ScreenHeader title={props.title} onBack={props.onClose} />
        <PageContent className="desktop-page-body">
          {props.children}
        </PageContent>
      </PageSurface>
    );
  return <ModalActionDialog {...props} />;
}

function ModalActionDialog({
  title,
  anchor,
  onClose,
  children,
  menu = false,
  compact = false,
  className = "",
  closeIcon,
  closeLabel,
}: ActionDialogProps) {
  const desktop = useDesktopLayout();
  const ref = useRef<HTMLDialogElement>(null);
  useToastHost(ref);
  useEffect(() => {
    const dialog = ref.current!;
    const opener = document.activeElement;
    dialog.showModal();
    const viewport = window.visualViewport;
    const position = () => {
      if (!anchor) return;
      const top = viewport?.offsetTop ?? 0;
      const height = viewport?.height ?? innerHeight;
      const width = viewport?.width ?? innerWidth;
      const bounds = dialog.getBoundingClientRect();
      dialog.style.left = `${Math.max(8, Math.min(anchor.right - bounds.width, width - bounds.width - 8))}px`;
      dialog.style.top = `${Math.max(top + 8, Math.min(anchor.bottom + 4, top + height - bounds.height - 8))}px`;
    };
    position();
    const resize = new ResizeObserver(position);
    resize.observe(dialog);
    viewport?.addEventListener("resize", position);
    viewport?.addEventListener("scroll", position);
    window.addEventListener("resize", position);
    return () => {
      resize.disconnect();
      viewport?.removeEventListener("resize", position);
      viewport?.removeEventListener("scroll", position);
      window.removeEventListener("resize", position);
      dialog.close();
      if (opener instanceof HTMLElement && opener.isConnected)
        opener.focus({ preventScroll: true });
    };
  }, []);
  return (
    <dialog
      ref={ref}
      data-desktop={desktop || undefined}
      className={`dialog ${menu || compact ? "anchored-dialog" : "message-action-dialog"} ${menu ? "message-action-menu" : ""} ${className}`}
      aria-label={title}
      onCancel={(e) => {
        e.preventDefault();
        onClose();
      }}
      onClick={(event) => {
        if (event.target !== event.currentTarget) return;
        const box = event.currentTarget.getBoundingClientRect();
        if (
          event.clientX < box.left ||
          event.clientX > box.right ||
          event.clientY < box.top ||
          event.clientY > box.bottom
        )
          onClose();
      }}
    >
      {!menu && !compact && (
        <>
          <button
            className="close"
            aria-label={closeLabel ?? t("dialog.close")}
            onClick={onClose}
          >
            {closeIcon ?? <Icon name="close" />}
          </button>
          <h2>{title}</h2>
        </>
      )}
      <div
        role={menu ? "menu" : undefined}
        onKeyDown={(event) => {
          if (
            !menu ||
            !["ArrowUp", "ArrowDown", "Home", "End"].includes(event.key)
          )
            return;
          event.preventDefault();
          const buttons = [
            ...event.currentTarget.querySelectorAll<HTMLButtonElement>(
              "button:not(:disabled)",
            ),
          ];
          const current = buttons.indexOf(
            document.activeElement as HTMLButtonElement,
          );
          const index =
            event.key === "Home"
              ? 0
              : event.key === "End"
                ? buttons.length - 1
                : (current +
                    (event.key === "ArrowDown" ? 1 : -1) +
                    buttons.length) %
                  buttons.length;
          buttons[index]?.focus();
        }}
      >
        {children}
      </div>
    </dialog>
  );
}
