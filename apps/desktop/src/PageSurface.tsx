import {
  useEffect,
  useLayoutEffect,
  useRef,
  useState,
  useSyncExternalStore,
  type ReactNode,
} from "react";
import { createPortal } from "react-dom";
import { useToastHost } from "./Toast";

const query = "(min-width: 768px)";
const openPages = new WeakMap<HTMLElement, number>();
const subscribe = (notify: () => void) => {
  const media = window.matchMedia(query);
  media.addEventListener("change", notify);
  return () => media.removeEventListener("change", notify);
};
export const useDesktopLayout = () =>
  useSyncExternalStore(
    subscribe,
    () => window.matchMedia(query).matches,
    () => false,
  );

/** Full workflows occupy the desktop content pane; phones keep their modal page. */
export function PageSurface({
  title,
  className = "",
  onClose,
  children,
}: {
  title: string;
  className?: string;
  onClose: () => void;
  children: ReactNode;
}) {
  const desktop = useDesktopLayout();
  const [host, setHost] = useState<HTMLElement | null>(null);
  const page = useRef<HTMLElement>(null);
  const dialog = useRef<HTMLDialogElement>(null);
  useToastHost(dialog);
  useEffect(() => {
    if (desktop) setHost(document.getElementById("desktop-page-outlet"));
    else {
      const node = dialog.current;
      node?.showModal();
      return () => node?.close();
    }
  }, [desktop]);
  useEffect(() => {
    if (desktop && host) page.current?.focus({ preventScroll: true });
  }, [desktop, host]);
  useLayoutEffect(() => {
    if (!desktop || !host) return;
    const shell = host.closest(".shell");
    openPages.set(host, (openPages.get(host) ?? 0) + 1);
    host.setAttribute("data-active", "true");
    shell?.setAttribute("data-page-open", "true");
    return () => {
      const remaining = Math.max(0, (openPages.get(host) ?? 1) - 1);
      openPages.set(host, remaining);
      if (!remaining) {
        host.removeAttribute("data-active");
        shell?.removeAttribute("data-page-open");
      }
    };
  }, [desktop, host]);
  if (desktop)
    return (
      host &&
      createPortal(
        <section
          ref={page}
          className={`desktop-page content-pane ${className}`}
          aria-label={title}
          tabIndex={-1}
          onKeyDown={(event) => {
            if (
              event.key === "Escape" &&
              !document.querySelector("dialog[open]")
            ) {
              event.stopPropagation();
              onClose();
            }
          }}
        >
          {children}
        </section>,
        host,
      )
    );
  return (
    <dialog
      ref={dialog}
      className={`dialog ${className}`}
      aria-label={title}
      onCancel={(event) => {
        event.preventDefault();
        onClose();
      }}
    >
      {children}
    </dialog>
  );
}
