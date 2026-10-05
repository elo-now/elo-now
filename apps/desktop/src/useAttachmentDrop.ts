import { useEffect, useRef, useState, type DragEvent } from "react";
import { droppedAttachment, hasDroppedFiles } from "./attachmentDrop";

export function useAttachmentDrop(options: {
  desktop: boolean;
  enabled: boolean;
  scope: string;
  onFile: (file: File) => void;
  onError: (error: unknown) => void;
}) {
  const [dragging, setDragging] = useState(false);
  const depth = useRef(0);
  const available = () =>
    options.desktop &&
    options.enabled &&
    !document.querySelector("dialog[open]");
  useEffect(() => {
    depth.current = 0;
    setDragging(false);
  }, [options.scope, options.enabled]);
  useEffect(() => {
    if (!options.desktop) return;
    // An OS file dropped outside the composer must not navigate the WebView.
    const preventNavigation = (event: globalThis.DragEvent) => {
      if (event.dataTransfer && hasDroppedFiles(event.dataTransfer))
        event.preventDefault();
    };
    window.addEventListener("dragover", preventNavigation);
    window.addEventListener("drop", preventNavigation);
    return () => {
      window.removeEventListener("dragover", preventNavigation);
      window.removeEventListener("drop", preventNavigation);
    };
  }, [options.desktop]);
  return {
    dragging,
    handlers: {
      onDragEnter(event: DragEvent<HTMLElement>) {
        if (!hasDroppedFiles(event.dataTransfer) || !available()) return;
        event.preventDefault();
        depth.current += 1;
        setDragging(true);
      },
      onDragOver(event: DragEvent<HTMLElement>) {
        if (!hasDroppedFiles(event.dataTransfer)) return;
        event.preventDefault();
        event.dataTransfer.dropEffect = available() ? "copy" : "none";
      },
      onDragLeave() {
        depth.current = Math.max(0, depth.current - 1);
        if (!depth.current) setDragging(false);
      },
      onDrop(event: DragEvent<HTMLElement>) {
        depth.current = 0;
        setDragging(false);
        if (!hasDroppedFiles(event.dataTransfer)) return;
        event.preventDefault();
        if (!available()) return;
        try {
          options.onFile(droppedAttachment(event.dataTransfer));
        } catch (error) {
          options.onError(error);
        }
      },
    },
  };
}
