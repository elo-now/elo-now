import {
  useEffect,
  useLayoutEffect,
  useRef,
  useId,
  useState,
  type ComponentPropsWithoutRef,
  type RefObject,
} from "react";
import { createPortal } from "react-dom";
import { useRealtimePresentation } from "./useRealtime";
import { pastedImage } from "./composerClipboard";
import { createComposerSizer } from "./composerSizing";
import { t } from "./i18n";
import {
  insertMention,
  mentionQuery,
  mentionIdentities,
  reconcileMentions,
  type ComposerMention,
  type MentionCandidate,
} from "./composerMentions";
import "./composerMentions.css";
import { useEditMessage } from "./MessageActions";
import type { Stream } from "./model";

/** Share draft sizing between the conversation and its thread. */
export function ComposerInput({
  inputRef,
  onPasteImage,
  mentionCandidates = [],
  mentions = [],
  onDraftChange,
  onEditLatest,
  editTarget,
  ...props
}: ComponentPropsWithoutRef<"textarea"> & {
  inputRef?: RefObject<HTMLTextAreaElement | null>;
  onPasteImage?: (file: File) => void;
  mentionCandidates?: MentionCandidate[];
  mentions?: ComposerMention[];
  onDraftChange?: (text: string, mentions: ComposerMention[]) => void;
  onEditLatest?: () => void;
  editTarget?: { chat: Stream; row: Stream["rows"][number] };
}) {
  const localRef = useRef<HTMLTextAreaElement>(null);
  const realtime = useRealtimePresentation();
  const editMessage = useEditMessage();
  useEffect(() => {
    if (!props.value || props.disabled) realtime.typing(false);
  }, [props.value, props.disabled]);
  const input = inputRef ?? localRef;
  const sizer = useRef<ReturnType<typeof createComposerSizer>>(undefined);
  if (!sizer.current) sizer.current = createComposerSizer();
  const listId = useId();
  const [caret, setCaret] = useState<number>();
  const [activeOption, setActiveOption] = useState(0);
  const [dismissed, setDismissed] = useState<string>();
  const [position, setPosition] = useState({
    left: 0,
    bottom: 0,
    width: 0,
    maxHeight: 240,
  });
  const text = typeof props.value === "string" ? props.value : "";
  const query =
    caret !== undefined && onDraftChange && !props.disabled && !props.readOnly
      ? mentionQuery(text, caret)
      : undefined;
  const queryKey = query ? `${query.start}:${query.end}:${query.query}` : "";
  const selectedIdentities = mentionIdentities(text, mentions);
  const options =
    query && dismissed !== queryKey
      ? mentionCandidates
          .filter(
            (candidate) =>
              (selectedIdentities.length < 32 ||
                selectedIdentities.includes(candidate.identity_id)) &&
              candidate.label
                .toLocaleLowerCase()
                .includes(query.query.toLocaleLowerCase()),
          )
          .slice(0, 8)
      : [];
  const open = options.length > 0;
  useEffect(() => setActiveOption(0), [queryKey]);
  useEffect(() => {
    if (open)
      document
        .getElementById(
          `${listId}-${Math.min(activeOption, options.length - 1)}`,
        )
        ?.scrollIntoView({ block: "nearest" });
  }, [activeOption, open]);
  useLayoutEffect(() => {
    if (!open) return;
    const update = () => {
      const rect = input.current?.getBoundingClientRect();
      if (rect)
        setPosition({
          left: Math.max(
            8,
            Math.min(
              rect.left,
              window.innerWidth - Math.min(rect.width, 360) - 8,
            ),
          ),
          bottom: window.innerHeight - rect.top + 6,
          width: Math.min(rect.width, 360, window.innerWidth - 16),
          maxHeight: Math.min(
            240,
            Math.max(
              44,
              rect.top - (window.visualViewport?.offsetTop ?? 0) - 8,
            ),
          ),
        });
    };
    update();
    window.addEventListener("resize", update);
    window.visualViewport?.addEventListener("resize", update);
    window.visualViewport?.addEventListener("scroll", update);
    return () => {
      window.removeEventListener("resize", update);
      window.visualViewport?.removeEventListener("resize", update);
      window.visualViewport?.removeEventListener("scroll", update);
    };
  }, [open, queryKey, input]);
  const selectMention = (candidate: MentionCandidate) => {
    if (!query || !onDraftChange) return;
    const next = insertMention(text, mentions, query, candidate);
    if (props.maxLength && next.text.length > props.maxLength) return;
    onDraftChange(next.text, next.mentions);
    setCaret(undefined);
    input.current?.focus({ preventScroll: true });
    requestAnimationFrame(() =>
      input.current?.setSelectionRange(next.caret, next.caret),
    );
    realtime.typing(true);
  };
  const resize = () => {
    const node = input.current;
    if (node) sizer.current!.resize(node);
  };
  // Includes preference changes and restored drafts, not just keystrokes.
  useLayoutEffect(resize);
  useLayoutEffect(() => {
    const node = input.current;
    if (!node) return;
    let width = node.getBoundingClientRect().width;
    let resizeFrame = 0;
    const observer = new ResizeObserver(() => {
      const next = node.getBoundingClientRect().width;
      if (next !== width) {
        width = next;
        cancelAnimationFrame(resizeFrame);
        resizeFrame = requestAnimationFrame(resize);
      }
    });
    observer.observe(node);
    const viewport = window.visualViewport;
    viewport?.addEventListener("resize", resize);
    window.addEventListener("resize", resize);
    const fontsLoaded = () => {
      sizer.current!.invalidate();
      resize();
    };
    document.fonts.addEventListener("loadingdone", fontsLoaded);
    return () => {
      observer.disconnect();
      cancelAnimationFrame(resizeFrame);
      viewport?.removeEventListener("resize", resize);
      window.removeEventListener("resize", resize);
      document.fonts.removeEventListener("loadingdone", fontsLoaded);
      sizer.current!.dispose();
    };
  }, [input]);
  return (
    <>
      <textarea
        {...props}
        ref={input}
        rows={1}
        aria-controls={open ? listId : undefined}
        aria-autocomplete={
          onDraftChange && mentionCandidates.length ? "list" : undefined
        }
        aria-activedescendant={
          open
            ? `${listId}-${Math.min(activeOption, options.length - 1)}`
            : undefined
        }
        onSelect={(event) => {
          props.onSelect?.(event);
          const node = event.currentTarget;
          setCaret(
            node.selectionStart === node.selectionEnd
              ? node.selectionStart
              : undefined,
          );
        }}
        onPaste={(event) => {
          props.onPaste?.(event);
          if (
            event.defaultPrevented ||
            props.disabled ||
            props.readOnly ||
            !onPasteImage
          )
            return;
          const image = pastedImage(event.clipboardData);
          if (!image) return;
          event.preventDefault();
          onPasteImage(image);
        }}
        onChange={(event) => {
          onDraftChange?.(
            event.target.value,
            reconcileMentions(text, event.target.value, mentions),
          );
          props.onChange?.(event);
          setCaret(event.target.selectionStart);
          setDismissed(undefined);
          realtime.typing(!!event.target.value.trim());
        }}
        onBlur={(event) => {
          setCaret(undefined);
          realtime.typing(false);
          props.onBlur?.(event);
        }}
        onKeyDown={(event) => {
          if (
            !event.nativeEvent.isComposing &&
            !event.ctrlKey &&
            !event.metaKey &&
            !event.altKey &&
            !event.shiftKey &&
            open &&
            ["ArrowDown", "ArrowUp", "Enter", "Tab", "Escape"].includes(
              event.key,
            )
          ) {
            event.preventDefault();
            if (event.key === "Escape") setDismissed(queryKey);
            else if (event.key === "ArrowDown")
              setActiveOption((value) => (value + 1) % options.length);
            else if (event.key === "ArrowUp")
              setActiveOption(
                (value) => (value + options.length - 1) % options.length,
              );
            else
              selectMention(
                options[Math.min(activeOption, options.length - 1)],
              );
            return;
          }
          if (
            (onEditLatest || (editTarget && editMessage)) &&
            !text &&
            event.key === "ArrowUp" &&
            !event.shiftKey &&
            !event.ctrlKey &&
            !event.metaKey &&
            !event.altKey &&
            !event.nativeEvent.isComposing &&
            window.matchMedia("(min-width: 768px)").matches
          ) {
            event.preventDefault();
            if (onEditLatest) onEditLatest();
            else if (editTarget) editMessage?.(editTarget.chat, editTarget.row);
            return;
          }
          props.onKeyDown?.(event);
          if (
            !event.defaultPrevented &&
            event.key === "Enter" &&
            !event.shiftKey &&
            !event.ctrlKey &&
            !event.metaKey &&
            !event.altKey &&
            !event.nativeEvent.isComposing &&
            window.matchMedia("(min-width: 768px)").matches
          ) {
            event.preventDefault();
            const form = event.currentTarget.form;
            const submit = form?.querySelector<HTMLButtonElement>(
              'button:not([type]), button[type="submit"]',
            );
            if (submit && !submit.disabled) form?.requestSubmit(submit);
          }
        }}
      />
      {open &&
        createPortal(
          <div
            id={listId}
            role="listbox"
            aria-label={t("mentions.choose")}
            className="composer-mention-menu"
            style={{ position: "fixed", ...position }}
          >
            {options.map((candidate, index) => (
              <button
                key={candidate.identity_id}
                id={`${listId}-${index}`}
                type="button"
                role="option"
                tabIndex={-1}
                aria-selected={
                  index === Math.min(activeOption, options.length - 1)
                }
                onPointerDown={(event) => event.preventDefault()}
                onMouseDown={(event) => event.preventDefault()}
                onClick={() => selectMention(candidate)}
              >
                <span>{candidate.label}</span>
                {mentionCandidates.some(
                  (other) =>
                    other.identity_id !== candidate.identity_id &&
                    other.label === candidate.label,
                ) && <small>{candidate.identity_id.slice(0, 12)}</small>}
              </button>
            ))}
          </div>,
          input.current?.closest("dialog") ?? document.body,
        )}
    </>
  );
}
