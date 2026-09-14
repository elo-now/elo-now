import { useId, useRef, useState, type RefObject } from "react";
import { flushSync } from "react-dom";
import { Icon } from "./Icon";
import { t } from "./i18n";

type SearchProps = {
  label: string;
  value: string;
  onChange: (value: string) => void;
  disabled?: boolean;
};

export function SearchField({
  label,
  value,
  onChange,
  inputRef,
  id,
  className = "",
  disabled = false,
}: SearchProps & {
  inputRef?: RefObject<HTMLInputElement | null>;
  id?: string;
  className?: string;
}) {
  const localRef = useRef<HTMLInputElement>(null);
  const input = inputRef ?? localRef;
  return (
    <div className={`search-field ${className}`}>
      <input
        ref={input}
        id={id}
        className="search-input"
        type="search"
        disabled={disabled}
        value={value}
        aria-label={label}
        placeholder={label}
        autoComplete="off"
        autoCapitalize="none"
        autoCorrect="off"
        spellCheck={false}
        enterKeyHint="search"
        onKeyDown={(event) => {
          if (event.key === "Enter") {
            event.preventDefault();
            event.currentTarget.blur();
          }
        }}
        onChange={(event) => onChange(event.target.value)}
      />
      {value && (
        <button
          type="button"
          className="search-clear"
          disabled={disabled}
          aria-label={t("search.clear")}
          onPointerDown={(event) => event.preventDefault()}
          onClick={() => {
            onChange("");
            input.current?.focus({ preventScroll: true });
          }}
        >
          <Icon name="close" />
        </button>
      )}
    </div>
  );
}

/** Shared list search; filtering stays with the caller. */
export function FloatingSearch({
  label,
  value,
  onChange,
  disabled = false,
}: SearchProps) {
  const [expanded, setExpanded] = useState(!!value);
  const input = useRef<HTMLInputElement>(null);
  const toggleButton = useRef<HTMLButtonElement>(null);
  const inputId = useId();
  const open = () => {
    // WebKit only opens the software keyboard while still inside the tap.
    // Remove inert before focusing, rather than waiting for an effect/animation.
    flushSync(() => {
      setExpanded(true);
    });
    input.current?.focus({ preventScroll: true });
  };
  const close = () => {
    input.current?.blur();
    onChange("");
    setExpanded(false);
    toggleButton.current?.focus({ preventScroll: true });
  };
  return (
    <div
      className="floating-search"
      data-expanded={expanded}
      onKeyDown={(event) => {
        if (event.key === "Escape" && expanded) {
          event.preventDefault();
          close();
        }
      }}
    >
      <div className="search-orb">
        <div className="search-expand" inert={!expanded}>
          <SearchField
            label={label}
            value={value}
            onChange={onChange}
            inputRef={input}
            id={inputId}
            disabled={disabled}
          />
        </div>
        <button
          ref={toggleButton}
          type="button"
          className="search-toggle"
          aria-label={expanded ? t("search.close") : label}
          aria-expanded={expanded}
          aria-controls={inputId}
          disabled={disabled}
          onPointerDown={(event) => event.preventDefault()}
          onClick={expanded ? close : open}
        >
          <Icon name="search" />
        </button>
      </div>
    </div>
  );
}
