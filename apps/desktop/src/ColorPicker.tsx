import { useEffect, useId, useRef, useState, type PointerEvent } from "react";
import { Icon } from "./Icon";
import { t } from "./i18n";
import { hexToHsv, hsvToHex, normalizeHex, type Hsv } from "./color";

/** Edits a local draft; only Save updates the surrounding appearance. */
export function ColorPicker({
  label,
  value,
  onSave,
  onClose,
}: {
  label: string;
  value: string;
  onSave: (value: string) => void;
  onClose: () => void;
}) {
  const id = useId();
  const dialogRef = useRef<HTMLDialogElement>(null);
  const [hsv, setHsv] = useState(() => hexToHsv(value));
  const [hex, setHex] = useState(value.toUpperCase());
  const preview = hsvToHex(hsv);
  const valid = normalizeHex(hex);
  useEffect(() => {
    const dialog = dialogRef.current;
    dialog?.showModal();
    return () => dialog?.close();
  }, []);

  const update = (next: Hsv) => {
    setHsv(next);
    setHex(hsvToHex(next).toUpperCase());
  };
  const move = (event: PointerEvent<HTMLDivElement>) => {
    const bounds = event.currentTarget.getBoundingClientRect();
    if (!bounds.width || !bounds.height) return;
    update({
      ...hsv,
      s: Math.min(1, Math.max(0, (event.clientX - bounds.left) / bounds.width)),
      v:
        1 -
        Math.min(1, Math.max(0, (event.clientY - bounds.top) / bounds.height)),
    });
  };

  return (
    <dialog
      ref={dialogRef}
      className="dialog color-picker"
      aria-labelledby={`${id}-title`}
      onKeyDown={(event) => {
        if (event.key === "Escape") event.stopPropagation();
      }}
      onCancel={(event) => {
        event.preventDefault();
        onClose();
      }}
    >
      <button
        autoFocus
        type="button"
        className="icon close"
        aria-label={t("dialog.close")}
        onClick={onClose}
      >
        <Icon name="close" />
      </button>
      <h2 id={`${id}-title`}>{label}</h2>
      <form
        noValidate
        onSubmit={(event) => {
          event.preventDefault();
          if (valid) onSave(valid);
        }}
      >
        <div
          className="color-pad"
          style={{ backgroundColor: `hsl(${hsv.h} 100% 50%)` }}
          onPointerDown={(event) => {
            if (!event.isPrimary || event.button !== 0) return;
            event.preventDefault();
            event.currentTarget.setPointerCapture(event.pointerId);
            move(event);
          }}
          onPointerMove={(event) => {
            if (event.currentTarget.hasPointerCapture(event.pointerId))
              move(event);
          }}
          onPointerUp={(event) => {
            if (event.currentTarget.hasPointerCapture(event.pointerId)) {
              move(event);
              event.currentTarget.releasePointerCapture(event.pointerId);
            }
          }}
        >
          <span
            className="color-pad-thumb"
            aria-hidden="true"
            style={{
              left: `${hsv.s * 100}%`,
              top: `${(1 - hsv.v) * 100}%`,
              background: preview,
            }}
          />
          {/* Separate native sliders keep both axes accessible by keyboard and assistive technology. */}
          <input
            className="color-pad-accessible"
            type="range"
            min="0"
            max="100"
            value={Math.round(hsv.s * 100)}
            aria-label={t("picker.saturation")}
            onChange={(event) =>
              update({ ...hsv, s: Number(event.target.value) / 100 })
            }
          />
          <input
            className="color-pad-accessible"
            type="range"
            min="0"
            max="100"
            value={Math.round(hsv.v * 100)}
            aria-label={t("picker.brightness")}
            onChange={(event) =>
              update({ ...hsv, v: Number(event.target.value) / 100 })
            }
          />
        </div>
        <label className="color-hue-label" htmlFor={`${id}-hue`}>
          <span>{t("picker.hue")}</span>
          <span aria-hidden="true">{Math.round(hsv.h)}°</span>
        </label>
        <input
          id={`${id}-hue`}
          className="color-hue"
          type="range"
          min="0"
          max="360"
          value={Math.round(hsv.h)}
          onChange={(event) =>
            update({ ...hsv, h: Number(event.target.value) })
          }
          style={{ color: `hsl(${hsv.h} 100% 50%)` }}
        />
        <div className="color-picker-values">
          <label className="color-hex">
            <span>{t("picker.hex")}</span>
            <input
              type="text"
              value={hex}
              maxLength={7}
              spellCheck={false}
              autoCapitalize="characters"
              autoComplete="off"
              autoCorrect="off"
              enterKeyHint="done"
              aria-invalid={!valid}
              aria-describedby={`${id}-hex-help`}
              onChange={(event) => {
                setHex(event.target.value);
                const next = normalizeHex(event.target.value);
                if (!next) return;
                const parsed = hexToHsv(next);
                setHsv({
                  ...parsed,
                  h: parsed.s === 0 ? hsv.h : parsed.h,
                  s: parsed.v === 0 ? hsv.s : parsed.s,
                });
              }}
              onBlur={() => {
                if (valid) setHex(valid.toUpperCase());
              }}
            />
          </label>
          <div className="color-preview">
            <span>{t("picker.current")}</span>
            <i style={{ background: value }} />
          </div>
          <div className="color-preview">
            <span>{t("picker.new")}</span>
            <i style={{ background: preview }} />
          </div>
        </div>
        <p id={`${id}-hex-help`} className="color-hex-help">
          {t("picker.hexHelp")}
        </p>
        <button type="submit" disabled={!valid}>
          {t("picker.save")}
        </button>
      </form>
    </dialog>
  );
}
