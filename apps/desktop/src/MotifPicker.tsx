import { useState } from "react";
import { ActionDialog } from "./ActionDialog";
import { Icon } from "./Icon";
import { t } from "./i18n";
import { motifEmoji, motifImage, motifs, type Motif } from "./motifs";
import "./motifs.css";

function MotifPreview({ motif }: { motif: Motif }) {
  const emoji = motifEmoji(motif);
  return (
    <span
      className={`motif-art ${motif === "none" ? "motif-art-none" : emoji ? "motif-art-emoji" : ""}`}
      aria-hidden="true"
      style={
        motif === "none"
          ? undefined
          : emoji
            ? { backgroundImage: motifImage(motif) }
            : {
                maskImage: motifImage(motif),
                WebkitMaskImage: motifImage(motif),
              }
      }
    />
  );
}

export function MotifPicker({
  value,
  onChange,
}: {
  value: Motif;
  onChange: (motif: Motif) => void;
}) {
  const [anchor, setAnchor] = useState<DOMRect | null>(null);
  return (
    <>
      <h3 id="appearance-motif-label">{t("motif.label")}</h3>
      <button
        type="button"
        className="motif-selector"
        aria-haspopup="dialog"
        aria-expanded={!!anchor}
        aria-labelledby="appearance-motif-label appearance-motif-value"
        onClick={(event) => {
          event.currentTarget.focus({ preventScroll: true });
          setAnchor(event.currentTarget.getBoundingClientRect());
        }}
      >
        <MotifPreview motif={value} />
        <span id="appearance-motif-value">{t(`motif.${value}`)}</span>
        <Icon name="next" />
      </button>
      {anchor && (
        <ActionDialog
          title={t("motif.label")}
          anchor={anchor}
          compact
          className="motif-popover"
          onClose={() => setAnchor(null)}
        >
          <div className="motif-grid">
            {motifs.map((motif) => (
              <button
                key={motif}
                type="button"
                aria-pressed={value === motif}
                onClick={() => {
                  onChange(motif);
                  setAnchor(null);
                }}
              >
                <MotifPreview motif={motif} />
                <span>{t(`motif.${motif}`)}</span>
                {value === motif && (
                  <span className="motif-selected">
                    <Icon name="check" />
                  </span>
                )}
              </button>
            ))}
          </div>
        </ActionDialog>
      )}
    </>
  );
}
