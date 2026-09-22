import { useState } from "react";
import { DrawMotif } from "./DrawMotif";
import { type CustomMotif } from "./customMotif";
import { ActionDialog } from "./ActionDialog";
import { Icon } from "./Icon";
import { t } from "./i18n";
import { motifEmoji, motifImage, motifs, type Motif } from "./motifs";
import "./motifs.css";

function MotifPreview({
  motif,
  drawing = null,
}: {
  motif: Motif;
  drawing?: CustomMotif | null;
}) {
  const emoji = motifEmoji(motif);
  const image = motifImage(motif, "#000000", 1, 0, drawing);
  return (
    <span
      className={`motif-art ${motif === "none" ? "motif-art-none" : emoji ? "motif-art-emoji" : ""}`}
      aria-hidden="true"
      style={
        motif === "none"
          ? undefined
          : emoji
            ? { backgroundImage: image }
            : {
                maskImage: image,
                WebkitMaskImage: image,
              }
      }
    />
  );
}

export function MotifPicker({
  value,
  onChange,
  drawing,
  onDrawing,
}: {
  value: Motif;
  onChange: (motif: Motif) => void;
  drawing: CustomMotif | null;
  onDrawing: (drawing: CustomMotif) => boolean;
}) {
  const [anchor, setAnchor] = useState<DOMRect | null>(null);
  const [drawOpen, setDrawOpen] = useState(false);
  return (
    <>
      <h3 id="appearance-motif-label">{t("motif.label")}</h3>
      <button
        type="button"
        className="motif-selector"
        aria-haspopup="dialog"
        aria-expanded={!!anchor || drawOpen}
        aria-labelledby="appearance-motif-label appearance-motif-value"
        onClick={(event) => {
          event.currentTarget.focus({ preventScroll: true });
          setAnchor(event.currentTarget.getBoundingClientRect());
        }}
      >
        <MotifPreview motif={value} drawing={drawing} />
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
            <button
              type="button"
              className="motif-custom-tile"
              aria-pressed={value === "custom"}
              onClick={() => {
                setAnchor(null);
                setDrawOpen(true);
              }}
            >
              {drawing ? (
                <MotifPreview motif="custom" drawing={drawing} />
              ) : (
                <span className="motif-draw-icon" aria-hidden="true">
                  <Icon name="edit" />
                </span>
              )}
              <span>{t(drawing ? "motif.draw.edit" : "motif.draw.title")}</span>
              {value === "custom" && (
                <span className="motif-selected">
                  <Icon name="check" />
                </span>
              )}
            </button>
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
      {drawOpen && (
        <DrawMotif
          value={drawing}
          onClose={() => setDrawOpen(false)}
          onSave={(next) => {
            if (!onDrawing(next)) return false;
            setDrawOpen(false);
            return true;
          }}
        />
      )}
    </>
  );
}
