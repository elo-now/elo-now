import { useEffect, useMemo, useRef, useState, type PointerEvent } from "react";
import { ActionDialog } from "./ActionDialog";
import { t } from "./i18n";
import {
  DRAW_SIZE,
  DRAW_WIDTH,
  MAX_DRAW_POINTS,
  MAX_DRAW_STROKES,
  strokePath,
  type CustomMotif,
  type DrawPoint,
  type DrawStroke,
} from "./customMotif";

export function DrawMotif({
  value,
  onSave,
  onClose,
}: {
  value: CustomMotif | null;
  onSave: (drawing: CustomMotif) => boolean;
  onClose: () => void;
}) {
  const [strokes, setStrokes] = useState<DrawStroke[]>(value?.strokes ?? []);
  const [smooth, setSmooth] = useState(value?.smooth ?? true);
  const [livePath, setLivePath] = useState("");
  const [full, setFull] = useState(false);
  const [saveFailed, setSaveFailed] = useState(false);
  const [undoCount, setUndoCount] = useState(0);
  const active = useRef<{ pointer: number; points: DrawStroke } | null>(null);
  const frame = useRef<number | null>(null);
  const undo = useRef<DrawStroke[][]>([]);
  const pointCount = useMemo(
    () => strokes.reduce((n, stroke) => n + stroke.length, 0),
    [strokes],
  );
  const paths = useMemo(
    () => strokes.map((stroke) => strokePath(stroke, smooth)),
    [strokes, smooth],
  );
  useEffect(
    () => () => {
      if (frame.current !== null) cancelAnimationFrame(frame.current);
    },
    [],
  );

  function replace(next: DrawStroke[]) {
    undo.current.push(strokes);
    if (undo.current.length > MAX_DRAW_STROKES) undo.current.shift();
    setUndoCount(undo.current.length);
    setStrokes(next);
    setFull(false);
  }
  function sample(
    event: globalThis.PointerEvent,
    area: SVGSVGElement,
  ): DrawPoint {
    const box = area.getBoundingClientRect();
    const inset = DRAW_WIDTH / 2 + 1;
    const bound = (n: number) =>
      Math.round(Math.min(DRAW_SIZE - inset, Math.max(inset, n)) * 100) / 100;
    return [
      bound(((event.clientX - box.left) / box.width) * DRAW_SIZE),
      bound(((event.clientY - box.top) / box.height) * DRAW_SIZE),
    ];
  }
  function append(event: PointerEvent<SVGSVGElement>) {
    const current = active.current;
    if (!current || current.pointer !== event.pointerId) return;
    event.preventDefault();
    event.stopPropagation();
    const samples = event.nativeEvent.getCoalescedEvents?.() ?? [];
    for (const item of samples.length ? samples : [event.nativeEvent]) {
      const point = sample(item, event.currentTarget);
      const last = current.points[current.points.length - 1];
      if (Math.hypot(point[0] - last[0], point[1] - last[1]) < 0.65) continue;
      if (pointCount + current.points.length >= MAX_DRAW_POINTS) {
        setFull(true);
        break;
      }
      current.points.push(point);
    }
    if (frame.current === null)
      frame.current = requestAnimationFrame(() => {
        frame.current = null;
        if (active.current)
          setLivePath(strokePath(active.current.points, smooth));
      });
  }
  function finish(event: PointerEvent<SVGSVGElement>) {
    if (active.current?.pointer !== event.pointerId) return;
    if (event.type === "pointerup") append(event);
    const points = active.current.points;
    active.current = null;
    if (frame.current !== null) cancelAnimationFrame(frame.current);
    frame.current = null;
    replace([...strokes, points]);
    setLivePath("");
    if (event.currentTarget.hasPointerCapture(event.pointerId))
      event.currentTarget.releasePointerCapture(event.pointerId);
  }

  return (
    <ActionDialog
      page
      title={t("motif.draw.title")}
      className="draw-motif-dialog"
      onClose={onClose}
    >
      <div className="draw-motif-content">
        <div className="draw-motif-board">
          <svg
            viewBox={`0 0 ${DRAW_SIZE} ${DRAW_SIZE}`}
            role="img"
            aria-label={t("motif.draw.area")}
            onPointerDown={(event) => {
              if (!event.isPrimary || event.button !== 0 || active.current)
                return;
              event.preventDefault();
              event.stopPropagation();
              if (
                strokes.length >= MAX_DRAW_STROKES ||
                pointCount >= MAX_DRAW_POINTS
              ) {
                setFull(true);
                return;
              }
              event.currentTarget.setPointerCapture(event.pointerId);
              const points = [sample(event.nativeEvent, event.currentTarget)];
              active.current = { pointer: event.pointerId, points };
              setLivePath(strokePath(points, smooth));
            }}
            onPointerMove={append}
            onPointerUp={finish}
            onPointerCancel={finish}
            onLostPointerCapture={finish}
          >
            <g
              fill="none"
              stroke="currentColor"
              strokeWidth={DRAW_WIDTH}
              strokeLinecap="round"
              strokeLinejoin="round"
            >
              {paths.map((path, i) => (
                <path key={i} d={path} />
              ))}
              {livePath && <path d={livePath} />}
            </g>
          </svg>
          {!strokes.length && !livePath && (
            <span className="draw-motif-placeholder">
              {t("motif.draw.here")}
            </span>
          )}
        </div>
        <button
          type="button"
          className="settings-toggle draw-motif-smoothing"
          role="switch"
          aria-checked={smooth}
          disabled={!!livePath}
          onClick={() => setSmooth(!smooth)}
        >
          <span>{t("motif.draw.smooth")}</span>
          <span className="toggle-track" aria-hidden="true">
            <span />
          </span>
        </button>
        <div className="draw-motif-tools">
          <button
            type="button"
            className="secondary"
            disabled={!undoCount || !!livePath}
            onClick={() => {
              const previous = undo.current.pop();
              if (previous) {
                setStrokes(previous);
                setUndoCount(undo.current.length);
                setFull(false);
              }
            }}
          >
            {t("motif.draw.undo")}
          </button>
          <button
            type="button"
            className="secondary"
            disabled={!strokes.length || !!livePath}
            onClick={() => replace([])}
          >
            {t("motif.draw.clear")}
          </button>
        </div>
        {full && (
          <p className="draw-motif-limit" role="status">
            {t("motif.draw.full")}
          </p>
        )}
        {saveFailed && (
          <p className="draw-motif-error" role="alert">
            {t("motif.draw.saveFailed")}
          </p>
        )}
        <div className="draw-motif-actions">
          <button type="button" className="secondary" onClick={onClose}>
            {t("dialog.cancel")}
          </button>
          <button
            type="button"
            disabled={!strokes.length || !!livePath}
            onClick={() => setSaveFailed(!onSave({ v: 1, smooth, strokes }))}
          >
            {t("picker.save")}
          </button>
        </div>
      </div>
    </ActionDialog>
  );
}
