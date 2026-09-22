import { t } from "./i18n";
export type RecoveryStep = {
  request: string;
  stage:
    "unlocking" | "unpacking" | "checking" | "saving" | "opening" | "ready";
  done: number;
  total: number;
};
export function acceptsRecoveryStep(
  value: unknown,
  request: string,
): value is RecoveryStep {
  if (!value || typeof value !== "object") return false;
  const step = value as RecoveryStep;
  return (
    step.request === request &&
    [
      "unlocking",
      "unpacking",
      "checking",
      "saving",
      "opening",
      "ready",
    ].includes(step.stage) &&
    Number.isSafeInteger(step.done) &&
    Number.isSafeInteger(step.total) &&
    step.done >= 0 &&
    step.total >= step.done
  );
}
export function RecoveryProgress({
  value,
  paused,
  pausing,
  onPause,
}: {
  value: RecoveryStep | null;
  paused: boolean;
  pausing: boolean;
  onPause?: () => void;
}) {
  if (!value && !paused) return null;
  return (
    <div
      className="recovery-progress"
      data-paused={paused}
      role="status"
      aria-live="polite"
    >
      <p>
        {paused
          ? t("recover.progressPaused")
          : t(`recover.progress.${value!.stage}`)}
      </p>
      {!paused && (
        <progress
          aria-label={t(`recover.progress.${value!.stage}`)}
          max={value!.total || 1}
          value={value!.total ? value!.done : undefined}
        />
      )}
      {!paused && <small>{t("recover.progressKeepOpen")}</small>}
      {onPause && !paused && (
        <button
          type="button"
          className="secondary"
          disabled={pausing}
          onClick={onPause}
        >
          {t(pausing ? "recover.progressPausing" : "recover.progressPause")}
        </button>
      )}
    </div>
  );
}
