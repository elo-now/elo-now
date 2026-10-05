/** Inclusive ECMAScript Date limit; keep expiry bounds aligned with record.rs. */
export const MAX_TIMESTAMP_MS = 8_640_000_000_000_000;

export function isTimestampMs(value: unknown): value is number {
  return (
    typeof value === "number" &&
    Number.isSafeInteger(value) &&
    value >= 0 &&
    value <= MAX_TIMESTAMP_MS
  );
}

export function isExpiryTimestamp(value: unknown): value is number {
  return isTimestampMs(value) && value > 0;
}

/** Persisted or remote timestamps must be checked before Date.toISOString. */
export function timestampIso(value: unknown): string | undefined {
  return isTimestampMs(value) ? new Date(value).toISOString() : undefined;
}
