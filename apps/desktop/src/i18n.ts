import { en } from "./locales/en";

export const locale = "en";
export type MessageKey = keyof typeof en;

/** Sentence case for displayed errors; backend values and logs stay intact. */
export function errorText(message: string): string {
  return message.replace(
    /^(\s*)(\p{Ll})/u,
    (_, space: string, initial: string) =>
      space + initial.toLocaleUpperCase(locale),
  );
}

/** Render a whole message; values are inserted once and never parsed as copy. */
export function t(
  key: MessageKey,
  values: Record<string, string | number> = {},
): string {
  return en[key].replace(/\{(\w+)\}/g, (_, name: string) => {
    if (!Object.prototype.hasOwnProperty.call(values, name)) {
      throw new Error(`Missing message value: ${key}.${name}`);
    }
    return typeof values[name] === "number"
      ? new Intl.NumberFormat(locale).format(values[name])
      : String(values[name]);
  });
}

/** Compact, locale-aware size for attachment UI; canonical values stay in bytes. */
export function formatFileSize(bytes: number): string {
  const safeBytes = Number.isFinite(bytes) ? Math.max(0, bytes) : 0;
  const units = ["B", "KB", "MB"] as const;
  let value = safeBytes;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  const maximumFractionDigits = unit === 0 || value >= 10 ? 0 : 1;
  return `${new Intl.NumberFormat(locale, { maximumFractionDigits }).format(value)} ${units[unit]}`;
}

/** Unknown backend warnings must remain visible instead of being discarded. */
export function warningText(
  code: string | undefined,
  fallback: string,
): string {
  if (code === "history_may_be_incomplete") return t("warning.history");
  if (code === "recovery_requires_review") return t("warning.recovery");
  return fallback;
}

export function formatInvitationValidity(value: number): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "";
  return t("spaces.validUntil", {
    date: new Intl.DateTimeFormat(locale, {
      year: "numeric",
      month: "short",
      day: "numeric",
    }).format(date),
    time: new Intl.DateTimeFormat(locale, {
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      hourCycle: "h23",
      timeZoneName: "short",
    }).format(date),
  });
}

export function formatTimestamp(
  value: string | undefined,
  timeZone?: string,
): string {
  if (!value) return "";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return new Intl.DateTimeFormat(locale, {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hourCycle: "h23",
    timeZone,
    timeZoneName: "short",
  }).format(date);
}

/** Compact local display time; the canonical timestamp retains its year. */
export function formatMessageTime(
  value: string | undefined,
  includeDate = false,
): string {
  if (!value) return "";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return new Intl.DateTimeFormat(locale, {
    ...(includeDate ? ({ month: "short", day: "numeric" } as const) : {}),
    hour: "2-digit",
    minute: "2-digit",
    hourCycle: "h23",
  }).format(date);
}

/** Group adjacent messages by the reader's calendar day, not their UTC date. */
export function messageDayKey(
  value: string | undefined,
  timeZone?: string,
): string {
  const date = value ? new Date(value) : null;
  if (!date || Number.isNaN(date.getTime())) return "unknown";
  const parts = new Intl.DateTimeFormat("en-US", {
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    timeZone,
  }).formatToParts(date);
  return ["year", "month", "day"]
    .map((type) => parts.find((part) => part.type === type)!.value)
    .join("-");
}

export function formatMessageDay(value: string | undefined): string {
  const date = value ? new Date(value) : null;
  if (!date || Number.isNaN(date.getTime()))
    return t("message.dateUnavailable");
  return new Intl.DateTimeFormat(locale, {
    weekday: "short",
    month: "short",
    day: "numeric",
  }).format(date);
}
