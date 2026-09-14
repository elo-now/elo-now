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

/** Unknown backend warnings must remain visible instead of being discarded. */
export function warningText(
  code: string | undefined,
  fallback: string,
): string {
  if (code === "history_may_be_incomplete") return t("warning.history");
  if (code === "recovery_requires_review") return t("warning.recovery");
  return fallback;
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

/** Local display time, with a date at the start of a conversation list. */
export function formatMessageTime(
  value: string | undefined,
  includeDate = false,
): string {
  if (!value) return "";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return new Intl.DateTimeFormat(locale, {
    ...(includeDate
      ? ({ year: "numeric", month: "short", day: "numeric" } as const)
      : {}),
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
    year: "numeric",
    month: "short",
    day: "numeric",
  }).format(date);
}
