import { invoke } from "@tauri-apps/api/core";
import { en } from "./locales/en";

const isTauri = () =>
  typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
const messages = new Map<string, string>(
  Object.entries(en)
    .filter(([, text]) => !text.includes("{"))
    .map(([key, text]) => [text, key]),
);
const seen = new Map<string, number>();

/** Only semantic keys and operation names enter IPC, never exception contents. */
export function diagnostic(
  kind: "error" | "event",
  source: string,
  code: string,
  elapsedMs?: number,
) {
  if (!isTauri()) return;
  const now = Date.now();
  const key = `${kind}.${source}.${code}`;
  if (now - (seen.get(key) ?? 0) < 10_000) return;
  for (const [old, at] of seen) if (now - at > 10_000) seen.delete(old);
  if (seen.size >= 64) return;
  seen.set(key, now);
  void invoke("diagnostic_task", {
    request: {
      op: "event",
      kind,
      source,
      code,
      elapsed_ms: elapsedMs === undefined ? undefined : Math.round(elapsedMs),
    },
  }).catch(() => {});
}

export function diagnosticErrorMessage(message: string) {
  diagnostic("error", "ui", messages.get(message) ?? "error.generic");
}

export type DiagnosticStatus = {
  available: boolean;
  live_available?: boolean;
  enabled: boolean;
  installation?: string;
};
export async function setDiagnosticMode(
  enabled: boolean,
): Promise<DiagnosticStatus> {
  if (!isTauri()) return { available: false, enabled: false };
  return invoke("diagnostic_task", { request: { op: "set", enabled } });
}

let installed = false;
export function installDiagnostics(enabled: boolean) {
  if (installed) return;
  installed = true;
  void setDiagnosticMode(enabled).catch(() => {});
  // ErrorEvent.message, stack, filename and Promise rejection values may
  // include private data. The operation and UI breadcrumbs supply context.
  window.addEventListener("error", () =>
    diagnostic("error", "runtime", "javascript_error"),
  );
  window.addEventListener("unhandledrejection", () =>
    diagnostic("error", "runtime", "unhandled_rejection"),
  );
}
