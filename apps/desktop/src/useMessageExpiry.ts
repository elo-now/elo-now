import { useEffect, useMemo, useState } from "react";
import { expireMessageRows, expireView } from "./messageExpiry";
import type { MessageRow } from "./messageThreads";
import type { View } from "./model";

/** Wake at the nearest deadline or resume; no polling and no network requests. */
function useExpiryClock(rows: MessageRow[]) {
  const [clock, update] = useState(Date.now);
  const now = Date.now();
  const next = rows.reduce<number | undefined>((nearest, row) => {
    const deadline = row.body.payload?.expires_at_ms;
    return deadline != null &&
      deadline > now &&
      (nearest == null || deadline < nearest)
      ? deadline
      : nearest;
  }, undefined);
  useEffect(() => {
    const tick = () => update(Date.now());
    const timer =
      next == null
        ? undefined
        : setTimeout(
            tick,
            Math.min(Math.max(0, next - Date.now()), 2_147_483_647),
          );
    document.addEventListener("visibilitychange", tick);
    window.addEventListener("focus", tick);
    return () => {
      clearTimeout(timer);
      document.removeEventListener("visibilitychange", tick);
      window.removeEventListener("focus", tick);
    };
  }, [next]);
  return clock;
}

export function useExpiringRows(rows: MessageRow[]) {
  const clock = useExpiryClock(rows);
  return useMemo(() => expireMessageRows(rows, Date.now()), [rows, clock]);
}

export function useExpiringView(view: View | null) {
  const rows = [...(view?.streams ?? []), ...(view?.all_streams ?? [])].flatMap(
    (stream) => stream.rows,
  );
  const clock = useExpiryClock(rows);
  return useMemo(() => expireView(view, Date.now()), [view, clock]);
}
