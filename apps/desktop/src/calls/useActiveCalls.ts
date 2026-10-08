import { useSyncExternalStore } from "react";
import type { View } from "../model";
import type { Calls } from "./controller";
import { activeSessions } from "./sessionPresence";

/** A local join and discoverable sessions remain visible after minimizing. */
export function useActiveCalls(calls: Calls, view: View | null) {
  const getSnapshot = () => {
    if (!view) return false;
    const state = calls.getSnapshot();
    return !!state.active || activeSessions(view, state.available).length > 0;
  };
  // The boolean snapshot avoids rerendering navigation on media tile updates.
  return useSyncExternalStore(calls.subscribe, getSnapshot, getSnapshot);
}
