import { useSyncExternalStore } from "react";

let required = false;
const listeners = new Set<() => void>();
export const updateRequired = () => required;
export function setUpdateRequired(value: boolean) {
  if (required === value) return;
  required = value;
  listeners.forEach((notify) => notify());
}
export function subscribeUpdateRequired(notify: () => void) {
  listeners.add(notify);
  return () => {
    listeners.delete(notify);
  };
}
export function useUpdateRequired() {
  return useSyncExternalStore(
    subscribeUpdateRequired,
    updateRequired,
    updateRequired,
  );
}
