import { flushSync } from "react-dom";

/** Commit Back immediately; the destination content owns its entrance motion. */
export function navigateBack(
  navigate: () => void,
  stillCurrent: () => boolean,
): void {
  if (!stillCurrent()) return;
  flushSync(navigate);
}
