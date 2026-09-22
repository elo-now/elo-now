let holds = 0;

/** Pause new background passes while a foreground setup flow owns the UI.
 * Existing operations finish normally; nested owners release independently. */
export function pauseBackgroundSync(): () => void {
  holds++;
  let released = false;
  return () => {
    if (released) return;
    released = true;
    holds--;
  };
}

export function backgroundSyncPaused(): boolean {
  return holds > 0;
}
