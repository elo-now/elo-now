/** Release capture immediately and give signed Leave a short chance before locking. */
export async function leaveBeforeLock(
  calls: { leave(reason: string): Promise<void> },
  lock: () => Promise<unknown>,
) {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    await Promise.race([
      calls.leave("profile_locked").catch(() => {}),
      new Promise<void>((resolve) => {
        timer = setTimeout(resolve, 400);
      }),
    ]);
  } finally {
    clearTimeout(timer);
    await lock();
  }
}
