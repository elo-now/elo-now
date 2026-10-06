import { acceptView } from "./liveSync";
import type { View } from "./model";

/** A native request can finish after navigation or while a React update waits.
 * Keep both its view and its receive lease inside the originating conversation. */
export async function retrieveUnavailableMessage({
  identity,
  space,
  scope,
  currentScope,
  request,
  updateView,
  receive,
}: {
  identity: string;
  space: View["active_space"];
  scope: string;
  currentScope: () => string | undefined;
  request: () => Promise<{ view?: View }>;
  updateView: (update: (current: View | null) => View | null) => void;
  receive: () => void | (() => void);
}): Promise<void | (() => void)> {
  const result = await request();
  if (currentScope() !== scope) return;
  const next = result.view;
  if (next) {
    updateView((current) => {
      if (
        currentScope() !== scope ||
        current?.identity !== identity ||
        current.active_space !== space ||
        next.active_space !== space
      )
        return current;
      return acceptView(current, next);
    });
  }
  return receive();
}
