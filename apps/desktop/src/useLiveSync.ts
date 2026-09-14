import { useEffect, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import type { View } from "./model";
import { startLiveSync, type SyncResult, type SyncProgress } from "./liveSync";

export function useLiveSync(
  view: View | null,
  conversation: boolean,
  busy: boolean,
  onResult: (result: SyncResult) => void,
  suspended: () => boolean = () => false,
) {
  const [progress, setProgress] = useState<SyncProgress>(null);
  const latest = useRef({ view, conversation, busy, onResult, suspended });
  latest.current = { view, conversation, busy, onResult, suspended };
  const worker = useRef<ReturnType<typeof startLiveSync> | undefined>(
    undefined,
  );
  useEffect(() => {
    setProgress(null);
    if (!view) return;
    const identity = view.identity;
    const loop = startLiveSync(
      identity,
      () => ({
        conversation: latest.current.conversation,
        busy: latest.current.busy || latest.current.suspended(),
        messages:
          !!latest.current.view?.replicas.length ||
          !!latest.current.view?.spaces?.some(
            (space) => space.status === "joined",
          ),
        invitations:
          !!latest.current.view?.invitations?.enabled ||
          !!latest.current.view?.spaces?.length,
      }),
      (op, force = false) =>
        invoke<SyncResult>("operate", {
          request: { op, force, expected_identity: identity },
        }),
      (result) => latest.current.onResult(result),
      setProgress,
    );
    worker.current = loop;
    return () => {
      loop.stop();
      worker.current = undefined;
    };
  }, [view?.identity]);
  useEffect(() => {
    worker.current?.changed();
  }, [
    conversation,
    view?.replicas.length,
    view?.invitations?.enabled,
    view?.spaces?.length,
  ]);
  // This also covers reactions/pins committed through shared message actions.
  const pending = useRef(view?.counts.pending ?? 0);
  useEffect(() => {
    const count = view?.counts.pending ?? 0;
    if (count > pending.current) worker.current?.request();
    pending.current = count;
  }, [view?.identity, view?.counts.pending]);
  return {
    progress,
    request: (membership = false) => worker.current?.request(membership),
  };
}
