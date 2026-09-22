import { useEffect, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
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
  useEffect(() => {
    if (!view) return;
    let active = true;
    // Native desktop delivery continues while the WebView is hidden. Mobile
    // keeps its existing push/resume flow and never emits this event.
    const listener = listen<SyncResult>("desktop-sync", ({ payload }) => {
      const identity = payload.view?.identity ?? payload.identity;
      if (active && identity === latest.current.view?.identity)
        latest.current.onResult(payload);
    });
    return () => {
      active = false;
      void listener.then((unlisten) => unlisten());
    };
  }, [view?.identity]);
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
      (op, force = false, receiveOnly = false) =>
        invoke<SyncResult>("operate", {
          request: {
            op,
            force,
            foreground: true,
            expected_identity: identity,
            ...(receiveOnly
              ? {
                  receive_only: true,
                  target_space: latest.current.view?.active_space,
                  expected_space: latest.current.view?.active_space,
                }
              : {}),
          },
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
