import { useEffect, useMemo, useSyncExternalStore } from "react";
import { OutgoingMessages, withOutgoingMessages } from "./outgoingMessages";
import type { MessageRow } from "./messageThreads";

export function useOutgoingMessages(
  profile: string,
  scope: string,
  rows: MessageRow[],
  replies: MessageRow[],
) {
  // A locked or switched profile gets a separate store. Late native completions
  // can only update the old store, never another profile's history.
  const store = useMemo(() => new OutgoingMessages(), [profile]);
  const echoes = useSyncExternalStore(
    store.subscribe,
    store.snapshot,
    store.snapshot,
  );
  useEffect(
    () => store.observe(scope, [...rows, ...replies]),
    [store, scope, rows, replies, echoes],
  );
  return {
    send: store.send.bind(store),
    rows: withOutgoingMessages(rows, echoes, scope),
    replies: withOutgoingMessages(replies, echoes, scope),
  };
}
