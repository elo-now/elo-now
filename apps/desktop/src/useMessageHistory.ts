import { useEffect, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import type { Stream, View } from "./model";
import {
  mergeHistory,
  sameHistoryScope,
  preparedHistoryMatches,
  type HistoryPage,
} from "./messageHistory";
import { useToast } from "./Toast";

export function useMessageHistory(
  view: View | null,
  chat: Stream | undefined,
  active: boolean,
  query: string,
  thread?: string,
  around?: string,
  prepared?: HistoryPage,
) {
  const enabled = !!(view?.paged && chat && active);
  const key = JSON.stringify([
    view?.identity,
    view?.active_space,
    chat?.space,
    chat?.stream,
    query.trim(),
    thread,
    around,
  ]);
  const [state, setState] = useState<{
    key: string;
    rows: Stream["rows"];
    context: Stream["rows"];
    next: string | null;
    newer?: string | null;
    ready: boolean;
    loading: boolean;
    failed?: boolean;
  }>({
    key: "",
    rows: [],
    context: [],
    next: null,
    ready: false,
    loading: false,
  });
  const { reportError } = useToast();
  const seed: typeof state | undefined =
    view &&
    chat &&
    preparedHistoryMatches(
      prepared,
      view.identity,
      view.active_space,
      chat.space,
      chat.stream,
      around,
      thread,
      query,
    )
      ? {
          key,
          rows: prepared!.rows,
          context: prepared!.context,
          next: prepared!.next,
          newer: prepared!.newer,
          ready: true,
          loading: false,
        }
      : undefined;
  const current = state.key === key ? state : seed;
  const generation = useRef(0);
  const inFlight = useRef<
    { key: string; epoch: number; refresh: boolean } | undefined
  >(undefined);
  const latest = useRef({ view, chat, key, state });
  latest.current = { view, chat, key, state: current ?? state };
  const request = async (before?: string, forward = false) => {
    const current = latest.current;
    if (!current.view || !current.chat) return;
    const epoch = generation.current;
    if (
      inFlight.current?.key === current.key &&
      inFlight.current.epoch === epoch
    ) {
      // Background revisions can arrive while the native reader is queued.
      // Keep its first valid page and coalesce changes into one later refresh.
      if (!before) inFlight.current.refresh = true;
      return;
    }
    const flight = { key: current.key, epoch, refresh: false };
    inFlight.current = flight;
    setState((old) =>
      old.key === current.key
        ? { ...old, loading: true, failed: false }
        : {
            key: current.key,
            rows: [],
            context: [],
            next: null,
            ready: false,
            loading: true,
          },
    );
    try {
      const response = await invoke<{ history: HistoryPage }>("operate", {
        request: {
          op: "history_page",
          expected_identity: current.view.identity,
          expected_space: current.view.active_space,
          space: current.chat.space,
          stream: current.chat.stream,
          before,
          query,
          thread,
          forward,
          around:
            before ||
            (current.state.key === current.key &&
              current.state.ready &&
              !current.state.newer)
              ? undefined
              : around,
        },
      });
      const page = response.history;
      if (
        generation.current !== epoch ||
        latest.current.key !== current.key ||
        !sameHistoryScope(
          page,
          current.view.identity,
          current.view.active_space,
          current.chat.space,
          current.chat.stream,
        )
      )
        return;
      setState((old) => {
        const same = old.key === current.key;
        return {
          key: current.key,
          rows: mergeHistory(same ? old.rows : [], page.rows),
          context: mergeHistory(same ? old.context : [], page.context),
          next: forward
            ? old.next
            : before || !same || !old.ready
              ? page.next
              : old.next,
          newer: forward
            ? page.next
            : before
              ? old.newer
              : page.newer
                ? (same && old.newer) || page.newer
                : null,
          ready: true,
          loading: true,
        };
      });
      if (!before && current.state.key === current.key) {
        const existing = mergeHistory(current.state.rows, current.state.context)
          .map((row) => row.id)
          .filter((id) => !page.rows.some((row) => row.id === id));
        for (let offset = 0; offset < existing.length; offset += 1000) {
          if (
            generation.current !== epoch ||
            latest.current.key !== current.key
          )
            break;
          const fresh = await invoke<{ history: HistoryPage }>("operate", {
            request: {
              op: "history_page",
              expected_identity: current.view.identity,
              expected_space: current.view.active_space,
              space: current.chat.space,
              stream: current.chat.stream,
              records: existing.slice(offset, offset + 1000),
            },
          });
          if (
            generation.current !== epoch ||
            !sameHistoryScope(
              fresh.history,
              current.view.identity,
              current.view.active_space,
              current.chat.space,
              current.chat.stream,
            )
          )
            break;
          setState((old) =>
            old.key === current.key
              ? {
                  ...old,
                  rows: mergeHistory(
                    old.rows,
                    fresh.history.rows.filter((row) =>
                      old.rows.some((item) => item.id === row.id),
                    ),
                  ),
                  context: mergeHistory(
                    old.context,
                    fresh.history.rows.filter((row) =>
                      old.context.some((item) => item.id === row.id),
                    ),
                  ),
                }
              : old,
          );
        }
      }
    } catch (error) {
      if (generation.current === epoch && latest.current.key === current.key) {
        setState((old) =>
          old.key === current.key ? { ...old, failed: true } : old,
        );
        reportError(error);
      }
    } finally {
      if (inFlight.current === flight) inFlight.current = undefined;
      if (generation.current === epoch)
        setState((old) =>
          old.key === current.key ? { ...old, loading: false } : old,
        );
      if (
        flight.refresh &&
        generation.current === epoch &&
        latest.current.key === current.key
      )
        setTimeout(() => {
          if (
            generation.current === epoch &&
            latest.current.key === current.key
          )
            void loader.current();
        }, 0);
    }
  };
  const loader = useRef(request);
  loader.current = request;
  useEffect(() => {
    generation.current++;
    return () => {
      generation.current++;
    };
  }, [key, enabled]);
  useEffect(() => {
    if (!enabled) return;
    if (seed && state.key !== key) {
      setState(seed);
      if (prepared!.revision >= (view?.revision ?? 0)) return;
    }
    const timer = setTimeout(
      () => void loader.current(),
      query.trim() ? 180 : 0,
    );
    return () => {
      clearTimeout(timer);
    };
  }, [key, enabled, view?.revision]);
  useEffect(() => {
    if (
      enabled &&
      (query.trim() || thread) &&
      current?.ready &&
      !current.loading &&
      !current.failed &&
      current.next &&
      current.rows.length < 50
    ) {
      const timer = setTimeout(() => void loader.current(current.next!), 0);
      return () => clearTimeout(timer);
    }
  }, [
    enabled,
    key,
    current?.next,
    current?.loading,
    current?.ready,
    current?.failed,
  ]);
  return {
    enabled,
    ready: !enabled || !!current?.ready,
    loading: enabled && (!current || current.loading),
    retry: () => loader.current(),
    hasNewer: enabled && !!current?.newer,
    loadNewer: async () => {
      if (current?.newer && !current.loading)
        await loader.current(current.newer, true);
    },
    rows: enabled
      ? mergeHistory(current?.rows ?? [], current?.context ?? [])
      : (chat?.rows ?? []),
    hasMore: enabled && !!current?.next,
    loadMore: async () => {
      if (current?.next && !current.loading) await loader.current(current.next);
    },
    markRead: (ids: string[]) =>
      setState((old) => {
        const mark = (rows: Stream["rows"]) =>
          rows.map((row) =>
            ids.includes(row.id)
              ? { ...row, unread: false, marked_unread: false }
              : row,
          );
        return { ...old, rows: mark(old.rows), context: mark(old.context) };
      }),
  };
}
