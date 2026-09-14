import type { Stream } from "./model";
export type HistoryPage = {
  identity: string;
  space_context?: string | null;
  space: string;
  stream: string;
  revision: number;
  rows: Stream["rows"];
  context: Stream["rows"];
  next: string | null;
  newer?: string | null;
  thread?: string | null;
  query?: string;
};

/** A prepared page is usable on the first render only for its exact destination. */
export function preparedHistoryMatches(
  page: HistoryPage | undefined,
  identity: string,
  context: string | null | undefined,
  space: string,
  stream: string,
  around: string | undefined,
  thread: string | undefined,
  query: string,
) {
  return (
    !!page &&
    !!around &&
    !query.trim() &&
    !page.query &&
    (page.thread ?? undefined) === thread &&
    sameHistoryScope(page, identity, context, space, stream) &&
    page.rows.some((row) => row.id === around)
  );
}
/** Pagination can overlap after a concurrent arrival. Record IDs deduplicate;
 * signed logical time retains the conversation's canonical display ordering. */
export function mergeHistory(old: Stream["rows"], fresh: Stream["rows"]) {
  const rows = new Map(old.map((row) => [row.id, row]));
  fresh.forEach((row) => rows.set(row.id, row));
  return [...rows.values()].sort(
    (a, b) =>
      (a.body.logical_time ?? 0) - (b.body.logical_time ?? 0) ||
      (a.body.issuer_credential ?? "").localeCompare(
        b.body.issuer_credential ?? "",
      ) ||
      a.id.localeCompare(b.id),
  );
}
export function sameHistoryScope(
  page: HistoryPage,
  identity: string,
  context: string | null | undefined,
  space: string,
  stream: string,
) {
  return (
    page.identity === identity &&
    page.space_context === context &&
    page.space === space &&
    page.stream === stream
  );
}
