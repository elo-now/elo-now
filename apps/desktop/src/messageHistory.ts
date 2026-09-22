import { messageLogicalTime, type Stream } from "./model";
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
const messageIdentity = (row: Stream["rows"][number]) =>
  row.body.deleted_record_id ??
  (row.body.kind === "unavailable"
    ? (row.body.locator?.message_record_id ?? row.id)
    : row.id);

/** Pagination can overlap after a concurrent arrival. The original signed
 * message supersedes its locator placeholder once a requested body arrives;
 * signed logical time retains the conversation's canonical display ordering. */
export function mergeHistory(old: Stream["rows"], fresh: Stream["rows"]) {
  const rows = new Map<string, Stream["rows"][number]>();
  for (const row of [...old, ...fresh]) {
    const key = messageIdentity(row);
    const existing = rows.get(key);
    if (existing?.body.kind === "deleted" && row.body.kind !== "deleted")
      continue;
    if (
      !existing ||
      existing.body.kind === "unavailable" ||
      row.body.kind !== "unavailable"
    )
      rows.set(key, row);
  }
  return [...rows.values()].sort(
    (a, b) =>
      messageLogicalTime(a) - messageLogicalTime(b) ||
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
