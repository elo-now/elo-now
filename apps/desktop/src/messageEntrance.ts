import { messageIdentity, type MessageRow } from "./messageThreads";

const LIVE_AGE_MS = 30_000;
const PAGE_WAIT_MS = 10_000;
const NO_ARRIVALS: string[] = [];

/** Presentation only: history growth is never evidence of a live arrival. */
export class MessageEntrance {
  private scope = "";
  private ready = false;
  private openedAt = 0;
  private seen = new Set<string>();
  private pending = new Map<string, number>();
  private rows?: readonly MessageRow[];

  pause() {
    this.ready = false;
    this.rows = undefined;
    this.seen.clear();
    this.pending.clear();
  }

  receive(
    scope: string,
    rows: readonly MessageRow[],
    received: readonly string[],
    now: number,
  ) {
    if (!received.length || !this.ready || scope !== this.scope) return;
    const ids = new Set(received);
    for (const row of rows) {
      if (
        !ids.has(row.id) ||
        this.seen.has(messageIdentity(row)) ||
        row.body.kind !== "chat.message"
      )
        continue;
      const created = Date.parse(row.body.created_at ?? "");
      if (
        Number.isFinite(created) &&
        created >= this.openedAt &&
        created >= now - LIVE_AGE_MS &&
        created <= now
      )
        this.pending.set(row.id, now + PAGE_WAIT_MS);
    }
  }

  observe(
    scope: string,
    rows: readonly MessageRow[],
    active: boolean,
    now: number,
  ): string[] {
    if (!active) {
      if (this.ready || scope !== this.scope) {
        this.scope = scope;
        this.pause();
      }
      return NO_ARRIVALS;
    }
    if (scope !== this.scope || !this.ready) {
      this.scope = scope;
      this.ready = true;
      this.openedAt = now;
      this.seen = new Set(rows.map(messageIdentity));
      this.pending.clear();
      this.rows = rows;
      return NO_ARRIVALS;
    }
    // History may wrap the same immutable rows in a new array while composing.
    // Skip ID parsing, set updates and allocations until message data changes.
    if (
      this.rows === rows ||
      (this.rows?.length === rows.length &&
        rows.every((row, index) => row === this.rows![index]))
    )
      return NO_ARRIVALS;
    this.rows = rows;
    for (const [id, deadline] of this.pending)
      if (deadline < now) this.pending.delete(id);
    const arriving: string[] = [];
    for (const row of rows) {
      const id = messageIdentity(row);
      if (
        !this.seen.has(id) &&
        row.body.kind === "chat.message" &&
        (row.local_echo === "saving" || this.pending.has(id))
      )
        arriving.push(row.id);
      this.seen.add(id);
      this.pending.delete(id);
    }
    return arriving;
  }
}
