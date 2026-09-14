import { useEffect, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { ActionDialog } from "./ActionDialog";
import { formatTimestamp, t, type MessageKey } from "./i18n";
import { statusText } from "./model";
import { useToast } from "./Toast";
import type { Stream } from "./model";
import "./messageDebug.css";

export type AuditEvent = {
  sequence: number;
  at: number;
  kind: string;
  peer: string | null;
  mailbox: string | null;
  attempt: number | null;
  error: string | null;
  http_status: number | null;
  next_retry: number | null;
};
type Target = {
  endpoint?: string;
  peer: string;
  mailbox: string;
  state: string;
  attempts: number;
  next_retry: number;
  last_error: string | null;
  receipt: {
    stored_at: number;
    arrival_seq: number;
    size_bytes: number;
    generation: string;
  } | null;
};
type SignedAction = {
  id: string;
  actor: string;
  name: string | null;
  at: string;
  action: { type: "reaction" | "pin"; emoji?: string; active: boolean };
};
type Audit = {
  record: string;
  state: string;
  author: string;
  author_name: string | null;
  credential: string;
  config: string;
  created_at: string;
  first_seen: number;
  journal_since: number;
  event_limit: number;
  events: AuditEvent[];
  targets: Target[];
  sources: {
    object: string;
    history: boolean;
    peer: string | null;
    mailbox: string | null;
    state: string | null;
    arrival_seq: number | null;
  }[];
  actions: SignedAction[];
  actions_total: number;
};

const failures: Record<string, MessageKey> = {
  NETWORK: "messageDebug.network",
  TIMEOUT: "messageDebug.timeout",
  DNS: "messageDebug.dns",
  CONNECT: "messageDebug.connect",
  TLS: "messageDebug.tls",
  TLS_REVOKED: "messageDebug.revoked",
  TLS_EXPIRED: "messageDebug.expired",
  TLS_UNTRUSTED: "messageDebug.untrusted",
  HTTP: "messageDebug.httpError",
  INVALID_RESPONSE: "messageDebug.invalidResponse",
  INVALID_RECEIPT: "messageDebug.invalidReceipt",
  REMOTE_UNAVAILABLE: "messageDebug.legacyError",
  PROCESS_RESTART: "messageDebug.PROCESS_RESTART",
  STALE_CONFIG: "messageDebug.HELD",
};
export function auditFailure(code: string): string {
  return t(failures[code] ?? "messageDebug.legacyError");
}
const events: Record<string, MessageKey> = {
  QUEUED: "messageDebug.QUEUED",
  UPLOAD_STARTED: "messageDebug.UPLOAD_STARTED",
  RETRY_SCHEDULED: "messageDebug.RETRY_SCHEDULED",
  STORED: "messageDebug.STORED",
  HELD: "messageDebug.HELD",
  PROCESS_RESTART: "messageDebug.PROCESS_RESTART",
  RECEIVED: "messageDebug.RECEIVED",
  HISTORY_IMPORTED: "messageDebug.HISTORY_IMPORTED",
  REPAIR_STARTED: "messageDebug.REPAIR_STARTED",
  REPAIRED: "messageDebug.REPAIRED",
  REPAIR_FAILED: "messageDebug.REPAIR_FAILED",
};
const timestamp = (ms: number) => formatTimestamp(new Date(ms).toISOString());
const short = (id: string) => id.slice(0, 12) + "…";

export function MessageDebug({
  identity,
  chat,
  record,
  onClose,
}: {
  identity: string;
  chat: Stream;
  record: string;
  onClose: () => void;
}) {
  const [audit, setAudit] = useState<Audit | null>(null);
  const [busy, setBusy] = useState(false);
  const [revision, setRevision] = useState(0);
  const { reportError } = useToast();
  const error = useRef(reportError);
  error.current = reportError;
  useEffect(() => {
    let active = true;
    setBusy(true);
    void invoke<{ result: Audit }>("operate", {
      request: {
        op: "message_debug",
        expected_identity: identity,
        space: chat.space,
        stream: chat.stream,
        record,
      },
    })
      .then((response) => {
        if (active) setAudit(response.result);
      })
      .catch((reason: unknown) => {
        if (active) error.current(reason);
      })
      .finally(() => {
        if (active) setBusy(false);
      });
    return () => {
      active = false;
    };
  }, [identity, chat.space, chat.stream, record, revision]);
  return (
    <ActionDialog
      title={t("messageDebug.title")}
      className="message-debug"
      onClose={onClose}
    >
      <p className="muted">{t("messageDebug.localOnly")}</p>
      {audit && (
        <>
          <dl className="message-debug-facts">
            <dt>{t("messageStatus.state")}</dt>
            <dd>{statusText(audit.state)}</dd>
            <dt>{t("messageDebug.author")}</dt>
            <dd>
              {audit.author_name}
              <code>{audit.author}</code>
            </dd>
            <dt>{t("messageDebug.created")}</dt>
            <dd>{formatTimestamp(audit.created_at)}</dd>
            <dt>{t("messageDebug.firstSeen")}</dt>
            <dd>{timestamp(audit.first_seen)}</dd>
            <dt>{t("messageStatus.id")}</dt>
            <dd>
              <code>{audit.record}</code>
            </dd>
            <dt>{t("messageDebug.credential")}</dt>
            <dd>
              <code>{audit.credential}</code>
            </dd>
          </dl>
          <h3>{t("messageDebug.delivery")}</h3>
          {!audit.targets.length && (
            <p className="muted">{t("messageDebug.noTargets")}</p>
          )}
          {audit.targets.map((target) => (
            <section
              className="message-debug-card"
              key={target.peer + target.mailbox}
            >
              <p>
                {target.endpoint ??
                  t("messageDebug.server", { id: short(target.peer) })}
              </p>
              <code>{target.mailbox}</code>
              <p>
                {t("messageDebug.targetState", {
                  state: target.state,
                  count: target.attempts,
                })}
              </p>
              {target.state === "PENDING" && target.next_retry > 0 && (
                <p>
                  {t("messageDebug.retryAt", {
                    time: timestamp(target.next_retry),
                  })}
                </p>
              )}
              {target.last_error &&
                (() => {
                  const last = [...audit.events]
                    .reverse()
                    .find(
                      (event) =>
                        event.peer === target.peer &&
                        event.mailbox === target.mailbox &&
                        event.error,
                    );
                  return (
                    <>
                      <p>{auditFailure(last?.error ?? target.last_error)}</p>
                      {last?.http_status != null && (
                        <p>
                          {t("messageDebug.httpStatus", {
                            status: last.http_status,
                          })}
                        </p>
                      )}
                    </>
                  );
                })()}
              {target.receipt && (
                <>
                  <p>{t("messageDebug.receipt")}</p>
                  <p>
                    {t("messageDebug.receiptTime", {
                      time: timestamp(target.receipt.stored_at),
                    })}
                  </p>
                  <p>
                    {t("messageDebug.receiptMeta", {
                      sequence: target.receipt.arrival_seq,
                      bytes: target.receipt.size_bytes,
                    })}
                  </p>
                </>
              )}
            </section>
          ))}
          <h3>{t("messageDebug.timeline")}</h3>
          <p className="muted">
            {t("messageDebug.retention", {
              count: audit.event_limit,
              time: timestamp(audit.journal_since),
            })}
          </p>
          <ol className="message-debug-timeline">
            {audit.events.map((event) => (
              <li key={event.sequence}>
                <span>
                  {t(events[event.kind] ?? "messageDebug.unknownEvent")}
                </span>
                <time>{timestamp(event.at)}</time>
                {event.peer && (
                  <p>{t("messageDebug.server", { id: short(event.peer) })}</p>
                )}
                {event.attempt !== null && (
                  <p>{t("messageDebug.attempt", { count: event.attempt })}</p>
                )}
                {event.http_status !== null && (
                  <p>
                    {t("messageDebug.httpStatus", {
                      status: event.http_status,
                    })}
                  </p>
                )}
                {event.error && <p>{auditFailure(event.error)}</p>}
                {event.next_retry !== null && (
                  <p>
                    {t("messageDebug.retryAt", {
                      time: timestamp(event.next_retry),
                    })}
                  </p>
                )}
              </li>
            ))}
          </ol>
          {!audit.events.length && (
            <p className="muted">{t("messageDebug.noEvents")}</p>
          )}
          {audit.sources.some((source) => source.peer || source.history) && (
            <>
              <h3>{t("messageDebug.sources")}</h3>
              {audit.sources
                .filter((source) => source.peer || source.history)
                .map((source, i) => (
                  <div className="message-debug-card" key={source.object + i}>
                    <p>
                      {t(
                        source.history
                          ? "messageDebug.HISTORY_IMPORTED"
                          : "messageDebug.RECEIVED",
                      )}
                    </p>
                    {source.peer && (
                      <p>
                        {t("messageDebug.server", { id: short(source.peer) })}
                      </p>
                    )}
                    {source.arrival_seq !== null && (
                      <p>
                        {t("messageDebug.arrival", {
                          count: source.arrival_seq,
                        })}
                      </p>
                    )}
                  </div>
                ))}
            </>
          )}
          <h3>{t("messageDebug.changes")}</h3>
          <ol className="message-debug-timeline">
            {audit.actions.map((entry) => (
              <li key={entry.id}>
                <span>
                  {t(
                    entry.action.type === "pin"
                      ? entry.action.active
                        ? "messageDebug.pinned"
                        : "messageDebug.unpinned"
                      : entry.action.active
                        ? "messageDebug.reacted"
                        : "messageDebug.unreacted",
                    { emoji: entry.action.emoji ?? "" },
                  )}
                </span>
                <time>{formatTimestamp(entry.at)}</time>
                <p>{entry.name || short(entry.actor)}</p>
                <code>{entry.actor}</code>
              </li>
            ))}
          </ol>
          {!audit.actions.length && (
            <p className="muted">{t("messageDebug.noChanges")}</p>
          )}
          {audit.actions_total > audit.actions.length && (
            <p className="muted">
              {t("messageDebug.recentChanges", {
                count: audit.actions.length,
                total: audit.actions_total,
              })}
            </p>
          )}
        </>
      )}
      <button
        className="secondary"
        disabled={busy}
        onClick={() => setRevision((value) => value + 1)}
      >
        {t(busy ? "messageDebug.loading" : "messageDebug.refresh")}
      </button>
    </ActionDialog>
  );
}
