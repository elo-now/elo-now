import { mergeHistory } from "./messageHistory";
import { messageIdentity, type MessageRow } from "./messageThreads";

export type SendReceipt = {
  id: string;
  logical_time: number;
  expires_at_ms?: number | null;
};
type Echo = { key: string; scope: string; row: MessageRow };
type Draft = {
  scope: string;
  identity: string;
  credential: string;
  text: string;
  mentions?: string[];
  createdAt: string;
  logicalTime: number;
  thread?: string;
  expiresAt?: number;
};

/** Transient UI state only. Durable queuing and authorization stay in the core. */
export class OutgoingMessages {
  private echoes: Echo[] = [];
  private listeners = new Set<() => void>();
  snapshot = () => this.echoes;
  subscribe = (listener: () => void) => {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  };
  private update(echoes: Echo[]) {
    this.echoes = echoes;
    this.listeners.forEach((listener) => listener());
  }
  async send(draft: Draft, commit: () => Promise<SendReceipt>) {
    const key = `outgoing:${crypto.randomUUID()}`;
    this.update([
      ...this.echoes,
      {
        key,
        scope: draft.scope,
        row: {
          id: key,
          state: "SENDING",
          local_echo: "saving",
          body: {
            kind: "chat.message",
            issuer_identity: draft.identity,
            issuer_credential: draft.credential,
            created_at: draft.createdAt,
            logical_time: draft.logicalTime,
            payload: {
              text: draft.text,
              mentions: draft.mentions,
              thread_root: draft.thread,
              expires_at_ms: draft.expiresAt,
            },
          },
        },
      },
    ]);
    try {
      const receipt = await commit();
      const expiresAt =
        receipt.expires_at_ms === undefined
          ? draft.expiresAt
          : receipt.expires_at_ms;
      this.update(
        this.echoes.map((echo) =>
          echo.key === key
            ? {
                ...echo,
                row: {
                  ...echo.row,
                  id: receipt.id,
                  state: "LOCAL",
                  local_echo: "saved",
                  body: {
                    ...echo.row.body,
                    logical_time: receipt.logical_time,
                    payload: {
                      ...echo.row.body.payload,
                      expires_at_ms: expiresAt,
                    },
                  },
                },
              }
            : echo,
        ),
      );
    } catch (error) {
      this.update(this.echoes.filter((echo) => echo.key !== key));
      throw error;
    }
  }
  observe(scope: string, rows: MessageRow[]) {
    const ids = new Set(rows.map(messageIdentity));
    const remaining = this.echoes.filter(
      (echo) => echo.scope !== scope || !ids.has(echo.row.id),
    );
    if (remaining.length !== this.echoes.length) this.update(remaining);
  }
  forget(scope: string) {
    this.update(this.echoes.filter((echo) => echo.scope !== scope));
  }
}

export function withOutgoingMessages(
  rows: MessageRow[],
  echoes: Echo[],
  scope: string,
) {
  const ids = new Set(rows.map(messageIdentity));
  const pending = echoes.filter(
    (echo) => echo.scope === scope && !ids.has(echo.row.id),
  );
  return pending.length
    ? mergeHistory(
        pending.map((echo) => echo.row),
        rows,
      )
    : rows;
}
