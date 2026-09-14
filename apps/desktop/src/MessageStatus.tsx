import { useEffect, useRef, useState, type ReactNode } from "react";
import { Icon, type IconName } from "./Icon";
import { t, formatTimestamp, type MessageKey } from "./i18n";
import { statusText } from "./model";
import { ActionDialog } from "./ActionDialog";

type StatusKind = "queued" | "synced" | "pending" | "issue";
type Presentation = {
  icon: IconName;
  label: MessageKey;
};
const legend: Record<StatusKind, Presentation> = {
  queued: { icon: "queued", label: "messageStatus.queued" },
  synced: { icon: "synced", label: "messageStatus.synced" },
  pending: {
    icon: "syncPending",
    label: "messageStatus.pending",
  },
  issue: { icon: "syncIssue", label: "messageStatus.issue" },
};

// QUEUED is projected from actual pending/inflight outbox targets by the core.
// LOCAL alone can have no delivery target, so it must never imply a send queue.
export function messageStatusKind(state: string): StatusKind {
  switch (state) {
    case "QUEUED":
      return "queued";
    case "ACCEPTED":
    case "STORED":
      return "synced";
    case "LOCAL":
    case "REPAIR_PENDING":
    case "HELD_STALE_CONFIG":
    case "QUARANTINED_STALE":
    case "WAITING_FOR_PROOF":
      return "pending";
    default:
      return "issue";
  }
}

export function MessageStatusButton({
  state,
  onOpen,
}: {
  state: string;
  onOpen: () => void;
}) {
  const kind = messageStatusKind(state);
  const presentation = legend[kind];
  return (
    <button
      type="button"
      className="message-status"
      data-status={kind}
      aria-label={t("messageStatus.show", { status: t(presentation.label) })}
      title={t(presentation.label)}
      aria-haspopup="dialog"
      onClick={(event) => {
        // WebKit can leave the message row focused after a touch on its button.
        // Restore focus to the actual trigger when the dialog closes.
        event.currentTarget.focus({ preventScroll: true });
        onOpen();
      }}
    >
      <Icon name={presentation.icon} />
    </button>
  );
}

export type MessageStatusSelection = {
  state?: string;
  id?: string;
  sender?: string;
  createdAt?: string;
};

function StatusDialog({
  title,
  onClose,
  children,
}: {
  title: MessageKey;
  onClose: () => void;
  children: ReactNode;
}) {
  const ref = useRef<HTMLDialogElement>(null);
  useEffect(() => {
    const dialog = ref.current;
    dialog?.showModal();
    return () => {
      if (dialog?.open) dialog.close();
    };
  }, []);
  return (
    <dialog
      ref={ref}
      className="dialog status-dialog"
      aria-labelledby="message-status-title"
      onCancel={(event) => {
        event.preventDefault();
        onClose();
      }}
    >
      <button
        className="close"
        autoFocus
        aria-label={t("dialog.close")}
        onClick={onClose}
      >
        <Icon name="close" />
      </button>
      <h2 id="message-status-title">{t(title)}</h2>
      {children}
    </dialog>
  );
}

const detailHelp: Record<string, MessageKey> = {
  LOCAL: "messageStatus.local",
  QUEUED: "messageStatus.queueHelp",
  ACCEPTED: "messageStatus.accepted",
  STORED: "messageStatus.stored",
  REPAIR_PENDING: "messageStatus.repairPending",
  HELD_STALE_CONFIG: "messageStatus.held",
  QUARANTINED_STALE: "messageStatus.quarantined",
  WAITING_FOR_PROOF: "messageStatus.waiting",
  REJECTED: "messageStatus.rejected",
};

export function MessageStatusDialog({
  selection,
  expert,
  onClose,
}: {
  selection: MessageStatusSelection;
  expert: boolean;
  onClose: () => void;
}) {
  const [details, setDetails] = useState(false);
  const opener = useRef(document.activeElement);
  const anchor = useRef(
    opener.current instanceof HTMLElement
      ? opener.current.getBoundingClientRect()
      : undefined,
  );
  useEffect(
    () => () => {
      const element = opener.current;
      if (element instanceof HTMLElement && element.isConnected)
        requestAnimationFrame(() => element.focus({ preventScroll: true }));
    },
    [],
  );
  const current = selection.state
    ? messageStatusKind(selection.state)
    : undefined;
  if (details && expert && selection.id) {
    const help = Object.prototype.hasOwnProperty.call(
      detailHelp,
      selection.state ?? "",
    )
      ? detailHelp[selection.state!]
      : "messageStatus.unknown";
    return (
      <StatusDialog
        key="details"
        title="messageStatus.details"
        onClose={onClose}
      >
        <dl className="message-details">
          <dt>{t("messageStatus.state")}</dt>
          <dd>
            {statusText(selection.state ?? "")}
            <p>{t(help)}</p>
          </dd>
          <dt>{t("messageStatus.id")}</dt>
          <dd>
            <code>{selection.id}</code>
          </dd>
          <dt>{t("messageStatus.sender")}</dt>
          <dd>
            <code>{selection.sender}</code>
          </dd>
          <dt>{t("messageStatus.time")}</dt>
          <dd>{formatTimestamp(selection.createdAt)}</dd>
          <dt>{t("messageStatus.recipients")}</dt>
          <dd>{t("messageStatus.notTracked")}</dd>
          <dt>{t("messageStatus.read")}</dt>
          <dd>{t("messageStatus.notTracked")}</dd>
        </dl>
        <div className="status-actions">
          <button className="secondary" onClick={() => setDetails(false)}>
            {t("messageStatus.back")}
          </button>
        </div>
      </StatusDialog>
    );
  }
  return (
    <ActionDialog
      key="legend"
      compact
      className="status-popover"
      anchor={anchor.current}
      title={t("messageStatus.title")}
      onClose={onClose}
    >
      <ul className="status-legend">
        {Object.entries(legend).map(([key, value]) => (
          <li
            key={key}
            data-selected={current === key}
            aria-current={current === key ? "true" : undefined}
          >
            <span className="status-symbol">
              <Icon name={value.icon} />
            </span>
            <span>{t(value.label)}</span>
          </li>
        ))}
      </ul>
      <div className="status-actions">
        {expert && selection.id && (
          <button
            className="secondary"
            aria-haspopup="dialog"
            onClick={() => setDetails(true)}
          >
            {t("messageStatus.details")}
          </button>
        )}
      </div>
    </ActionDialog>
  );
}
