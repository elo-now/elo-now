import { useEffect, useRef, useState } from "react";
import { Icon } from "./Icon";
import { ScreenHeader } from "./ScreenHeader";
import { MessageContent } from "./MessageContent";
import { ComposerInput } from "./ComposerInput";
import { EmptyState } from "./EmptyState";
import { PullToRefresh } from "./PullToRefresh";
import { t, messageDayKey, formatMessageDay } from "./i18n";
import {
  beginsNewMessageSection,
  isNewMessage,
  messageCreatedAt,
  type Stream,
  type View,
} from "./model";
import type { MessageStatusSelection } from "./MessageStatus";
import type { MessageRow, MessageThread } from "./messageThreads";
import { messageIdentity } from "./messageThreads";
import { UnavailableMessage } from "./UnavailableMessage";
import { AttachmentButton, type AttachmentProgress } from "./AttachmentButton";

export function ThreadView({
  view,
  chat,
  thread,
  hideAvatars,
  mobile,
  busy,
  draft,
  onDraft,
  onBack,
  onRefresh,
  onRead,
  onSend,
  onStatus,
  onFile,
  downloadingAttachment,
  attachmentProgress,
  onCancelAttachment,
  composeRevision,
  target,
  historyLoading = false,
  historyReady = true,
  hasOlder = false,
  onOlder,
  hasNewer = false,
  onNewer,
  onRetry,
  newMessage,
  onJumpToLatest,
  onRequestMessage,
  onUnavailable,
}: {
  view: View;
  chat: Stream;
  thread: MessageThread;
  hideAvatars: boolean;
  mobile: boolean;
  busy: boolean;
  draft: string;
  onDraft: (text: string) => void;
  onBack: () => void;
  onRefresh: () => Promise<void>;
  onRead: (ids: string[]) => void;
  onSend: (text: string) => Promise<boolean>;
  onStatus: (selection: MessageStatusSelection) => void;
  onFile: (row: MessageRow) => void;
  downloadingAttachment?: string;
  attachmentProgress?: AttachmentProgress;
  onCancelAttachment: () => void;
  composeRevision: number;
  target?: { id: string; key: number };
  historyLoading?: boolean;
  historyReady?: boolean;
  hasOlder?: boolean;
  onOlder?: () => Promise<void>;
  hasNewer?: boolean;
  onNewer?: () => Promise<void>;
  onRetry?: () => Promise<void>;
  newMessage?: { id: string; key: number };
  onJumpToLatest?: (id: string) => void;
  onRequestMessage: (row: MessageRow) => Promise<void>;
  onUnavailable: () => void;
}) {
  const [seen, setSeen] = useState(new Set<string>());
  const [ownSendRevision, setOwnSendRevision] = useState(0);
  const [scrollTarget, setScrollTarget] = useState(target);
  const composer = useRef<HTMLTextAreaElement>(null);
  const posting = useRef(false);
  const canReply = !!thread.root && chat.can_post && !chat.forked;
  const rows = thread.root ? [thread.root, ...thread.replies] : thread.replies;
  useEffect(() => setScrollTarget(target), [target]);
  useEffect(() => {
    if (composeRevision > 0 && canReply) composer.current?.focus();
  }, [composeRevision, canReply]);
  const submit = async () => {
    if (posting.current || busy || !canReply || !draft.trim()) return;
    posting.current = true;
    try {
      if (await onSend(draft)) {
        onDraft("");
        setScrollTarget(undefined);
        setOwnSendRevision((value) => value + 1);
      }
    } finally {
      posting.current = false;
    }
  };
  return (
    <section
      className="thread-view content-pane"
      aria-label={t("thread.title")}
    >
      <ScreenHeader
        title={t("thread.title")}
        onBack={onBack}
        backLabel={t("thread.back")}
      />
      <div className="searchable-list">
        <PullToRefresh
          className="messages thread-messages"
          enabled={mobile}
          disabled={busy}
          onRefresh={onRefresh}
          resetKey={`${chat.stream}:${thread.rootId}`}
          scrollToRecord={scrollTarget}
          onLoadOlder={hasOlder ? onOlder : undefined}
          loadingOlder={historyLoading}
          historyReady={historyReady}
          followLatest={!hasNewer}
          newMessage={newMessage}
          onJumpToLatest={onJumpToLatest}
          scrollToEndKey={
            ownSendRevision && !scrollTarget
              ? `${thread.rootId}:${ownSendRevision}:${rows.filter((row) => row.body.issuer_identity === view.identity).at(-1)?.id ?? ""}`
              : undefined
          }
          onVisibleUnread={(ids) => {
            setSeen((current) => new Set([...current, ...ids]));
            onRead(ids);
          }}
        >
          {historyLoading && !historyReady && (
            <p className="history-loading" role="status">
              {t("history.loading")}
            </p>
          )}
          {!historyReady && !historyLoading && (
            <button
              className="history-more secondary"
              onClick={() => void onRetry?.()}
            >
              {t("history.retry")}
            </button>
          )}
          {hasOlder && (
            <button
              className="history-more secondary"
              disabled={historyLoading}
              onClick={() => void onOlder?.()}
            >
              {t("history.older")}
            </button>
          )}
          {historyReady && !thread.root && (
            <EmptyState message={t("thread.missingRoot")}>
              <p className="empty-state-help">{t("thread.missingHelp")}</p>
            </EmptyState>
          )}
          {rows.map((row, index) => (
            <ThreadMessage
              key={row.id}
              view={view}
              chat={chat}
              row={row}
              rows={rows}
              index={index}
              seen={seen}
              root={messageIdentity(row) === thread.rootId}
              hideAvatars={hideAvatars}
              busy={busy}
              onStatus={onStatus}
              onFile={onFile}
              downloadingAttachment={downloadingAttachment}
              attachmentProgress={attachmentProgress}
              onCancelAttachment={onCancelAttachment}
              onRequestMessage={onRequestMessage}
              onUnavailable={onUnavailable}
            />
          ))}
          {hasNewer && (
            <button
              className="history-more secondary"
              disabled={historyLoading}
              onClick={() => void onNewer?.()}
            >
              {t("history.newer")}
            </button>
          )}
          {historyReady && !hasOlder && !thread.replies.length && (
            <EmptyState message={t("thread.empty")} />
          )}
        </PullToRefresh>
      </div>
      <form
        className="composer"
        onSubmit={(event) => {
          event.preventDefault();
          void submit();
        }}
      >
        <ComposerInput
          inputRef={composer}
          aria-label={t("thread.reply")}
          placeholder={
            canReply ? t("thread.placeholder") : t("composer.unavailable")
          }
          value={draft}
          onChange={(e) => onDraft(e.target.value)}
          disabled={busy || !canReply}
          maxLength={16384}
        />
        <div>
          <button
            aria-label={t("composer.send")}
            title={t("composer.send")}
            disabled={busy || !canReply || !draft.trim()}
          >
            <Icon name="up" />
          </button>
        </div>
      </form>
    </section>
  );
}
function ThreadMessage({
  view,
  chat,
  row,
  rows,
  index,
  seen,
  root,
  hideAvatars,
  busy,
  onStatus,
  onFile,
  downloadingAttachment,
  attachmentProgress,
  onCancelAttachment,
  onRequestMessage,
  onUnavailable,
}: {
  view: View;
  chat: Stream;
  row: MessageRow;
  rows: MessageRow[];
  index: number;
  seen: Set<string>;
  root: boolean;
  hideAvatars: boolean;
  busy: boolean;
  onStatus: (selection: MessageStatusSelection) => void;
  onFile: (row: MessageRow) => void;
  downloadingAttachment?: string;
  attachmentProgress?: AttachmentProgress;
  onCancelAttachment: () => void;
  onRequestMessage: (row: MessageRow) => Promise<void>;
  onUnavailable: () => void;
}) {
  return (
    <>
      {index > 0 &&
        messageDayKey(messageCreatedAt(row)) !==
          messageDayKey(messageCreatedAt(rows[index - 1])) && (
          <h3 className="message-day">
            <span>{formatMessageDay(messageCreatedAt(row))}</span>
          </h3>
        )}
      {beginsNewMessageSection(rows, index, seen) && (
        <div className="unread-separator" role="separator">
          <span>{t("unread.new")}</span>
        </div>
      )}
      <article
        className="message"
        data-thread-root={root || undefined}
        data-record-id={row.id}
        data-hide-avatars={hideAvatars || undefined}
        data-new={isNewMessage(rows, index, seen) || undefined}
        data-unread-id={row.unread ? row.id : undefined}
        data-own={row.body.issuer_identity === view.identity}
        tabIndex={-1}
      >
        <MessageContent
          view={view}
          chat={chat}
          row={row}
          showDate={index === 0}
          hideAvatars={hideAvatars}
          onStatus={row.body.kind === "unavailable" ? undefined : onStatus}
        >
          {row.body.kind === "deleted" ? (
            <p className="deleted-message">{t("messageActions.deleted")}</p>
          ) : row.body.kind === "unavailable" ? (
            <UnavailableMessage
              disabled={busy}
              onRequest={() => onRequestMessage(row)}
              onUnavailable={onUnavailable}
            />
          ) : row.body.kind === "chat.message" ? (
            <p>{row.body.payload?.text}</p>
          ) : (
            <AttachmentButton
              row={row}
              disabled={busy}
              download={
                downloadingAttachment === row.id
                  ? attachmentProgress
                  : undefined
              }
              onDownload={() => onFile(row)}
              onCancel={onCancelAttachment}
            />
          )}
        </MessageContent>
      </article>
    </>
  );
}
