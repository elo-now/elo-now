import {
  MessageMore,
  MessageReactionButton,
  MessageReactions,
} from "./MessageActions";
import type { ReactNode } from "react";
import { isExpiryTimestamp, timestampIso } from "./timestamps";
import {
  formatMessageTime,
  formatTimestamp,
  formatAttachmentExpiry,
  t,
} from "./i18n";
import { Icon } from "./Icon";
import { OnlineIndicator } from "./useRealtime";
import {
  messageCreatedAt,
  senderInitials,
  senderName,
  type Stream,
  type View,
} from "./model";
import {
  MessageStatusButton,
  type MessageStatusSelection,
} from "./MessageStatus";

/** The same author, avatar, time and optional status control in Chats and Buzz. */
export function MessageContent({
  view,
  chat,
  row,
  hideAvatars,
  showDate = false,
  context,
  children,
  onStatus,
  more,
}: {
  view: View;
  chat?: Stream;
  row: Stream["rows"][number];
  hideAvatars: boolean;
  showDate?: boolean;
  context?: ReactNode;
  more?: ReactNode;
  children: ReactNode;
  onStatus?: (selection: MessageStatusSelection) => void;
}) {
  const createdAt = messageCreatedAt(row);
  const expiresAt = row.body.payload?.expires_at_ms;
  return (
    <>
      {!hideAvatars && (
        <div className="avatar">
          {senderInitials(view, row.body.issuer_identity, chat)}
          <OnlineIndicator identity={row.body.issuer_identity} chat={chat} />
        </div>
      )}
      <div className="message-content">
        <div
          className="message-meta"
          data-context={!!context || undefined}
          data-full-date={showDate || undefined}
        >
          <strong title={row.body.issuer_identity}>
            {senderName(view, row.body.issuer_identity, chat)}
          </strong>
          <span className="message-time">
            <time dateTime={createdAt} title={formatTimestamp(createdAt)}>
              {formatMessageTime(createdAt, showDate)}
            </time>
            {row.pinned && (
              <span
                className="message-pin"
                role="img"
                aria-label={t("messageActions.pinned")}
                title={t("messageActions.pinned")}
              >
                <Icon name="pin" />
              </span>
            )}
          </span>
          {context}
          {row.local_echo ? (
            <span className="message-controls">
              <span
                className="message-status"
                role="status"
                aria-label={t(
                  row.local_echo === "saving"
                    ? "messageStatus.saving"
                    : "messageStatus.pending",
                )}
                title={t(
                  row.local_echo === "saving"
                    ? "messageStatus.saving"
                    : "messageStatus.pending",
                )}
              >
                <Icon name="syncPending" />
              </span>
            </span>
          ) : (
            row.body.kind !== "deleted" &&
            (onStatus || more) && (
              <span className="message-controls">
                {onStatus && (
                  <MessageStatusButton
                    state={row.state}
                    onOpen={() =>
                      onStatus({
                        state: row.state,
                        id: row.id,
                        sender: row.body.issuer_identity,
                        createdAt,
                      })
                    }
                  />
                )}
                {onStatus && chat && (
                  <MessageReactionButton chat={chat} row={row} />
                )}
                {more ??
                  (onStatus && chat && <MessageMore chat={chat} row={row} />)}
              </span>
            )
          )}
        </div>
        {children}
        {row.body.kind === "chat.message" &&
          isExpiryTimestamp(row.body.payload?.edited_at_ms) && (
            <time
              className="message-edited"
              dateTime={timestampIso(row.body.payload!.edited_at_ms!)}
              title={formatTimestamp(
                timestampIso(row.body.payload!.edited_at_ms!),
              )}
            >
              {t("messageActions.edited")}
            </time>
          )}
        {["chat.message", "unavailable"].includes(row.body.kind) &&
          isExpiryTimestamp(expiresAt) && (
            <div className="message-expiry">
              <time dateTime={timestampIso(expiresAt)}>
                {t("messageActions.expiresAt", {
                  date: formatAttachmentExpiry(expiresAt),
                })}
              </time>
            </div>
          )}
        {chat && !row.local_echo && row.body.kind !== "deleted" && (
          <MessageReactions chat={chat} row={row} />
        )}
      </div>
    </>
  );
}
