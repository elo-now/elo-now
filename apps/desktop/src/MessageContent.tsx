import {
  MessageMore,
  MessageReactionButton,
  MessageReactions,
} from "./MessageActions";
import type { ReactNode } from "react";
import { formatMessageTime, formatTimestamp, t } from "./i18n";
import { Icon } from "./Icon";
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
  return (
    <>
      {!hideAvatars && (
        <div className="avatar" aria-hidden="true">
          {senderInitials(view, row.body.issuer_identity, chat)}
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
          {row.body.kind !== "deleted" && (onStatus || more) && (
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
          )}
        </div>
        {children}
        {chat && row.body.kind !== "deleted" && (
          <MessageReactions chat={chat} row={row} />
        )}
      </div>
    </>
  );
}
