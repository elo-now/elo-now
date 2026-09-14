import {
  createContext,
  useContext,
  useEffect,
  useRef,
  useState,
  type ReactNode,
} from "react";
import { MessageContent } from "./MessageContent";
import { ScreenHeader } from "./ScreenHeader";
import { EmptyState } from "./EmptyState";
import { Icon } from "./Icon";
import { t, formatTimestamp, type MessageKey } from "./i18n";
import type { Stream, View } from "./model";
import { recordTimestamp } from "./model";
import type { StreamEntry } from "./streamFeed";
import { useToast, useToastHost } from "./Toast";
import {
  scheduleReminder,
  cancelReminder,
  reconcileReminders,
} from "./reminders";
import "./messageActions.css";
import { ActionDialog } from "./ActionDialog";
import { MessageDebug } from "./MessageDebug";

import reactionChoices from "../../../protocol/reactions.json";
export type MessageCollection =
  { kind: "pins"; stream: string } | { kind: "reminders" };
type Row = Stream["rows"][number];
type Selection = {
  chat: Stream;
  row: Row;
  anchor: DOMRect;
  onlyUnpin?: boolean;
};
const ActionsContext = createContext<{
  open: (
    chat: Stream,
    row: Row,
    trigger: HTMLButtonElement,
    onlyUnpin?: boolean,
  ) => void;
  react: (chat: Stream, row: Row, emoji: string) => void;
  chooseReaction: (chat: Stream, row: Row, trigger: HTMLButtonElement) => void;
  busy: boolean;
} | null>(null);

/** Shared by the timeline and its one-level threads; status keeps its own control. */
export function MessageMore({
  chat,
  row,
  onlyUnpin = false,
}: {
  chat: Stream;
  row: Row;
  onlyUnpin?: boolean;
}) {
  const actions = useContext(ActionsContext);
  if (!actions) return null;
  return (
    <button
      type="button"
      className="message-more"
      aria-label={t("messageActions.more")}
      aria-haspopup="menu"
      disabled={actions.busy}
      onClick={(event) => {
        event.currentTarget.focus({ preventScroll: true });
        actions.open(chat, row, event.currentTarget, onlyUnpin);
      }}
    >
      <Icon name="more" />
    </button>
  );
}
export function MessageReactionButton({
  chat,
  row,
}: {
  chat: Stream;
  row: Row;
}) {
  const actions = useContext(ActionsContext);
  if (!actions) return null;
  return (
    <button
      type="button"
      className="message-reaction-button"
      aria-label={t("messageActions.reaction")}
      aria-haspopup="dialog"
      disabled={actions.busy || !chat.can_post || chat.forked}
      onClick={(event) => {
        event.currentTarget.focus({ preventScroll: true });
        actions.chooseReaction(chat, row, event.currentTarget);
      }}
    >
      <Icon name="smile" />
    </button>
  );
}
export function MessageReactions({ chat, row }: { chat: Stream; row: Row }) {
  const actions = useContext(ActionsContext);
  if (!row.reactions?.length) return null;
  return (
    <div
      className="message-reactions"
      aria-label={t("messageActions.reactions")}
    >
      {row.reactions.map((reaction) => (
        <button
          key={reaction.emoji}
          type="button"
          aria-pressed={reaction.mine}
          aria-label={t("messageActions.reactionCount", {
            emoji: reaction.emoji,
            count: reaction.count,
          })}
          disabled={!actions || actions.busy || !chat.can_post || chat.forked}
          onClick={() => actions?.react(chat, row, reaction.emoji)}
        >
          <span>{reaction.emoji}</span>
          <span>{reaction.count}</span>
        </button>
      ))}
    </div>
  );
}

export function MessageActionsProvider({
  view,
  expert,
  hideAvatars,
  mobile,
  collection,
  onCollection,
  onChange,
  onUnread,
  onOpen,
  children,
}: {
  view: View;
  expert: boolean;
  hideAvatars: boolean;
  mobile: boolean;
  collection: MessageCollection | null;
  onCollection: (collection: MessageCollection | null) => void;
  onChange: (request: Record<string, unknown>) => Promise<unknown>;
  onUnread: (chat: Stream, row: Row) => Promise<void>;
  onOpen: (entry: StreamEntry) => void;
  children: ReactNode;
}) {
  const latestView = useRef(view);
  latestView.current = view;
  const [selection, setSelection] = useState<Selection | null>(null);
  const [debug, setDebug] = useState<{ chat: Stream; record: string } | null>(
    null,
  );
  const [panel, setPanel] = useState<"menu" | "reaction" | "remind">("menu");
  const [busy, setBusy] = useState(false);
  const pending = useRef(false);
  const [customTime, setCustomTime] = useState("");
  const [presetMinutes, setPresetMinutes] = useState<number | null>(null);
  const [systemNotification, setSystemNotification] = useState(false);
  const { reportError, notify } = useToast();
  const close = () => {
    if (!pending.current) setSelection(null);
  };
  const run = async (work: () => Promise<unknown>) => {
    if (pending.current) return;
    pending.current = true;
    setBusy(true);
    try {
      await work();
      setSelection(null);
    } catch (error) {
      reportError(error);
    } finally {
      pending.current = false;
      setBusy(false);
    }
  };
  const signedAction = (
    chat: Stream,
    row: Row,
    action: Record<string, unknown>,
  ) =>
    onChange({
      op: "message_action",
      space: chat.space,
      stream: chat.stream,
      created_at: recordTimestamp(),
      action: { target: row.id, ...action },
    });
  const react = (chat: Stream, row: Row, emoji: string) =>
    void run(() =>
      signedAction(chat, row, {
        type: "reaction",
        emoji,
        active: !row.reactions?.find((r) => r.emoji === emoji)?.mine,
      }),
    );
  const pin = (chat: Stream, row: Row, active: boolean) =>
    signedAction(chat, row, { type: "pin", active });
  const remind = async (chat: Stream, row: Row, due: number) => {
    await onChange({
      op: "remind",
      target_space: chat.space_context,
      space: chat.space,
      stream: chat.stream,
      record: row.id,
      due_at: due,
      system_notification: systemNotification,
    });
    // The durable private reminder always exists before asking the OS to schedule it.
    try {
      if (!systemNotification) {
        await cancelReminder(view.identity, chat.stream, row.id, mobile);
        notify(t("reminders.saved"));
        return;
      }
      const scheduled = await scheduleReminder(
        view.identity,
        chat.stream,
        row.id,
        due,
        mobile,
      );
      notify(t(scheduled ? "reminders.saved" : "reminders.inApp"));
    } catch {
      notify(t("reminders.inApp"));
    }
  };
  useEffect(() => {
    const reconcile = () => {
      void reconcileReminders(latestView.current, mobile).catch(() => {});
    };
    reconcile();
    const resume = () => {
      if (document.visibilityState === "visible") reconcile();
    };
    document.addEventListener("visibilitychange", resume);
    return () => document.removeEventListener("visibilitychange", resume);
  }, [view.identity, mobile]);
  const currentChat =
    (view.all_streams ?? view.streams).find(
      (chat) => chat.stream === selection?.chat.stream,
    ) ?? selection?.chat;
  const currentRow =
    currentChat?.rows.find((row) => row.id === selection?.row.id) ??
    selection?.row;
  const menuItem = (key: MessageKey, action: () => void, disabled = false) => (
    <button
      type="button"
      role="menuitem"
      disabled={busy || disabled}
      onClick={action}
    >
      <span>{t(key)}</span>
    </button>
  );
  return (
    <ActionsContext.Provider
      value={{
        busy,
        react,
        chooseReaction: (chat, row, trigger) => {
          setPanel("reaction");
          setSelection({ chat, row, anchor: trigger.getBoundingClientRect() });
        },
        open: (chat, row, trigger, onlyUnpin) => {
          setPanel("menu");
          setCustomTime("");
          setPresetMinutes(null);
          setSystemNotification(
            !!(view.all_reminders ?? view.reminders)?.find(
              (r) => r.stream === chat.stream && r.record === row.id,
            )?.system_notification,
          );
          setSelection({
            chat,
            row,
            anchor: trigger.getBoundingClientRect(),
            onlyUnpin,
          });
        },
      }}
    >
      {children}
      {expert && debug && (
        <MessageDebug
          identity={view.identity}
          chat={debug.chat}
          record={debug.record}
          onClose={() => setDebug(null)}
        />
      )}
      {collection && (
        <MessageCollectionView
          view={view}
          collection={collection}
          hideAvatars={hideAvatars}
          onClose={() => onCollection(null)}
          onOpen={(entry) => {
            onCollection(null);
            onOpen(entry);
          }}
          onRemove={(chat, row) =>
            void run(async () => {
              await onChange({
                op: "reminder_remove",
                target_space: chat.space_context,
                space: chat.space,
                stream: chat.stream,
                record: row.id,
              });
              try {
                await cancelReminder(
                  view.identity,
                  chat.stream,
                  row.id,
                  mobile,
                );
              } catch {
                notify(t("reminders.cancelFailed"));
              }
            })
          }
          onRemind={(chat, row, trigger) => {
            setCustomTime("");
            setPresetMinutes(null);
            setSystemNotification(
              !!(view.all_reminders ?? view.reminders)?.find(
                (r) => r.stream === chat.stream && r.record === row.id,
              )?.system_notification,
            );
            setPanel("remind");
            setSelection({
              chat,
              row,
              anchor: trigger.getBoundingClientRect(),
            });
          }}
          busy={busy}
        />
      )}
      {selection && currentChat && currentRow && (
        <ActionDialog
          key={panel}
          title={t(
            panel === "reaction"
              ? "messageActions.reaction"
              : panel === "remind"
                ? "messageActions.remind"
                : "messageActions.more",
          )}
          anchor={panel !== "remind" ? selection.anchor : undefined}
          menu={panel === "menu"}
          compact={panel === "reaction"}
          className={panel === "reaction" ? "reaction-popover" : ""}
          onClose={close}
        >
          {panel === "menu" ? (
            <>
              {!selection.onlyUnpin && (
                <>
                  {menuItem(
                    "messageActions.unread",
                    () => void run(() => onUnread(currentChat, currentRow)),
                  )}
                </>
              )}
              {menuItem(
                selection.onlyUnpin || currentRow.pinned
                  ? "messageActions.unpin"
                  : "messageActions.pin",
                () =>
                  void run(() =>
                    pin(
                      currentChat,
                      currentRow,
                      selection.onlyUnpin ? false : !currentRow.pinned,
                    ),
                  ),
                !currentChat.can_post || currentChat.forked,
              )}
              {!selection.onlyUnpin && (
                <>
                  {menuItem("messageActions.remind", () => setPanel("remind"))}
                  {menuItem(
                    "messageActions.copy",
                    () =>
                      void run(async () => {
                        await navigator.clipboard.writeText(
                          currentRow.body.payload?.text ??
                            currentRow.body.filename ??
                            "",
                        );
                        notify(t("messageActions.copied"));
                      }),
                  )}
                  {expert &&
                    menuItem("messageDebug.title", () => {
                      setDebug({ chat: currentChat, record: currentRow.id });
                      setSelection(null);
                    })}
                </>
              )}
            </>
          ) : panel === "reaction" ? (
            <div className="reaction-picker">
              {reactionChoices.map((emoji) => (
                <button
                  key={emoji}
                  disabled={busy}
                  aria-label={t("messageActions.reactWith", { emoji })}
                  aria-pressed={
                    !!currentRow.reactions?.find((r) => r.emoji === emoji)?.mine
                  }
                  onClick={() => react(currentChat, currentRow, emoji)}
                >
                  {emoji}
                </button>
              ))}
            </div>
          ) : (
            <div className="reminder-picker">
              {(
                [
                  [20, "reminders.twentyMinutes"],
                  [60, "reminders.oneHour"],
                  [180, "reminders.threeHours"],
                  [1440, "reminders.tomorrow"],
                  [10080, "reminders.nextWeek"],
                ] as const
              ).map(([minutes, label]) => (
                <button
                  key={minutes}
                  className="secondary"
                  aria-pressed={presetMinutes === minutes}
                  disabled={busy}
                  onClick={() => {
                    setPresetMinutes(minutes);
                    setCustomTime("");
                  }}
                >
                  {t(label)}
                </button>
              ))}
              <label>
                {t("reminders.chooseTime")}
                <input
                  type="datetime-local"
                  value={customTime}
                  onChange={(event) => {
                    setCustomTime(event.target.value);
                    setPresetMinutes(null);
                  }}
                  disabled={busy}
                />
              </label>
              <label className="check reminder-notification">
                <input
                  type="checkbox"
                  checked={systemNotification}
                  disabled={busy}
                  onChange={(event) =>
                    setSystemNotification(event.target.checked)
                  }
                />
                {t("reminders.systemNotification")}
              </label>
              <button
                disabled={
                  busy ||
                  (presetMinutes === null &&
                    (!customTime || !Number.isFinite(Date.parse(customTime))))
                }
                onClick={() =>
                  void run(() =>
                    remind(
                      currentChat,
                      currentRow,
                      presetMinutes === null
                        ? Date.parse(customTime)
                        : Date.now() + presetMinutes * 60_000,
                    ),
                  )
                }
              >
                {t("reminders.save")}
              </button>
            </div>
          )}
        </ActionDialog>
      )}
    </ActionsContext.Provider>
  );
}

function MessageCollectionView({
  view,
  collection,
  hideAvatars,
  onClose,
  onOpen,
  onRemove,
  onRemind,
  busy,
}: {
  view: View;
  collection: MessageCollection;
  hideAvatars: boolean;
  busy: boolean;
  onClose: () => void;
  onOpen: (entry: StreamEntry) => void;
  onRemove: (chat: Stream, row: Row) => void;
  onRemind: (chat: Stream, row: Row, trigger: HTMLButtonElement) => void;
}) {
  const ref = useRef<HTMLDialogElement>(null);
  const heading = useRef<HTMLHeadingElement>(null);
  useToastHost(ref);
  const [time, setTime] = useState(Date.now());
  useEffect(() => {
    ref.current?.showModal();
    heading.current?.focus({ preventScroll: true });
    const timer = setInterval(() => setTime(Date.now()), 30_000);
    return () => {
      ref.current?.close();
      clearInterval(timer);
    };
  }, []);
  const entries =
    collection.kind === "pins"
      ? view.streams
          .filter((chat) => chat.stream === collection.stream)
          .flatMap((chat) =>
            chat.rows
              .filter((row) => row.pinned)
              .map((row) => ({
                chat,
                row,
                due: undefined as number | undefined,
              })),
          )
      : (view.all_reminders ?? view.reminders ?? []).flatMap((reminder) => {
          const chat = (view.all_streams ?? view.streams).find(
            (s) => s.stream === reminder.stream,
          );
          if (!chat) return [];
          const row = chat.rows.find((r) => r.id === reminder.record);
          return [
            {
              chat,
              row: row ?? {
                id: reminder.record,
                state: "LOCAL",
                body: { kind: "unavailable", issuer_identity: view.identity },
              },
              due: reminder.due_at,
            },
          ];
        });
  return (
    <dialog
      ref={ref}
      className="dialog message-collection"
      aria-label={t(
        collection.kind === "pins" ? "messageActions.pins" : "reminders.title",
      )}
      onCancel={(e) => {
        e.preventDefault();
        onClose();
      }}
    >
      <ScreenHeader
        titleRef={heading}
        title={t(
          collection.kind === "pins"
            ? "messageActions.pins"
            : "reminders.title",
        )}
        onBack={onClose}
      />
      <div className="message-collection-list">
        {!entries.length && (
          <EmptyState
            message={t(
              collection.kind === "pins"
                ? "messageActions.noPins"
                : "reminders.empty",
            )}
          />
        )}
        {entries.map(({ chat, row, due }) => (
          <article
            className="message stream-card"
            key={`${chat.stream}:${row.id}`}
            data-hide-avatars={hideAvatars || undefined}
          >
            <MessageContent
              view={view}
              chat={chat}
              row={row}
              hideAvatars={hideAvatars}
              context={<span className="message-context">{chat.name}</span>}
              more={
                collection.kind === "pins" ? (
                  <MessageMore chat={chat} row={row} onlyUnpin />
                ) : undefined
              }
            >
              {due !== undefined && (
                <div className="reminder-time" data-due={due <= time}>
                  {formatTimestamp(new Date(due).toISOString())}
                  {due <= time && (
                    <span className="reminder-overdue">
                      {t("reminders.overdue")}
                    </span>
                  )}
                </div>
              )}
              <button
                className="stream-preview"
                disabled={row.body.kind === "unavailable"}
                onClick={() =>
                  onOpen({
                    key: `${chat.space}:${chat.stream}:${row.id}`,
                    chat,
                    row,
                  })
                }
              >
                <p>
                  <span className="stream-text">
                    {row.body.payload?.text ??
                      row.body.filename ??
                      t("reminders.unavailable")}
                  </span>
                </p>
              </button>
              {collection.kind === "reminders" && (
                <div className="reminder-actions">
                  <button
                    className="secondary"
                    disabled={busy}
                    onClick={() => onRemove(chat, row)}
                  >
                    {t("reminders.done")}
                  </button>
                  <button
                    className="secondary"
                    disabled={busy || row.body.kind === "unavailable"}
                    onClick={(event) =>
                      onRemind(chat, row, event.currentTarget)
                    }
                  >
                    {t("reminders.snooze")}
                  </button>
                </div>
              )}
            </MessageContent>
          </article>
        ))}
      </div>
    </dialog>
  );
}
