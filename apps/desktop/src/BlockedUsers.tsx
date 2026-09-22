import {
  createContext,
  useContext,
  useEffect,
  useRef,
  useState,
  type ReactNode,
} from "react";
import { ActionDialog } from "./ActionDialog";
import { t } from "./i18n";
import { Icon } from "./Icon";
import { EmptyState } from "./EmptyState";
import { useToast } from "./Toast";
import type { View } from "./model";

type Person = { identity: string; name: string };
const BlockContext = createContext<((person: Person) => void) | null>(null);
export function BlockingProvider({
  view,
  onChange,
  children,
}: {
  view: View;
  onChange: (request: Record<string, unknown>) => Promise<unknown>;
  children: ReactNode;
}) {
  const [person, setPerson] = useState<Person | null>(null);
  const [working, setWorking] = useState(false);
  const pending = useRef(false);
  const { reportError, notify } = useToast();
  const blocked = !!view.blocked_users?.some(
    (p) => p.identity === person?.identity,
  );
  const latest = useRef(view.identity);
  latest.current = view.identity;
  useEffect(() => setPerson(null), [view.identity, view.active_space]);
  const apply = async () => {
    if (!person || pending.current) return;
    const identity = view.identity;
    pending.current = true;
    setWorking(true);
    try {
      const result = await onChange({
        op: "set_user_blocked",
        identity: person.identity,
        name: person.name,
        blocked: !blocked,
      });
      if (latest.current !== identity) return;
      setPerson(null);
      notify(
        t(
          (result as { notification_pending?: boolean })?.notification_pending
            ? "blocking.pending"
            : blocked
              ? "blocking.unblocked"
              : "blocking.blocked",
        ),
      );
    } catch (error) {
      if (latest.current === identity) reportError(error);
    } finally {
      pending.current = false;
      setWorking(false);
    }
  };
  const close = () => {
    if (!pending.current) setPerson(null);
  };
  return (
    <BlockContext.Provider value={setPerson}>
      {children}
      {person && (
        <ActionDialog
          className="blocking-dialog"
          title={t(blocked ? "blocking.unblockName" : "blocking.blockName", {
            name: person.name,
          })}
          onClose={close}
        >
          <p>{t(blocked ? "blocking.unblockHelp" : "blocking.help")}</p>
          <div className="space-choice">
            <button
              type="button"
              className="secondary"
              disabled={working}
              onClick={close}
            >
              {t("dialog.cancel")}
            </button>
            <button
              type="button"
              disabled={working}
              aria-busy={working}
              onClick={() => void apply()}
            >
              {working
                ? t("blocking.saving")
                : t(blocked ? "blocking.unblock" : "blocking.block")}
            </button>
          </div>
        </ActionDialog>
      )}
    </BlockContext.Provider>
  );
}
export function BlockUserAction({
  identity,
  name,
  blocked = false,
  icon = false,
  menu = false,
  onSelect,
}: {
  identity: string;
  name: string;
  blocked?: boolean;
  icon?: boolean;
  menu?: boolean;
  onSelect?: () => void;
}) {
  const choose = useContext(BlockContext);
  if (!choose) return null;
  return (
    <button
      type="button"
      className={icon ? "icon" : undefined}
      role={menu ? "menuitem" : undefined}
      aria-label={t(blocked ? "blocking.unblockName" : "blocking.blockName", {
        name,
      })}
      onClick={() => {
        choose({ identity, name });
        onSelect?.();
      }}
    >
      {icon ? (
        <Icon name="rejected" />
      ) : (
        t(blocked ? "blocking.unblockAction" : "blocking.block")
      )}
    </button>
  );
}
export function BlockedUsers({ view }: { view: View }) {
  return (
    <section className="settings-page blocked-users">
      {(view.blocked_users?.length ?? 0) ? (
        <ul className="blocked-user-list">
          {view.blocked_users!.map((person) => (
            <li key={person.identity}>
              <div>
                <strong>{person.name}</strong>
              </div>
              <BlockUserAction {...person} blocked />
            </li>
          ))}
        </ul>
      ) : (
        <EmptyState message={t("blocking.empty")} />
      )}
    </section>
  );
}
