import { useEffect, useId, useRef, useState } from "react";
import { ActionDialog } from "./ActionDialog";
import { useToast } from "./Toast";
import { t } from "./i18n";
import type { ChatGroup } from "./model";
import "./chatGroupDialog.css";

export function ChatGroupDialog({
  disabled,
  onCreate,
  onAdded,
  onClose,
}: {
  disabled: boolean;
  onCreate: (name: string) => Promise<ChatGroup | undefined>;
  onAdded: (group: ChatGroup) => void;
  onClose: () => void;
}) {
  const [name, setName] = useState("");
  const [busy, setBusy] = useState(false);
  const pending = useRef(false);
  const mounted = useRef(true);
  const inputId = useId();
  const { reportError } = useToast();
  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);
  const close = () => {
    if (!disabled && !pending.current) onClose();
  };
  const create = async () => {
    if (disabled || pending.current || !name.trim()) return;
    pending.current = true;
    setBusy(true);
    try {
      const group = await onCreate(name.trim());
      if (group && mounted.current) {
        onAdded(group);
        onClose();
      }
    } catch (error) {
      if (mounted.current) reportError(error);
    } finally {
      pending.current = false;
      if (mounted.current) setBusy(false);
    }
  };
  return (
    <ActionDialog
      title={t("groups.new")}
      compact
      className="chat-group-dialog"
      onClose={close}
    >
      <h2>{t("groups.new")}</h2>
      <label htmlFor={inputId}>{t("groups.name")}</label>
      <input
        id={inputId}
        autoFocus
        autoComplete="off"
        value={name}
        disabled={disabled || busy}
        onChange={(event) => setName(event.target.value)}
        onKeyDown={(event) => {
          if (event.key === "Enter" && !event.nativeEvent.isComposing) {
            // This dialog is also used inside the New chat form.
            event.preventDefault();
            event.stopPropagation();
            void create();
          }
        }}
      />
      <div className="dialog-buttons">
        <button
          type="button"
          className="secondary"
          disabled={disabled || busy}
          onClick={close}
        >
          {t("dialog.cancel")}
        </button>
        <button
          type="button"
          disabled={disabled || busy || !name.trim()}
          onClick={() => void create()}
        >
          {t("groups.create")}
        </button>
      </div>
    </ActionDialog>
  );
}
