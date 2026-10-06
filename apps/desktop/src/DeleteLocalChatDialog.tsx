import { ActionDialog } from "./ActionDialog";
import { t } from "./i18n";

export function DeleteLocalChatDialog({
  chatName,
  busy,
  onClose,
  onConfirm,
}: {
  chatName: string;
  busy: boolean;
  onClose: () => void;
  onConfirm: () => void;
}) {
  return (
    <ActionDialog
      title={t("chat.deleteLocalTitle")}
      onClose={() => {
        if (!busy) onClose();
      }}
    >
      <p>{t("chat.deleteLocalName", { name: chatName })}</p>
      <p className="muted">{t("chat.deleteLocalHelp")}</p>
      <div className="dialog-buttons">
        <button className="secondary" disabled={busy} onClick={onClose}>
          {t("dialog.cancel")}
        </button>
        <button className="danger-action" disabled={busy} onClick={onConfirm}>
          {t("chat.deleteLocalConfirm")}
        </button>
      </div>
    </ActionDialog>
  );
}
