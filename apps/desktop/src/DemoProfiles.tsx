import { Icon } from "./Icon";
import { useEffect, useRef } from "react";
import { t } from "./i18n";

// Public, disposable simulator fixtures. Never add real credentials here.
const presets = [
  { label: "demo.android", password: "qwertyuiopas" },
  { label: "demo.ios", password: "elotestprofile2026" },
] as const;

export function DemoProfiles({
  onSelect,
  onOpenDemo,
  busy,
  onClose,
}: {
  onSelect: (password: string) => void;
  onOpenDemo: (person: string) => void;
  busy: boolean;
  onClose: () => void;
}) {
  const dialog = useRef<HTMLDialogElement>(null);
  useEffect(() => {
    const element = dialog.current;
    element?.showModal();
    return () => element?.close();
  }, []);
  return (
    <dialog
      ref={dialog}
      className="dialog demo-dialog"
      aria-labelledby="demo-title"
      onCancel={(event) => {
        event.preventDefault();
        if (!busy) onClose();
      }}
    >
      <button
        autoFocus
        className="icon close"
        type="button"
        aria-label={t("dialog.close")}
        onClick={onClose}
        disabled={busy}
      >
        <Icon name="close" />
      </button>
      <h2 id="demo-title">{t("demo.title")}</h2>
      <p>{t("demo.help")}</p>
      <div className="demo-presets">
        {presets.map((preset) => (
          <button
            type="button"
            className="secondary"
            key={preset.label}
            onClick={() => onSelect(preset.password)}
            disabled={busy}
          >
            {t(preset.label)}
          </button>
        ))}
      </div>
      <h3>{t("demo.workspace")}</h3>
      <p>{t("demo.workspaceHelp")}</p>
      <div className="demo-people">
        {["Alex", "Maya", "Jules", "Sam"].map((person) => (
          <button
            type="button"
            key={person}
            disabled={busy}
            onClick={() => onOpenDemo(person.toLowerCase())}
          >
            {person}
          </button>
        ))}
      </div>
      {busy && <p role="status">{t("demo.preparing")}</p>}
    </dialog>
  );
}
