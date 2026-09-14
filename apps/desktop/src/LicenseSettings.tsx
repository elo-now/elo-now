import { useState } from "react";
import { Icon } from "./Icon";
import { ScreenHeader } from "./ScreenHeader";
import { t } from "./i18n";
import eloLicense from "../../../LICENSE?raw";
import lucideLicense from "../public/licenses/lucide.txt?raw";
import manropeLicense from "../public/brand/OFL.txt?raw";
import reactLicense from "../public/licenses/react.txt?raw";
import tauriLicense from "../public/licenses/tauri.txt?raw";
import qrLicense from "../public/licenses/recovery-qr.txt?raw";

const notices = [
  { name: "elo.now", license: "AGPL-3.0-only", text: eloLicense },
  { name: "Lucide", license: "ISC · MIT", text: lucideLicense },
  {
    name: "Manrope",
    license: "SIL Open Font License 1.1",
    text: manropeLicense,
  },
  { name: "React", license: "MIT", text: reactLicense },
  { name: "Tauri", license: "MIT · Apache-2.0", text: tauriLicense },
  { name: "QR recognition", license: "MIT · ISC", text: qrLicense },
];

export default function LicenseSettings({ onBack }: { onBack: () => void }) {
  const [selected, setSelected] = useState<(typeof notices)[number] | null>(
    null,
  );
  return (
    <>
      <ScreenHeader
        title={selected?.name ?? t("licenses.title")}
        onBack={selected ? () => setSelected(null) : onBack}
        backLabel={selected ? t("licenses.title") : t("settings.back")}
      />
      <div
        className="settings-page licenses-page"
        key={selected?.name ?? "list"}
      >
        {selected ? (
          <pre className="license-text">{selected.text}</pre>
        ) : (
          <>
            <p className="muted">{t("licenses.help")}</p>
            <div className="license-list">
              {notices.map((notice) => (
                <button
                  className="secondary"
                  key={notice.name}
                  onClick={() => setSelected(notice)}
                >
                  <span>
                    {notice.name}
                    <small>{notice.license}</small>
                  </span>
                  <Icon name="next" />
                </button>
              ))}
            </div>
          </>
        )}
      </div>
    </>
  );
}
