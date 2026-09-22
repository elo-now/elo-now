import { useEffect, useRef, useState, type ReactNode } from "react";
import { Icon } from "./Icon";
import { ScreenHeader } from "./ScreenHeader";
import { t } from "./i18n";
import eloLicense from "../../../LICENSE?raw";
import lucideLicense from "../public/licenses/lucide.txt?raw";
import manropeLicense from "../public/brand/OFL.txt?raw";
import reactLicense from "../public/licenses/react.txt?raw";
import tauriLicense from "../public/licenses/tauri.txt?raw";
import qrLicense from "../public/licenses/recovery-qr.txt?raw";

import callsLicense from "../public/licenses/calls.txt?raw";

const notices = [
  {
    name: "Call media",
    license: "Apache-2.0 · MIT · ISC · BSD-3-Clause",
    text: callsLicense,
  },
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

const documents = [
  "privacy",
  "terms",
  "community",
  "delete-account",
  "support",
] as const;
export type LegalDocument = (typeof documents)[number];

export default function LicenseSettings({
  onBack,
  backLabel,
  embedded = false,
  initialDocument,
  serviceRequests,
}: {
  onBack: () => void;
  backLabel?: string;
  embedded?: boolean;
  initialDocument?: LegalDocument;
  serviceRequests?: ReactNode;
}) {
  const [selected, setSelected] = useState<(typeof notices)[number] | null>(
    null,
  );
  const [document, setDocument] = useState<LegalDocument | undefined>(
    initialDocument,
  );
  const [licenses, setLicenses] = useState(false);
  const content = useRef<HTMLDivElement>(null);
  const title =
    selected?.name ??
    (document
      ? t(`legal.document.${document}.title`)
      : licenses
        ? t("licenses.title")
        : t("legal.title"));
  const nested = !!selected || !!document || licenses;
  const back = () => {
    if (selected) setSelected(null);
    else if (document) setDocument(undefined);
    else if (licenses) setLicenses(false);
    else onBack();
  };
  useEffect(() => {
    const dialog = content.current?.closest("dialog");
    if (dialog) dialog.scrollTop = 0;
    if (embedded && content.current?.parentElement)
      content.current.parentElement.scrollTop = 0;
    if (content.current) content.current.scrollTop = 0;
  }, [title, embedded]);
  return (
    <>
      {embedded ? (
        nested &&
        !initialDocument && (
          <>
            <button className="ghost" onClick={back}>
              {t(selected ? "licenses.title" : "legal.title")}
            </button>
            <h3>{title}</h3>
          </>
        )
      ) : (
        <ScreenHeader
          title={title}
          desktopRoot={!nested}
          onBack={back}
          backLabel={
            nested
              ? t(selected ? "licenses.title" : "legal.title")
              : (backLabel ?? t("settings.back"))
          }
        />
      )}
      <div
        ref={content}
        className={embedded ? "legal-embedded" : "settings-page licenses-page"}
        key={title}
      >
        {selected || document ? (
          <pre className="license-text">
            {selected?.text ?? t(`legal.document.${document!}.body`)}
          </pre>
        ) : licenses ? (
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
        ) : (
          <div className="license-list">
            {documents.map((slug) => (
              <button
                className="secondary"
                key={slug}
                onClick={() => setDocument(slug)}
              >
                <span>{t(`legal.document.${slug}.title`)}</span>
                <Icon name="next" />
              </button>
            ))}
            <button className="secondary" onClick={() => setLicenses(true)}>
              <span>{t("legal.licenses")}</span>
              <Icon name="next" />
            </button>
          </div>
        )}
        {!nested && serviceRequests}
      </div>
    </>
  );
}
