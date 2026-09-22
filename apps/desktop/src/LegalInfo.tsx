import { lazy, Suspense, useState } from "react";
import { createPortal } from "react-dom";
import { ActionDialog } from "./ActionDialog";
import type { LegalDocument } from "./LicenseSettings";
import { t } from "./i18n";
import "./legal.css";

const LicenseSettings = lazy(() => import("./LicenseSettings"));
export function hasAcceptedLegal(identity: string): boolean {
  try {
    return localStorage.getItem(`elo.legal.${identity}`) === t("legal.version");
  } catch {
    return false;
  }
}
export function acceptLegal(identity: string): void {
  try {
    localStorage.setItem(`elo.legal.${identity}`, t("legal.version"));
  } catch {
    // A failed local preference write does not undo the user's explicit action.
  }
}

export function LegalInfoButton({
  label = "legal.read",
  document,
  inline = false,
}: {
  label?: "legal.read" | "legal.title";
  document?: LegalDocument;
  inline?: boolean;
}) {
  const [open, setOpen] = useState(false);
  return (
    <>
      <button
        className={inline ? "legal-inline-link" : "ghost legal-info-button"}
        type="button"
        onClick={() => setOpen(true)}
      >
        {document ? t(`legal.document.${document}.title`) : t(label)}
      </button>
      {open &&
        createPortal(
          <ActionDialog
            title={
              document
                ? t(`legal.document.${document}.title`)
                : t("legal.title")
            }
            className="legal-dialog"
            onClose={() => setOpen(false)}
          >
            <Suspense fallback={<p className="muted">{t("legal.loading")}</p>}>
              <LicenseSettings
                embedded
                initialDocument={document}
                onBack={() => setOpen(false)}
              />
            </Suspense>
          </ActionDialog>,
          window.document.body,
        )}
    </>
  );
}

export function LegalNotice({
  action,
  unlocking = false,
}: {
  action?: string;
  unlocking?: boolean;
}) {
  const message = t(unlocking ? "legal.unlockNotice" : "legal.actionNotice", {
    action: action ?? "",
    terms: "{terms}",
    community: "{community}",
    privacy: "{privacy}",
  });
  return (
    <p className="legal-notice">
      {message.split(/(\{(?:terms|community|privacy)\})/).map((part, index) => {
        const document = {
          "{terms}": "terms",
          "{community}": "community",
          "{privacy}": "privacy",
        }[part] as LegalDocument | undefined;
        return document ? (
          <LegalInfoButton key={index} document={document} inline />
        ) : (
          part
        );
      })}
    </p>
  );
}
