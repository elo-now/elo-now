import { shareText } from "@choochmeque/tauri-plugin-sharekit-api";
import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { ActionDialog } from "./ActionDialog";
import { t } from "./i18n";
import { useToast } from "./Toast";
import type { View } from "./model";
import { AccountDeletion } from "./AccountDeletion";
const platformEmail = "elonow@9bits.com";
type Target = { identity: string; message?: string; text?: string };
export function ServiceRequestDialog({
  view,
  target,
  deletion = false,
  onClose,
  mobile = false,
}: {
  view: View;
  mobile?: boolean;
  target?: Target;
  deletion?: boolean;
  onClose: () => void;
}) {
  const [details, setDetails] = useState(
    deletion ? t("requests.deletionDefault") : "",
  );
  const { reportError } = useToast();
  const space = view.spaces?.find((s) => s.id === view.active_space);
  const scope = deletion ? (space?.managed ? space.id : undefined) : "platform";
  const [contact, setContact] = useState<string>();
  const [contactFailed, setContactFailed] = useState(false);
  const [retry, setRetry] = useState(0);
  useEffect(() => {
    let alive = true;
    setContact(undefined);
    setContactFailed(false);
    if (scope && scope !== "platform") {
      void invoke<{ result: { contact_email?: string | null } }>("operate", {
        request: {
          op: "space_contact",
          id: scope,
          expected_identity: view.identity,
        },
      })
        .then((reply) => {
          if (!alive) return;
          if (reply.result?.contact_email)
            setContact(reply.result.contact_email);
          else setContactFailed(true);
        })
        .catch(() => {
          if (alive) setContactFailed(true);
        });
    }
    return () => {
      alive = false;
    };
  }, [scope, view.identity, retry]);
  const email = scope === "platform" ? platformEmail : contact;
  const subject = t(
    deletion ? "requests.deletionSubject" : "requests.reportSubject",
  );
  const body = t("requests.emailBody", {
    identity: view.identity,
    space: space ? `${space.name} (${space.id})` : t("requests.noSpace"),
    target: target?.identity ?? "—",
    message: target?.message ?? "—",
    details: details.trim(),
  });
  const draft = `${t("requests.recipient", { email: email ?? "—" })}\n${subject}\n\n${body}`;
  return (
    <ActionDialog
      page
      className="service-request-dialog"
      title={t(deletion ? "requests.deletion" : "requests.report")}
      onClose={onClose}
    >
      {deletion && space?.managed && (
        <p className="muted">{t("requests.spaceHelp", { name: space.name })}</p>
      )}
      {!scope ? (
        <p className="muted">{t("requests.chooseSpace")}</p>
      ) : email ? (
        <p className="muted">
          {t(mobile ? "requests.emailHelp" : "requests.desktopEmailHelp", {
            email,
          })}
        </p>
      ) : (
        <p className="muted" role="status">
          {t(
            contactFailed
              ? "requests.contactUnavailable"
              : "requests.contactLoading",
          )}
        </p>
      )}
      {contactFailed && (
        <button className="secondary" onClick={() => setRetry((n) => n + 1)}>
          {t("requests.tryContact")}
        </button>
      )}
      <p className="muted">{t("requests.privateHelp")}</p>
      <label htmlFor="report-details">{t("requests.details")}</label>
      <textarea
        id="report-details"
        maxLength={2000}
        value={details}
        onChange={(event) => setDetails(event.target.value)}
      />
      <div className="space-choice">
        <button
          disabled={!email}
          onClick={() => {
            void (
              mobile
                ? shareText(draft)
                : invoke("open_mail_draft", { email, subject, body })
            ).catch(reportError);
          }}
        >
          {t("requests.useDraft")}
        </button>
      </div>
    </ActionDialog>
  );
}
export function ServiceRequests({
  view,
  mobile = false,
}: {
  view: View;
  mobile?: boolean;
}) {
  const [kind, setKind] = useState<"report" | "deletion">();
  return (
    <section className="service-requests">
      <div className="space-choice">
        <button className="secondary" onClick={() => setKind("report")}>
          {t("requests.report")}
        </button>
        <button className="secondary" onClick={() => setKind("deletion")}>
          {t("requests.deletion")}
        </button>
      </div>
      <AccountDeletion identity={view.identity} mobile={mobile} />
      {kind && (
        <ServiceRequestDialog
          mobile={mobile}
          view={view}
          deletion={kind === "deletion"}
          onClose={() => setKind(undefined)}
        />
      )}
    </section>
  );
}
