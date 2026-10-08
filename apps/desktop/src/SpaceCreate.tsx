import { useEffect, useRef, useState } from "react";
import { invoke } from "./diagnosticInvoke";
import { SpaceContactInput } from "./SpaceContact";
import {
  AttachmentStorageForm,
  emptyAttachmentStorage,
} from "./AttachmentStorageForm";
import {
  chooseHosting,
  hostingLifetime,
  hostingAttachmentRequest,
  messageLifetimeLabel,
  useHostingCatalog,
  type MessageLifetime,
} from "./Hosting";
import { HostingPicker } from "./HostingPicker";
import { ScreenHeader } from "./ScreenHeader";
import { InvitationCode } from "./InvitationFlow";
import { useToast } from "./Toast";
import { t } from "./i18n";
import type { View } from "./model";

export function SpaceCreate({
  view,
  mobile,
  onView,
  onBack,
}: {
  view: View;
  mobile: boolean;
  onView: (view: View) => void;
  onBack: () => void;
}) {
  const [name, setName] = useState(view.space_creation?.name ?? "");
  const [email, setEmail] = useState(view.space_creation?.contact_email ?? "");
  const [messageLifetime, setMessageLifetime] = useState<
    MessageLifetime | undefined
  >(view.space_creation?.message_lifetime_seconds);
  const [requireApproval, setRequireApproval] = useState(
    view.space_creation?.require_approval ?? true,
  );
  const [busy, setBusy] = useState(false);
  const [attachmentStorage, setAttachmentStorage] = useState(() =>
    emptyAttachmentStorage(
      view.space_creation?.attachment_storage_pending ?? false,
    ),
  );
  const pending = useRef(false);
  const alive = useRef(true);
  useEffect(() => {
    alive.current = true;
    return () => {
      alive.current = false;
    };
  }, []);
  const { reportError, onInvalid } = useToast();
  const creation = view.space_creation;
  const catalog = useHostingCatalog();
  const [hostingId, setHostingId] = useState(creation?.hosting_id);
  const host = creation
    ? catalog.entries.find((entry) => entry.id === creation.hosting_id)
    : chooseHosting(catalog.entries, hostingId);
  const lifetime = creation
    ? (creation.message_lifetime_seconds ?? 86_400)
    : host
      ? hostingLifetime(
          host,
          hostingId === host.id ? messageLifetime : undefined,
        )
      : undefined;
  const managedAttachments =
    creation?.attachment_storage_managed ??
    host?.attachment_storage_managed ??
    false;
  const storageAvailable =
    host?.attachment_storage_available ??
    (!!creation && !!view.attachment_storage_available);
  const selectHosting = (id: string) => {
    if (creation) return;
    setHostingId(id);
    const selected = catalog.entries.find((entry) => entry.id === id);
    setMessageLifetime(selected?.default_message_lifetime);
    setAttachmentStorage(emptyAttachmentStorage());
  };
  const ready = !!creation?.invitation && !creation.attachment_storage_pending;
  const call = async (request: Record<string, unknown>) => {
    const reply = await invoke<{ view: View }>("operate", {
      request: { ...request, expected_identity: view.identity },
    });
    if (alive.current) onView(reply.view);
    return reply.view;
  };
  const finish = async () => {
    if (busy) return;
    setBusy(true);
    try {
      if (creation?.space && !creation.attachment_storage_pending)
        await call({ op: "space_setup_done" });
      onBack();
    } catch (error) {
      reportError(error);
    } finally {
      setBusy(false);
    }
  };
  return (
    <section className="spaces-page">
      <ScreenHeader
        title={ready ? t("spaces.created") : t("spaces.create")}
        onBack={busy ? undefined : () => void finish()}
      />
      <div className="settings-page">
        {ready && creation?.invitation ? (
          <>
            <p className="page-description">
              {t("spaces.createdHelp", { name: creation.name })}
            </p>
            <InvitationCode
              link={creation.invitation}
              mobile={mobile}
              showLink={false}
            />
            <p className="muted">
              {t(
                creation.require_approval === false
                  ? "spaces.firstInvitationOpenHelp"
                  : "spaces.firstInvitationHelp",
              )}
            </p>
            <button disabled={busy} onClick={() => void finish()}>
              {t("spaces.openCreated")}
            </button>
          </>
        ) : (
          <form
            className="space-create-form"
            onInvalid={onInvalid}
            onSubmit={(event) => {
              event.preventDefault();
              if (
                pending.current ||
                (!creation &&
                  (catalog.status !== "ready" ||
                    !host ||
                    lifetime === undefined))
              )
                return;
              pending.current = true;
              setBusy(true);
              void call({
                op: "space_create",
                name: creation?.name ?? name.trim(),
                contact_email: creation?.contact_email || email.trim(),
                ...((creation?.hosting_id ?? host?.id)
                  ? { hosting_id: creation?.hosting_id ?? host?.id }
                  : {}),
                message_lifetime_seconds: lifetime,
                require_approval: creation?.require_approval ?? requireApproval,
                ...(storageAvailable || managedAttachments
                  ? {
                      attachment_storage: hostingAttachmentRequest(
                        {
                          attachment_storage_available: storageAvailable,
                          attachment_storage_managed: managedAttachments,
                        },
                        attachmentStorage,
                      ),
                    }
                  : {}),
              })
                .then((next) => {
                  if (
                    alive.current &&
                    !next.space_creation?.attachment_storage_pending
                  )
                    setAttachmentStorage(emptyAttachmentStorage());
                })
                .catch(async (error) => {
                  if (!alive.current) return;
                  reportError(error);
                  await call({ op: "space_list" }).catch(() => {});
                })
                .finally(() => {
                  pending.current = false;
                  if (alive.current) setBusy(false);
                });
            }}
          >
            <p className="page-description">{t("spaces.createHelp")}</p>
            <HostingPicker
              entries={catalog.entries}
              selectedId={creation?.hosting_id ?? host?.id}
              onSelect={selectHosting}
              status={catalog.status}
              request={catalog.request}
              refresh={catalog.refresh}
              disabled={busy || !!creation}
              pendingCreation={!!creation}
              mobile={mobile}
            />
            <div className="space-form-field">
              <label htmlFor="space-name">{t("spaces.name")}</label>
              <input
                id="space-name"
                value={creation?.name ?? name}
                maxLength={80}
                disabled={busy || !!creation}
                onChange={(event) => setName(event.target.value)}
                autoComplete="off"
                aria-describedby="space-hosting-limits"
              />
            </div>
            <SpaceContactInput
              value={creation?.contact_email || email}
              onChange={setEmail}
              disabled={busy || !!creation?.contact_email}
            />
            <div className="space-form-field">
              <label htmlFor="space-message-lifetime">
                {t("spaces.messageLifetime.label")}
              </label>
              <select
                id="space-message-lifetime"
                value={lifetime ?? ""}
                disabled={busy || !!creation || !host}
                onChange={(event) =>
                  setMessageLifetime(
                    event.target.value === "no_expiry"
                      ? "no_expiry"
                      : Number(event.target.value),
                  )
                }
              >
                {(creation
                  ? [lifetime ?? 86_400]
                  : (host?.message_lifetimes ?? [])
                ).map((seconds) => (
                  <option value={seconds} key={seconds}>
                    {messageLifetimeLabel(seconds)}
                  </option>
                ))}
              </select>
              <p className="caption muted">
                {t(
                  lifetime === "no_expiry"
                    ? "spaces.messageLifetime.noExpiryHelp"
                    : "spaces.messageLifetime.help",
                )}
              </p>
            </div>
            <label className="check">
              <input
                type="checkbox"
                checked={creation?.require_approval ?? requireApproval}
                disabled={busy || !!creation}
                onChange={(event) => setRequireApproval(event.target.checked)}
              />
              <span>{t("spaces.requireApproval")}</span>
            </label>
            {managedAttachments ? (
              <p className="caption muted">
                {t("hosting.managedAttachmentsHelp")}
              </p>
            ) : (
              storageAvailable && (
                <AttachmentStorageForm
                  value={attachmentStorage}
                  onChange={setAttachmentStorage}
                  disabled={busy}
                />
              )
            )}
            {creation?.attachment_storage_pending && (
              <p className="caption muted" role="status">
                {t("spaces.attachments.creationPending")}
              </p>
            )}
            {creation && <p className="muted">{t("spaces.resumeHelp")}</p>}
            <p id="space-hosting-limits" className="space-hosting-limits muted">
              {t(
                !host?.builtin
                  ? "hosting.independentLimits"
                  : managedAttachments
                    ? "hosting.managedLimits"
                    : storageAvailable
                      ? "spaces.hostingLimitsExternalAttachments"
                      : "spaces.hostingLimits",
              )}
            </p>
            <button
              type="submit"
              className="space-switch"
              disabled={
                busy ||
                !(creation?.name ?? name).trim() ||
                (!creation &&
                  (catalog.status !== "ready" ||
                    !host ||
                    lifetime === undefined))
              }
              aria-busy={busy}
            >
              {busy && (
                <span
                  className="invitation-qr-loader space-switch-loader"
                  aria-hidden="true"
                />
              )}
              <span className="space-switch-label">
                {t(
                  busy
                    ? "spaces.creating"
                    : creation
                      ? "spaces.resume"
                      : "spaces.create",
                )}
              </span>
            </button>
          </form>
        )}
      </div>
    </section>
  );
}
