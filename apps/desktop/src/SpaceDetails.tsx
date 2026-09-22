import { useEffect, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { ActionDialog } from "./ActionDialog";
import { SpaceContact } from "./SpaceContact";
import { SpaceStorage } from "./SpaceStorage";
import { SpaceAttachments } from "./SpaceAttachments";
import type { SpaceManagement } from "./SpaceRoles";
import type { SpaceSummary, View } from "./model";
import { t } from "./i18n";
import { useToast } from "./Toast";

export function SpaceDetails({
  identity,
  space,
  management,
  onView,
  onChanged,
}: {
  identity: string;
  space: SpaceSummary;
  management: SpaceManagement;
  onView: (view: View) => void;
  onChanged: () => Promise<void>;
}) {
  const primary = management.primary_owner === identity;
  const primaryName =
    management.members.find(
      (member) => member.identity === management.primary_owner,
    )?.name ?? "—";
  return (
    <div className="space-details">
      <SpaceContact
        identity={identity}
        space={space}
        email={management.contact_email ?? ""}
        revision={management.roles_revision}
        primaryName={primaryName}
        editable={primary}
        onView={onView}
        onChanged={onChanged}
      />
      {space.deletable && <SpaceStorage identity={identity} space={space} />}
      {space.deletable && management.attachments && (
        <SpaceAttachments
          identity={identity}
          space={space}
          value={management.attachments}
          onChanged={onChanged}
        />
      )}
      {primary && space.deletable && (
        <section className="space-details-section">
          <SpaceDeletion
            identity={identity}
            space={space}
            revision={management.roles_revision}
            onView={onView}
          />
        </section>
      )}
    </div>
  );
}

function SpaceDeletion({
  identity,
  space,
  revision,
  onView,
}: {
  identity: string;
  space: SpaceSummary;
  revision: number;
  onView: (view: View) => void;
}) {
  const [deleting, setDeleting] = useState(false);
  const [deleteName, setDeleteName] = useState("");
  const [busy, setBusy] = useState(false);
  const alive = useRef(true);
  const { reportError } = useToast();
  useEffect(() => {
    alive.current = true;
    return () => {
      alive.current = false;
    };
  }, []);
  return (
    <>
      {space.deletable && (
        <button
          className="secondary danger"
          disabled={busy}
          onClick={() => setDeleting(true)}
        >
          {t("spaces.delete")}
        </button>
      )}
      {deleting && (
        <ActionDialog
          title={t("spaces.deleteTitle", { name: space.name })}
          className="space-delete-dialog"
          onClose={() => {
            if (!busy) setDeleting(false);
          }}
        >
          <p className="muted">{t("spaces.deleteHelp")}</p>
          <label htmlFor="delete-space-name">
            {t("spaces.deleteTypeName", { name: space.name })}
          </label>
          <input
            id="delete-space-name"
            value={deleteName}
            disabled={busy}
            autoComplete="off"
            onChange={(event) => setDeleteName(event.target.value)}
          />
          <div className="space-choice">
            <button
              className="secondary"
              disabled={busy}
              onClick={() => setDeleting(false)}
            >
              {t("invite.cancel")}
            </button>
            <button
              className="danger"
              disabled={busy || deleteName !== space.name}
              aria-busy={busy}
              onClick={() => {
                if (busy || deleteName !== space.name) return;
                setBusy(true);
                void invoke<{ view: View }>("operate", {
                  request: {
                    op: "space_delete",
                    id: space.id,
                    expected_identity: identity,
                    body: {
                      revision: revision,
                      name: deleteName,
                      confirmed: true,
                    },
                  },
                })
                  .then((reply) => {
                    if (alive.current) {
                      onView(reply.view);
                      setDeleting(false);
                    }
                  })
                  .catch((error) => {
                    if (alive.current) reportError(error);
                  })
                  .finally(() => {
                    if (alive.current) setBusy(false);
                  });
              }}
            >
              {t("spaces.deletePermanently")}
            </button>
          </div>
        </ActionDialog>
      )}
    </>
  );
}
