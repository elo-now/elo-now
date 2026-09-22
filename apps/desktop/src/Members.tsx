import { useEffect, useRef, useState } from "react";
import { t } from "./i18n";
import { Icon } from "./Icon";
import { ScreenHeader } from "./ScreenHeader";
import { EmptyState } from "./EmptyState";
import {
  senderName,
  senderInitials,
  visibleMembers,
  permissionText,
  type Stream,
  type View,
} from "./model";
type Member = Stream["members"][number];
export function Members({
  view,
  stream,
  busy,
  hideAvatars,
  expert,
  onBack,
  onAdd,
  onRemove,
}: {
  view: View;
  stream: Stream;
  busy: boolean;
  hideAvatars: boolean;
  expert: boolean;
  onBack: () => void;
  onAdd: () => void;
  onRemove: (member: Member) => void;
}) {
  const [selected, setSelected] = useState<string | null>(null);
  const page = useRef<HTMLElement>(null);
  const selectedMember = stream.members.find((m) => m.identity_id === selected);
  const canManage = stream.can_manage_members === true && !stream.forked;
  const members = visibleMembers(view, stream, "");
  useEffect(() => {
    page.current?.focus();
  }, []);
  useEffect(() => {
    const key = (event: KeyboardEvent) => {
      if (
        event.key === "Escape" &&
        !event.defaultPrevented &&
        !document.querySelector('dialog[open], [role="dialog"]')
      ) {
        event.preventDefault();
        onBack();
      }
    };
    document.addEventListener("keydown", key);
    return () => document.removeEventListener("keydown", key);
  }, [onBack]);
  return (
    <section
      className="members-page content-pane"
      ref={page}
      tabIndex={-1}
      aria-label={t("members.heading")}
    >
      <ScreenHeader
        title={t("members.heading")}
        onBack={onBack}
        backLabel={t("nav.close")}
      />
      <div className="members-panel">
        <div className="members-scroll page-content">
          {stream.forked && <p className="error">{t("warning.forked")}</p>}
          {canManage && (
            <div className="member-invite-actions">
              <button disabled={busy} onClick={onAdd}>
                <Icon name="plus" />
                {t("members.addPeople")}
              </button>
            </div>
          )}
          {members.length ? (
            <ul className="member-list">
              {members.map((member) => (
                <li key={member.identity_id}>
                  <button
                    type="button"
                    className="member-row"
                    aria-label={t("members.open", {
                      name: senderName(view, member.identity_id, stream),
                    })}
                    aria-haspopup="dialog"
                    onClick={() => setSelected(member.identity_id)}
                  >
                    {!hideAvatars && (
                      <span className="avatar">
                        {senderInitials(view, member.identity_id, stream)}
                      </span>
                    )}
                    <span className="member-copy">
                      <strong>
                        {senderName(view, member.identity_id, stream)}
                      </strong>
                      <small>
                        {t(
                          stream.owners.some(
                            (o) => o.identity_id === member.identity_id,
                          )
                            ? "members.owner"
                            : "members.participant",
                        )}
                      </small>
                    </span>
                  </button>
                </li>
              ))}
            </ul>
          ) : (
            <EmptyState message={t("members.empty")} />
          )}
        </div>
      </div>
      {selectedMember && (
        <MemberDetails
          stream={stream}
          view={view}
          member={selectedMember}
          expert={expert}
          canRemove={
            canManage &&
            selected !== view.identity &&
            !stream.owners.some((o) => o.identity_id === selected)
          }
          busy={busy}
          onClose={() => setSelected(null)}
          onRemove={() => {
            setSelected(null);
            onRemove(selectedMember);
          }}
        />
      )}
    </section>
  );
}

function MemberDetails({
  stream,
  view,
  member,
  expert,
  canRemove,
  busy,
  onClose,
  onRemove,
}: {
  stream: Stream;
  view: View;
  member: Member;
  expert: boolean;
  canRemove: boolean;
  busy: boolean;
  onClose: () => void;
  onRemove: () => void;
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
      className="dialog member-dialog"
      aria-labelledby="member-title"
      onCancel={(event) => {
        event.preventDefault();
        onClose();
      }}
    >
      <button
        type="button"
        autoFocus
        className="icon close"
        aria-label={t("dialog.close")}
        onClick={onClose}
      >
        <Icon name="close" />
      </button>
      <h2 id="member-title">{senderName(view, member.identity_id, stream)}</h2>
      <div className="member-facts">
        <h3>{t("members.permissions")}</h3>
        <p>{member.capabilities.map(permissionText).join(", ")}</p>
      </div>
      {expert && (
        <div className="member-facts">
          <h3>{t("members.identifiers")}</h3>
          <dl>
            <dt>{t("members.identity")}</dt>
            <dd>
              <code>{member.identity_id}</code>
            </dd>
            <dt>{t("members.credentials")}</dt>
            <dd>
              {member.credential_ids.map((credential) => (
                <code key={credential}>{credential}</code>
              ))}
            </dd>
          </dl>
        </div>
      )}
      {canRemove && (
        <button
          type="button"
          className="member-remove"
          disabled={busy}
          onClick={onRemove}
        >
          {t("members.remove")}
        </button>
      )}
    </dialog>
  );
}
