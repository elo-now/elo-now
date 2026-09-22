import { useDesktopLayout } from "./PageSurface";
import { SpaceContactInput } from "./SpaceContact";
import { FloatingSearch, SearchField } from "./Search";
import { Icon } from "./Icon";
import { EmptyState } from "./EmptyState";
import "./contacts.css";
import "./newChat.css";
import { useEffect, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { ActionDialog } from "./ActionDialog";
import { t } from "./i18n";
import { useToast } from "./Toast";
import type { SpaceSummary, SpaceRoleRequest, View } from "./model";

type Member = {
  identity: string;
  name: string;
  role: "primary_owner" | "owner" | "member";
};
export type SpaceManagement = {
  members: Member[];
  roles_revision: number;
  primary_owner: string;
  contact_email?: string | null;
  attachments?: {
    policy: {
      enabled: boolean;
      max_file_bytes: number;
      max_space_bytes: number;
      retention: "never" | { days: number };
    };
    used_bytes: number;
    reserved_bytes: number;
  };
};
type Kind =
  "make_owner" | "remove_owner" | "transfer_primary" | "remove_member";
const roleLabel = (role: Member["role"]) =>
  t(
    role === "primary_owner"
      ? "spaces.role.primary"
      : role === "owner"
        ? "spaces.role.owner"
        : "spaces.role.member",
  );

export function SpaceMembers({
  identity,
  space,
  management,
  hideAvatars = false,
  onChanged,
  onView,
}: {
  identity: string;
  space: SpaceSummary;
  management: SpaceManagement;
  hideAvatars?: boolean;
  onChanged: () => Promise<void>;
  onView: (view: View) => void;
}) {
  const desktop = useDesktopLayout();
  const [menu, setMenu] = useState<{ identity: string; anchor: DOMRect }>();
  const menuMember = management.members.find(
    (member) => member.identity === menu?.identity,
  );
  const [change, setChange] = useState<{ member: Member; kind: Kind }>();
  const [busy, setBusy] = useState(false);
  const [visible, setVisible] = useState(20);
  const [query, setQuery] = useState("");
  const members = (management.members ?? []).filter((member) =>
    member.name.toLocaleLowerCase().includes(query.trim().toLocaleLowerCase()),
  );
  const alive = useRef(true);
  useEffect(() => {
    alive.current = true;
    return () => {
      alive.current = false;
    };
  }, []);
  const { reportError } = useToast();
  const primary = management.primary_owner === identity;
  const confirm = async () => {
    if (!change || busy) return;
    setBusy(true);
    try {
      const reply = await invoke<{ view: View }>("operate", {
        request: {
          op: "space_role_change",
          id: space.id,
          expected_identity: identity,
          body: {
            revision: management.roles_revision,
            kind: change.kind,
            target: change.member.identity,
          },
        },
      });
      if (!alive.current) return;
      onView(reply.view);
      setChange(undefined);
      if (reply.view.spaces?.find((s) => s.id === space.id)?.owner)
        await onChanged();
    } catch (error) {
      if (alive.current) {
        reportError(error);
        await onChanged().catch(() => {});
      }
    } finally {
      if (alive.current) setBusy(false);
    }
  };
  return (
    <section className="space-members">
      {desktop && !!management.members.length && (
        <SearchField
          label={t("spaces.searchMembers")}
          value={query}
          onChange={(value) => {
            setQuery(value);
            setVisible(20);
          }}
        />
      )}
      <ul
        className="dm-people"
        aria-label={t("spaces.membersTitle", {
          count: management.members.length,
        })}
      >
        {members.slice(0, visible).map((member) => (
          <li key={member.identity}>
            <div className="dm-person contact-row">
              {!hideAvatars && (
                <span className="avatar" aria-hidden="true">
                  {member.name
                    .trim()
                    .split(/\s+/)
                    .slice(0, 2)
                    .map((part) => [...part][0] ?? "")
                    .join("")
                    .toUpperCase()}
                </span>
              )}
              <span className="dm-person-copy">
                <span className="dm-person-name">{member.name}</span>
                <span className="dm-person-context">
                  {roleLabel(member.role)}
                </span>
              </span>
              {member.role !== "primary_owner" && (
                <button
                  type="button"
                  className="icon"
                  disabled={busy}
                  aria-label={t("spaces.memberActions", { name: member.name })}
                  aria-haspopup="menu"
                  onClick={(event) =>
                    setMenu({
                      identity: member.identity,
                      anchor: event.currentTarget.getBoundingClientRect(),
                    })
                  }
                >
                  <Icon name="more" />
                </button>
              )}
            </div>
          </li>
        ))}
      </ul>
      {!members.length && (
        <EmptyState message={t("spaces.noMatchingMembers")} />
      )}
      {menu && menuMember && (
        <ActionDialog
          menu
          anchor={menu.anchor}
          title={t("spaces.memberActions", { name: menuMember.name })}
          onClose={() => setMenu(undefined)}
        >
          {menuMember.role === "member" && (
            <button
              role="menuitem"
              onClick={() => {
                setMenu(undefined);
                setChange({ member: menuMember, kind: "make_owner" });
              }}
            >
              {t("spaces.makeOwner")}
            </button>
          )}
          {menuMember.role === "owner" && (
            <button
              role="menuitem"
              onClick={() => {
                setMenu(undefined);
                setChange({ member: menuMember, kind: "remove_owner" });
              }}
            >
              {t("spaces.removeOwner")}
            </button>
          )}
          {primary && menuMember.identity !== identity && (
            <button
              role="menuitem"
              onClick={() => {
                setMenu(undefined);
                setChange({ member: menuMember, kind: "transfer_primary" });
              }}
            >
              {t("spaces.transferPrimary")}
            </button>
          )}
          {menuMember.role !== "primary_owner" &&
            menuMember.identity !== identity && (
              <button
                role="menuitem"
                className="danger"
                onClick={() => {
                  setMenu(undefined);
                  setChange({ member: menuMember, kind: "remove_member" });
                }}
              >
                {t("spaces.removeMember")}
              </button>
            )}
        </ActionDialog>
      )}
      {visible < members.length && (
        <button className="secondary" onClick={() => setVisible((n) => n + 20)}>
          {t("spaces.moreMembers")}
        </button>
      )}
      {!desktop && !!management.members?.length && (
        <FloatingSearch
          label={t("spaces.searchMembers")}
          value={query}
          onChange={(value) => {
            setQuery(value);
            setVisible(20);
          }}
        />
      )}
      {change && (
        <ActionDialog
          className="space-member-dialog"
          title={t(
            change.kind === "remove_member"
              ? "spaces.removeMemberTitle"
              : change.kind === "make_owner"
                ? "spaces.makeOwnerTitle"
                : change.kind === "remove_owner"
                  ? "spaces.removeOwnerTitle"
                  : "spaces.transferTitle",
            { name: change.member.name },
          )}
          onClose={() => {
            if (!busy) setChange(undefined);
          }}
        >
          <p className="muted">
            {t(
              change.kind === "remove_member"
                ? change.member.role === "owner" && !primary
                  ? "spaces.removeMemberApprovalHelp"
                  : "spaces.removeMemberHelp"
                : change.kind === "make_owner"
                  ? "spaces.makeOwnerHelp"
                  : change.kind === "transfer_primary"
                    ? "spaces.transferHelp"
                    : primary || change.member.identity === identity
                      ? "spaces.removeOwnerHelp"
                      : "spaces.requestRemovalHelp",
            )}
          </p>
          <div className="space-choice">
            <button
              className="secondary"
              disabled={busy}
              onClick={() => setChange(undefined)}
            >
              {t("invite.cancel")}
            </button>
            <button
              disabled={busy}
              aria-busy={busy}
              onClick={() => void confirm()}
            >
              {t("spaces.confirm")}
            </button>
          </div>
        </ActionDialog>
      )}
    </section>
  );
}

export function SpaceRoleRequests({
  view,
  onView,
}: {
  view: View;
  onView: (view: View) => void;
}) {
  const [decision, setDecision] = useState<{
    item: SpaceRoleRequest;
    approve: boolean;
  }>();
  const [busy, setBusy] = useState(false);
  const alive = useRef(true);
  const { reportError } = useToast();
  useEffect(() => {
    alive.current = true;
    return () => {
      alive.current = false;
    };
  }, []);
  const [contactEmail, setContactEmail] = useState("");
  const confirm = async () => {
    if (!decision || busy) return;
    setBusy(true);
    const item = decision.item;
    try {
      const reply = await invoke<{ view: View }>("operate", {
        request: {
          op: "space_role_decide",
          id: item.space_id,
          expected_identity: view.identity,
          body: {
            revision: item.revision,
            request_id: item.request.id,
            approve: decision.approve,
            contact_email:
              decision.approve && item.request.kind === "transfer_primary"
                ? contactEmail.trim()
                : undefined,
          },
        },
      });
      if (alive.current) {
        onView(reply.view);
        setDecision(undefined);
      }
    } catch (error) {
      if (alive.current) {
        reportError(error);
        const reply = await invoke<{ view: View }>("operate", {
          request: { op: "space_refresh", expected_identity: view.identity },
        }).catch(() => null);
        if (alive.current && reply) {
          onView(reply.view);
          setDecision(undefined);
        }
      }
    } finally {
      if (alive.current) setBusy(false);
    }
  };
  if (!view.space_role_requests?.length) return null;
  return (
    <section className="space-role-requests">
      <h3>{t("spaces.roleRequests")}</h3>
      <ul className="space-requests-list">
        {view.space_role_requests.map((item) => (
          <li
            className="space-request"
            key={`${item.space_id}:${item.request.id}`}
          >
            <p className="muted">
              {t(
                item.request.kind === "remove_member"
                  ? "spaces.memberRemovalRequest"
                  : item.request.kind === "transfer_primary"
                    ? "spaces.transferRequest"
                    : "spaces.removalRequest",
                {
                  requester: item.request.requester_name,
                  target: item.request.target_name,
                  space: item.space_name,
                },
              )}
            </p>
            <div className="space-choice">
              {[true, false].map((approve) => (
                <button
                  key={String(approve)}
                  className={approve ? "" : "secondary"}
                  disabled={busy}
                  onClick={() => {
                    setContactEmail("");
                    setDecision({ item, approve });
                  }}
                >
                  {t(approve ? "spaces.approve" : "spaces.decline")}
                </button>
              ))}
            </div>
          </li>
        ))}
      </ul>
      {decision && (
        <ActionDialog
          className="space-role-dialog"
          title={t(
            decision.approve ? "spaces.confirmRole" : "spaces.declineRole",
          )}
          onClose={() => {
            if (!busy) setDecision(undefined);
          }}
        >
          <p className="muted">
            {t(
              !decision.approve
                ? "spaces.declineRoleHelp"
                : decision.item.request.kind === "remove_member"
                  ? "spaces.removeMemberHelp"
                  : decision.item.request.kind === "transfer_primary"
                    ? "spaces.acceptPrimaryHelp"
                    : "spaces.removeOwnerHelp",
            )}
          </p>
          {decision.approve &&
            decision.item.request.kind === "transfer_primary" && (
              <SpaceContactInput
                value={contactEmail}
                onChange={setContactEmail}
                disabled={busy}
              />
            )}
          <div className="space-choice">
            <button
              className="secondary"
              disabled={busy}
              onClick={() => setDecision(undefined)}
            >
              {t("invite.cancel")}
            </button>
            <button
              disabled={
                busy ||
                (decision.approve &&
                  decision.item.request.kind === "transfer_primary" &&
                  !contactEmail.trim())
              }
              aria-busy={busy}
              onClick={() => void confirm()}
            >
              {t("spaces.confirm")}
            </button>
          </div>
        </ActionDialog>
      )}
    </section>
  );
}
