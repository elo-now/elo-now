import { PageContent } from "./PageContent";
import { useEffect, useMemo, useState } from "react";
import { t } from "./i18n";
import type { View } from "./model";
import { knownPeople, findPeople } from "./directMessages";
import { ScreenHeader } from "./ScreenHeader";
import { FloatingSearch, SearchField } from "./Search";
import { Icon } from "./Icon";
import { EmptyState } from "./EmptyState";
import { BlockUserAction } from "./BlockedUsers";
import { ServiceRequestDialog } from "./ServiceRequests";
import "./contacts.css";

export function Contacts({
  view,
  hideAvatars,
  mobile,
  busy,
  onPerson,
  onScan,
  onCode,
}: {
  view: View;
  hideAvatars: boolean;
  mobile: boolean;
  busy: boolean;
  onPerson: (id: string, name: string) => void;
  onScan: () => void;
  onCode: () => void;
}) {
  const [query, setQuery] = useState("");
  const [report, setReport] = useState<string>();
  useEffect(() => setReport(undefined), [view.identity, view.active_space]);
  const people = useMemo(() => knownPeople(view), [view]);
  const visible = findPeople(people, query);
  return (
    <section className="contacts-page content-pane">
      <ScreenHeader
        title={t("nav.contacts")}
        search={
          <SearchField
            label={t("contacts.search")}
            value={query}
            onChange={setQuery}
          />
        }
        actions={
          <>
            {mobile && (
              <button
                className="icon"
                aria-label={t("invite.myCode")}
                onClick={onCode}
              >
                <Icon name="qr" />
              </button>
            )}
            <button
              type="button"
              className="icon"
              aria-label={t("contacts.add")}
              title={t("contacts.add")}
              onClick={onScan}
            >
              <Icon name="plus" />
            </button>
          </>
        }
      />
      <PageContent className="contacts-viewport">
        <div className="contacts-list">
          {visible.length ? (
            <ul className="dm-people">
              {visible.map((person) => (
                <li key={person.id}>
                  <div className="dm-person contact-row">
                    {!hideAvatars && (
                      <span className="avatar" aria-hidden="true">
                        {person.initials}
                      </span>
                    )}
                    <span className="dm-person-copy">
                      <span className="dm-person-name">{person.name}</span>
                    </span>
                    <button
                      className="icon contact-message"
                      disabled={
                        busy ||
                        !!view.blocked_users?.some(
                          (p) => p.identity === person.id,
                        )
                      }
                      aria-label={t("contacts.message", { name: person.name })}
                      title={t("contacts.message", { name: person.name })}
                      onClick={() => onPerson(person.id, person.name)}
                    >
                      <Icon name="chats" />
                    </button>
                    <BlockUserAction
                      identity={person.id}
                      name={person.name}
                      icon
                      blocked={
                        !!view.blocked_users?.some(
                          (p) => p.identity === person.id,
                        )
                      }
                    />
                    {person.id !== view.identity && (
                      <button
                        className="icon"
                        disabled={busy}
                        aria-label={t("requests.reportPerson", {
                          name: person.name,
                        })}
                        onClick={() => setReport(person.id)}
                      >
                        <Icon name="flag" />
                      </button>
                    )}
                  </div>
                </li>
              ))}
            </ul>
          ) : (
            <EmptyState
              message={t(
                query.trim() ? "contacts.noResults" : "contacts.empty",
              )}
            />
          )}
        </div>
        <FloatingSearch
          label={t("contacts.search")}
          value={query}
          onChange={setQuery}
        />
      </PageContent>
      {report && (
        <ServiceRequestDialog
          mobile={mobile}
          view={view}
          target={{ identity: report }}
          onClose={() => setReport(undefined)}
        />
      )}
    </section>
  );
}
