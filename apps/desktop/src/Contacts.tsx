import { useMemo, useState } from "react";
import { t } from "./i18n";
import type { View } from "./model";
import { knownPeople, findPeople } from "./directMessages";
import { ScreenHeader } from "./ScreenHeader";
import { FloatingSearch } from "./Search";
import { Icon } from "./Icon";
import { EmptyState } from "./EmptyState";
import "./contacts.css";

export function Contacts({
  view,
  hideAvatars,
  busy,
  onPerson,
  onScan,
  onMessages,
  onCode,
}: {
  view: View;
  hideAvatars: boolean;
  busy: boolean;
  onPerson: (id: string, name: string) => void;
  onScan: () => void;
  onMessages: () => void;
  onCode: () => void;
}) {
  const [query, setQuery] = useState("");
  const people = useMemo(() => knownPeople(view), [view]);
  const visible = findPeople(people, query);
  return (
    <section className="contacts-page">
      <ScreenHeader
        title={t("nav.contacts")}
        actions={
          <>
            <button
              className="icon"
              aria-label={t("invite.myCode")}
              onClick={onCode}
            >
              <Icon name="qr" />
            </button>
            <span className="desktop-only">
              <button
                className="icon"
                aria-label={t("nav.chats")}
                onClick={onMessages}
              >
                <Icon name="chats" />
              </button>
            </span>
          </>
        }
      />
      <div className="contacts-viewport">
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
                      disabled={busy}
                      aria-label={t("contacts.message", { name: person.name })}
                      title={t("contacts.message", { name: person.name })}
                      onClick={() => onPerson(person.id, person.name)}
                    >
                      <Icon name="chats" />
                    </button>
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
        <div className="floating-search contact-add">
          <div className="search-orb">
            <button
              className="search-toggle"
              aria-label={t("contacts.add")}
              onClick={onScan}
            >
              <Icon name="plus" />
            </button>
          </div>
        </div>
        <FloatingSearch
          label={t("contacts.search")}
          value={query}
          onChange={setQuery}
        />
      </div>
    </section>
  );
}
