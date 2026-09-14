import { t } from "./i18n";
import { Icon } from "./Icon";
import { FloatingSearch } from "./Search";
import { EmptyState } from "./EmptyState";
import { findPeople, type KnownPerson } from "./directMessages";

export function PeoplePicker({
  people,
  selected,
  query,
  onQuery,
  onToggle,
  hideAvatars,
  disabled,
  limit = 999,
}: {
  people: KnownPerson[];
  selected: string[];
  query: string;
  onQuery: (value: string) => void;
  onToggle: (id: string) => void;
  hideAvatars: boolean;
  disabled: boolean;
  limit?: number;
}) {
  const visible = findPeople(people, query);
  const chosen = people.filter((person) => selected.includes(person.id));
  return (
    <>
      {!!chosen.length && (
        <div className="dm-selection" aria-label={t("dm.selected")}>
          {chosen.map((person) => (
            <button
              key={person.id}
              type="button"
              disabled={disabled}
              aria-label={t("dm.removePerson", { name: person.name })}
              onClick={() => onToggle(person.id)}
            >
              {person.name}
              <Icon name="close" />
            </button>
          ))}
        </div>
      )}
      <div className="dm-people-viewport">
        <div className="dm-people-scroll">
          {!visible.length && (
            <EmptyState
              message={t(people.length ? "dm.noResults" : "dm.noPeople")}
            />
          )}
          <ul className="dm-people" aria-label={t("dm.people")}>
            {visible.map((person) => (
              <li key={person.id}>
                <label
                  className="dm-person"
                  data-hide-avatars={hideAvatars || undefined}
                >
                  {!hideAvatars && (
                    <span className="avatar" aria-hidden="true">
                      {person.initials}
                    </span>
                  )}
                  <span className="dm-person-copy">
                    <span className="dm-person-name">{person.name}</span>
                    <span className="dm-person-context">
                      {person.chats.join(", ")}
                      {people.some(
                        (other) =>
                          other.id !== person.id && other.name === person.name,
                      ) && ` · ${person.id.slice(0, 8)}`}
                    </span>
                  </span>
                  <input
                    type="checkbox"
                    checked={selected.includes(person.id)}
                    onChange={() => onToggle(person.id)}
                    disabled={
                      disabled ||
                      (!selected.includes(person.id) &&
                        selected.length >= limit)
                    }
                    aria-label={person.name}
                  />
                </label>
              </li>
            ))}
          </ul>
        </div>
        <FloatingSearch
          label={t("dm.findPeople")}
          value={query}
          onChange={onQuery}
          disabled={disabled}
        />
      </div>
    </>
  );
}
