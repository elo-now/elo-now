import { profileName, senderInitials, senderName, type View } from "./model";

export type KnownPerson = {
  id: string;
  name: string;
  initials: string;
  chats: string[];
};

/** Explicitly saved cards and verified current memberships, never a global directory. */
export function knownPeople(view: View): KnownPerson[] {
  const people = new Map<string, KnownPerson>();
  for (const contact of view.contacts ?? []) {
    if (contact.id === view.identity) continue;
    people.set(contact.id, {
      ...contact,
      initials: contact.name
        .trim()
        .split(/\s+/)
        .slice(0, 2)
        .map((part) => [...part][0] ?? "")
        .join("")
        .toUpperCase(),
      chats: [],
    });
  }
  for (const chat of view.streams) {
    if (
      chat.forked ||
      !chat.members.some(
        (member) =>
          member.identity_id === view.identity &&
          member.capabilities.includes("READ") &&
          member.credential_ids.includes(view.credential),
      )
    )
      continue;
    for (const member of chat.members) {
      if (
        member.identity_id === view.identity ||
        member.identity_type !== "HUMAN" ||
        !member.credential_ids.length
      )
        continue;
      const existing = people.get(member.identity_id);
      if (existing) {
        if (!existing.chats.includes(chat.name)) existing.chats.push(chat.name);
        if (chat.member_names?.[member.identity_id]) {
          existing.name = senderName(view, member.identity_id, chat);
          existing.initials = senderInitials(view, member.identity_id, chat);
        }
      } else {
        people.set(member.identity_id, {
          id: member.identity_id,
          name: senderName(view, member.identity_id, chat),
          initials: senderInitials(view, member.identity_id, chat),
          chats: [chat.name],
        });
      }
    }
  }
  return [...people.values()].sort(
    (a, b) => a.name.localeCompare(b.name) || a.id.localeCompare(b.id),
  );
}

export function findPeople(
  people: KnownPerson[],
  query: string,
): KnownPerson[] {
  const needle = query.trim().toLocaleLowerCase();
  return needle
    ? people.filter(
        (person) =>
          person.name.toLocaleLowerCase().includes(needle) ||
          person.chats.some((chat) =>
            chat.toLocaleLowerCase().includes(needle),
          ),
      )
    : people;
}

export function directName(view: View, people: KnownPerson[]): string {
  const names = [
    ...(people.length === 1
      ? []
      : [profileName(view) || view.identity.slice(0, 8)]),
    ...people.map((person) => person.name),
  ];
  const text = names.join(", ").replace(/[\u0000-\u001f\u007f]/g, "");
  const encoder = new TextEncoder();
  if (encoder.encode(text).length <= 120) return text;
  let prefix = "";
  for (const letter of text) {
    if (encoder.encode(prefix + letter).length > 117) break;
    prefix += letter;
  }
  return prefix.trimEnd() + "…";
}
