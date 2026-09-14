import type { Stream, View } from "./model";
import type { MessageKey } from "./i18n";
import type { IconName } from "./Icon";

export function isDirectChat(chat: Stream, identity: string): boolean {
  const people = new Set(chat.members.map((member) => member.identity_id));
  if (chat.chat_kind) {
    return chat.chat_kind === "direct" && people.has(identity);
  }
  return (
    people.size === 2 &&
    people.has(identity) &&
    chat.members.every(
      (member) => !member.identity_type || member.identity_type === "HUMAN",
    )
  );
}

export function chatIconName(chat: Stream, identity: string): IconName {
  if (!isDirectChat(chat, identity)) return "hash";
  const people = new Set(chat.members.map((member) => member.identity_id));
  return people.size > 2 ? "people" : "person";
}

// Presentation ordering only. Signed timestamps are not delivery receipts or
// evidence that a peer's clock is accurate. Invalid dates never become "now".
export function chatActivity(chat: Stream): number {
  return chat.rows.reduce((latest, row) => {
    const timestamp = Date.parse(row.body.created_at ?? "");
    return Number.isFinite(timestamp) ? Math.max(latest, timestamp) : latest;
  }, chat.created_at ?? 0);
}

export type ChatSection = {
  id: string;
  title?: MessageKey;
  chats: Stream[];
};

export function chatSections(
  view: View,
  filter: string,
  query = "",
): ChatSection[] {
  const ordered = [...view.streams].sort(
    (a, b) => chatActivity(b) - chatActivity(a),
  );
  const search = query.trim().toLocaleLowerCase();
  if (search) {
    return [
      {
        id: "search",
        chats: ordered.filter((chat) =>
          [
            chat.name,
            chat.rows.at(-1)?.body.payload?.text ?? "",
            chat.group
              ? ((view.groups ?? []).find((group) => group.id === chat.group)
                  ?.name ?? "")
              : "",
          ].some((value) => value.toLocaleLowerCase().includes(search)),
        ),
      },
    ];
  }
  if (filter === "overview") {
    const general = ordered.filter((chat) => chat.is_general === true);
    const remaining = ordered.filter((chat) => chat.is_general !== true);
    const recent = remaining.slice(0, 5);
    const ids = new Set(recent.map((chat) => chat.stream));
    const sections: ChatSection[] = [
      { id: "general", chats: general },
      { id: "recent", title: "groups.recent", chats: recent },
      {
        id: "ungrouped",
        title: "groups.ungrouped",
        chats: remaining.filter((chat) => !chat.group && !ids.has(chat.stream)),
      },
    ];
    return sections.filter((section) => section.chats.length > 0);
  }
  return [
    {
      id: filter,
      chats: ordered.filter((chat) =>
        filter === "dms"
          ? isDirectChat(chat, view.identity)
          : chat.group === filter,
      ),
    },
  ];
}
