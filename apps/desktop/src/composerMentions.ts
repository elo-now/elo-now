import { senderName, visibleMembers, type Stream, type View } from "./model";

export type MentionCandidate = { identity_id: string; label: string };
/** Offsets are UTF-16 textarea offsets, never inferred from a display name. */
export type ComposerMention = MentionCandidate & { start: number; end: number };

export function mentionCandidates(
  view: View,
  chat: Stream,
): MentionCandidate[] {
  return visibleMembers(view, chat, "")
    .filter((member) => member.capabilities.includes("READ"))
    .map((member) => ({
      identity_id: member.identity_id,
      label: senderName(view, member.identity_id, chat)
        .replace(/\s+/gu, " ")
        .trim()
        .slice(0, 80),
    }))
    .filter((candidate) => !!candidate.label);
}

const word = /[\p{L}\p{N}_@]/u;
function validMention(text: string, mention: ComposerMention): boolean {
  return (
    Number.isInteger(mention.start) &&
    Number.isInteger(mention.end) &&
    mention.start >= 0 &&
    mention.end <= text.length &&
    mention.end > mention.start &&
    !!mention.identity_id &&
    !!mention.label &&
    text.slice(mention.start, mention.end) === `@${mention.label}` &&
    (mention.start === 0 ||
      !word.test(Array.from(text.slice(0, mention.start)).at(-1)!)) &&
    (mention.end === text.length ||
      !word.test(Array.from(text.slice(mention.end))[0]))
  );
}

/** Keep selected identities only while their exact annotated text survives. */
export function reconcileMentions(
  previous: string,
  next: string,
  mentions: ComposerMention[],
): ComposerMention[] {
  let prefix = 0;
  while (
    prefix < previous.length &&
    prefix < next.length &&
    previous[prefix] === next[prefix]
  )
    prefix++;
  let suffix = 0;
  while (
    suffix < previous.length - prefix &&
    suffix < next.length - prefix &&
    previous[previous.length - 1 - suffix] === next[next.length - 1 - suffix]
  )
    suffix++;
  const oldEnd = previous.length - suffix;
  const delta = next.length - previous.length;
  return mentions.flatMap((mention) => {
    if (!validMention(previous, mention)) return [];
    const kept =
      mention.end <= prefix
        ? mention
        : mention.start >= oldEnd
          ? {
              ...mention,
              start: mention.start + delta,
              end: mention.end + delta,
            }
          : undefined;
    return kept && validMention(next, kept) ? [kept] : [];
  });
}

export function mentionIdentities(
  text: string,
  mentions: ComposerMention[],
): string[] {
  return [
    ...new Set(
      mentions
        .filter((mention) => validMention(text, mention))
        .map((mention) => mention.identity_id),
    ),
  ]
    .sort()
    .slice(0, 32);
}

/** Restore signed mention IDs for editing only when their current name is unambiguous. */
export function restoredMentions(
  text: string,
  identities: string[],
  candidates: MentionCandidate[],
): ComposerMention[] {
  return candidates
    .filter(
      (candidate) =>
        identities.includes(candidate.identity_id) &&
        candidates.filter((other) => other.label === candidate.label).length ===
          1,
    )
    .flatMap((candidate) => {
      const spans: ComposerMention[] = [];
      const token = `@${candidate.label}`;
      let start = text.indexOf(token);
      while (start !== -1) {
        const mention = { ...candidate, start, end: start + token.length };
        if (validMention(text, mention)) spans.push(mention);
        start = text.indexOf(token, start + token.length);
      }
      return spans;
    })
    .sort((a, b) => a.start - b.start);
}

export function mentionQuery(
  text: string,
  caret: number,
): { start: number; end: number; query: string } | undefined {
  const before = text.slice(0, caret);
  const start = before.lastIndexOf("@");
  if (
    start < 0 ||
    (start > 0 && word.test(Array.from(before.slice(0, start)).at(-1)!))
  )
    return;
  const query = before.slice(start + 1);
  if (query.length > 80 || /[\n\r@]/u.test(query)) return;
  return { start, end: caret, query };
}

export function insertMention(
  text: string,
  mentions: ComposerMention[],
  query: NonNullable<ReturnType<typeof mentionQuery>>,
  candidate: MentionCandidate,
) {
  const token = `@${candidate.label}`;
  const next = `${text.slice(0, query.start)}${token} ${text.slice(query.end)}`;
  const kept = reconcileMentions(text, next, mentions);
  return {
    text: next,
    mentions: [
      ...kept,
      { ...candidate, start: query.start, end: query.start + token.length },
    ],
    caret: query.start + token.length + 1,
  };
}
