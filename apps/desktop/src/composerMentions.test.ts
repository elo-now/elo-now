import { describe, expect, it } from "vitest";
import {
  insertMention,
  mentionIdentities,
  mentionQuery,
  reconcileMentions,
  restoredMentions,
  type ComposerMention,
} from "./composerMentions";

const person = { identity_id: "id-alice", label: "Alice Jones" };
const selected = (text = "Hello @Al") =>
  insertMention(text, [], mentionQuery(text, text.length)!, person);

describe("Identity-bound mentions", () => {
  it("selects a member identity and keeps full names and exact UTF-16 offsets", () => {
    const value = selected("👋 @Al");
    expect(value.text).toBe("👋 @Alice Jones ");
    expect(value.mentions).toEqual([{ ...person, start: 3, end: 15 }]);
    expect(mentionIdentities(value.text, value.mentions)).toEqual([
      person.identity_id,
    ]);
  });

  it("never turns pasted or manually typed names into signed mentions", () => {
    expect(mentionIdentities("Hello @Alice Jones", [])).toEqual([]);
    expect(reconcileMentions("", "@Alice Jones", [])).toEqual([]);
    expect(restoredMentions("@Alice Jones", [], [person])).toEqual([]);
    expect(mentionQuery("alice@example.com", 9)).toBeUndefined();
    expect(mentionQuery("x_@Al", 5)).toBeUndefined();
    expect(mentionQuery("Hello (@Al", 10)).toEqual({
      start: 7,
      end: 10,
      query: "Al",
    });
  });

  it("retains and shifts identities for unrelated edits and drops edited or deleted mention text", () => {
    const { text, mentions } = selected();
    const prefixed = `🙂 ${text}`;
    const shifted = reconcileMentions(text, prefixed, mentions);
    expect(shifted[0].start).toBe(9);
    expect(mentionIdentities(prefixed, shifted)).toEqual([person.identity_id]);
    expect(
      reconcileMentions(text, text.replace("Jones", "Smith"), mentions),
    ).toEqual([]);
    expect(reconcileMentions(text, "Hello ", mentions)).toEqual([]);
    expect(reconcileMentions(text, "Hello @Alice Jonesy ", mentions)).toEqual(
      [],
    );
    expect(reconcileMentions(text, "Hello X@Alice Jones ", mentions)).toEqual(
      [],
    );
    expect(reconcileMentions(text, `${text}next`, mentions)).toEqual(mentions);
  });

  it("allows identical display names to target distinct selected identities, without guessing during editing", () => {
    const other = { identity_id: "id-second", label: person.label };
    const first = selected();
    const typed = `${first.text}@Al`;
    const second = insertMention(
      typed,
      first.mentions,
      mentionQuery(typed, typed.length)!,
      other,
    );
    expect(mentionIdentities(second.text, second.mentions)).toEqual([
      person.identity_id,
      other.identity_id,
    ]);
    expect(
      restoredMentions(
        second.text,
        [person.identity_id, other.identity_id],
        [person, other],
      ),
    ).toEqual([]);
  });

  it("validates restored spans, removes duplicates and keeps punctuation boundaries", () => {
    const text = "@Alice Jones, thanks @Alice Jones!";
    const spans = restoredMentions(text, [person.identity_id], [person]);
    expect(spans).toHaveLength(2);
    expect(mentionIdentities(text, spans)).toEqual([person.identity_id]);
    const invalid = [
      { ...spans[0], start: -1 },
      { ...spans[0], end: 200 },
      { ...spans[0], label: "Other" },
      { ...spans[0], start: NaN },
    ] as ComposerMention[];
    expect(mentionIdentities(text, invalid)).toEqual([]);
    expect(
      restoredMentions(
        "email@Alice Jones and @Alice JonesExtra",
        [person.identity_id],
        [person],
      ),
    ).toEqual([]);
  });

  it("does not leak a mention identity when a selection replaces its token", () => {
    const first = selected();
    const replacement = "Hello @Bo ";
    const kept = reconcileMentions(first.text, replacement, first.mentions);
    expect(kept).toEqual([]);
    const result = insertMention(
      replacement,
      kept,
      { start: 6, end: 9, query: "Bo" },
      { identity_id: "id-bob", label: "Bob" },
    );
    expect(mentionIdentities(result.text, result.mentions)).toEqual(["id-bob"]);
  });
});
