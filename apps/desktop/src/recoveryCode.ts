/** A copyable representation only; the native core still verifies the recovery material. */
export function recoveryCode(card: {
  identity_id: string;
  phrase: string;
}): string {
  return `${card.identity_id}|${card.phrase.trim().split(/\s+/u).join(",")}`;
}

export function parseRecoveryCode(
  value: string,
): { identity_id: string; phrase: string } | null {
  if (value.length > 2048) return null;
  const parts = value.trim().split("|");
  if (parts.length !== 2) return null;
  const identity_id = parts[0].trim().toLowerCase();
  const words = parts[1].split(",").map((word) => word.trim().toLowerCase());
  if (
    !/^[a-f0-9]{64}$/u.test(identity_id) ||
    words.length !== 24 ||
    words.some((word) => !/^[a-z]+$/u.test(word))
  )
    return null;
  return { identity_id, phrase: words.join(" ") };
}
