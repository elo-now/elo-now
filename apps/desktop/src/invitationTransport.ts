// QR framing is transport only. Rust validates every complete signed exchange.
export const EXCHANGE_PREFIX = "elo://exchange/v1#";
export const CONTACT_PREFIX = "elo://contact/v1#";
export const SPACE_PREFIX = "elo://space/v1#";
export const SHORT_SPACE_PREFIX = "https://elo.now/join#";
export type InvitationLink = { kind: "space" | "exchange"; link: string };

// Classification never fetches a URL or extracts a seed for another consumer.
// Rust remains responsible for verifying the invitation and deployment pins.
export function normalizeInvitationLink(value: string): InvitationLink | null {
  const link = value.trim();
  if (link.startsWith(SHORT_SPACE_PREFIX)) {
    const fragment = link.slice(SHORT_SPACE_PREFIX.length);
    if (!/^(?:[A-Za-z0-9_-]{87}|[A-Za-z0-9_-]{130})$/.test(fragment))
      return null;
    try {
      const bytes = atob(
        fragment.replace(/-/g, "+").replace(/_/g, "/") +
          "=".repeat((4 - (fragment.length % 4)) % 4),
      );
      const canonical = btoa(bytes)
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=+$/, "");
      if (
        !(
          (bytes.length === 65 && bytes.charCodeAt(0) === 1) ||
          (bytes.length === 97 && bytes.charCodeAt(0) === 2)
        ) ||
        canonical !== fragment
      )
        return null;
    } catch {
      return null;
    }
    return { kind: "space", link };
  }
  if (link.length > 2 * 1024 * 1024 || !/^[\x20-\x7e]+$/.test(link))
    return null;
  if (link.startsWith(SPACE_PREFIX) && link.length > SPACE_PREFIX.length)
    return { kind: "space", link };
  if (
    (link.startsWith(EXCHANGE_PREFIX) &&
      link.length > EXCHANGE_PREFIX.length) ||
    (link.startsWith(CONTACT_PREFIX) && link.length > CONTACT_PREFIX.length)
  )
    return { kind: "exchange", link };
  return null;
}

export class QrParts {
  private id = "";
  private count = 0;
  private parts = new Map<number, string>();
  get progress() {
    return { received: this.parts.size, total: this.count };
  }
  add(content: string): string | null {
    const direct = normalizeInvitationLink(content);
    if (direct) return direct.link;
    const m = /^eloqr:1:([a-f0-9]{16}):(\d{1,2}):(\d{1,2}):([\s\S]+)$/.exec(
      content,
    );
    if (!m) throw new Error("invitationInvalidCode");
    const index = Number(m[2]),
      count = Number(m[3]),
      part = m[4];
    if (
      count < 2 ||
      count > 80 ||
      index >= count ||
      part.length > 900 ||
      !/^[\x20-\x7e]+$/.test(part)
    )
      throw new Error("invitationInvalidCode");
    if (this.id && (this.id !== m[1] || this.count !== count))
      throw new Error("invitationMixedCodes");
    this.id = m[1];
    this.count = count;
    const previous = this.parts.get(index);
    if (previous !== undefined && previous !== part)
      throw new Error("invitationMixedCodes");
    this.parts.set(index, part);
    if (this.parts.size !== count) return null;
    const link = Array.from({ length: count }, (_, i) =>
      this.parts.get(i),
    ).join("");
    const complete = normalizeInvitationLink(link);
    if (!complete || link.length > 64 * 1024)
      throw new Error("invitationInvalidCode");
    return complete.link;
  }
}
