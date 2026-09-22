// QR framing is transport only. Rust validates every complete signed exchange.
export const EXCHANGE_PREFIX = "elo://exchange/v1#";
export class QrParts {
  private id = "";
  private count = 0;
  private parts = new Map<number, string>();
  get progress() {
    return { received: this.parts.size, total: this.count };
  }
  add(content: string): string | null {
    if (content.startsWith(EXCHANGE_PREFIX)) {
      if (content.length > 2 * 1024 * 1024)
        throw new Error("invitationTooLarge");
      return content;
    }
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
    if (!link.startsWith(EXCHANGE_PREFIX) || link.length > 64 * 1024)
      throw new Error("invitationInvalidCode");
    return link;
  }
}
