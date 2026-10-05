import { describe, it, expect } from "vitest";
import {
  QrParts,
  EXCHANGE_PREFIX,
  SPACE_PREFIX,
  SHORT_SPACE_PREFIX,
  normalizeInvitationLink,
} from "./invitationTransport";

function shortLink(version = 1) {
  const bytes = Uint8Array.from(
    { length: 65 },
    (_, index) => (index * 17) % 256,
  );
  bytes[0] = version;
  return (
    SHORT_SPACE_PREFIX +
    btoa(String.fromCharCode(...bytes))
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "")
  );
}

describe("invitation input classification", () => {
  it("routes a canonical short link to Space while preserving the secret fragment", () => {
    const link = shortLink();
    expect(link.slice(SHORT_SPACE_PREFIX.length)).toHaveLength(87);
    expect(normalizeInvitationLink(` \n${link}\t`)).toEqual({
      kind: "space",
      link,
    });
    expect(new QrParts().add(link)).toBe(link);
  });

  it("retains existing exchange and Space invitations across paste and QR", () => {
    for (const [prefix, kind] of [
      [EXCHANGE_PREFIX, "exchange"],
      [SPACE_PREFIX, "space"],
    ]) {
      const link = `${prefix}aB7_-xyz9`;
      expect(normalizeInvitationLink(` ${link}\n`)).toEqual({ kind, link });
      expect(new QrParts().add(` ${link}\n`)).toBe(link);
      const parts = new QrParts();
      expect(parts.add(`eloqr:1:0123456789abcdef:1:2:aB7_-xyz9`)).toBeNull();
      expect(parts.add(`eloqr:1:0123456789abcdef:0:2:${prefix}`)).toBe(link);
    }
  });

  it("rejects alternate origins, URL encodings, query fields and fragment suffixes", () => {
    const link = shortLink();
    for (const invalid of [
      link.replace("https:", "http:"),
      link.replace("https:", "HTTPS:"),
      link.replace("elo.now/", "elo.now.example/"),
      link.replace("elo.now/", "user@elo.now/"),
      link.replace("elo.now/", "elo.now:443/"),
      link.replace("/join#", "/join/#"),
      link.replace("/join#", "/join?seed=private#"),
      link.replace("#A", "#%41"),
      `${link}=`,
      `${link}#another`,
      `${link}&extra`,
      `${link}\nextra`,
      link.slice(0, -1),
      shortLink(2),
    ]) {
      expect(normalizeInvitationLink(invalid)).toBeNull();
      expect(() => new QrParts().add(invalid)).toThrow("invitationInvalidCode");
    }
  });

  it("rejects noncanonical base64 padding bits even when they decode to the same bytes", () => {
    const link = shortLink();
    const alphabet =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    const last = alphabet.indexOf(link.at(-1)!);
    expect(last % 4).toBe(0);
    const invalid = link.slice(0, -1) + alphabet[last + 1];
    expect(normalizeInvitationLink(invalid)).toBeNull();
  });

  it("keeps malformed and oversized input out of invitation entrypoints", () => {
    for (const value of [
      "",
      "https://example.com",
      `${SPACE_PREFIX}é`,
      `${EXCHANGE_PREFIX}a\u0000b`,
      `${EXCHANGE_PREFIX}${"a".repeat(2 * 1024 * 1024)}`,
    ])
      expect(normalizeInvitationLink(value)).toBeNull();
  });
});

describe("QR exchange transport", () => {
  it("reassembles only a complete consistent transfer", () => {
    const p = new QrParts();
    expect(p.add("eloqr:1:0123456789abcdef:1:2:payload")).toBeNull();
    expect(p.add("eloqr:1:0123456789abcdef:1:2:payload")).toBeNull();
    expect(p.progress).toEqual({ received: 1, total: 2 });
    expect(p.add(`eloqr:1:0123456789abcdef:0:2:${EXCHANGE_PREFIX}`)).toBe(
      `${EXCHANGE_PREFIX}payload`,
    );
  });
  it("rejects mixed, conflicting, oversized and foreign codes", () => {
    const p = new QrParts();
    p.add("eloqr:1:0123456789abcdef:0:2:part");
    expect(() => p.add("eloqr:1:fedcba9876543210:1:2:other")).toThrow();
    expect(() => p.add("eloqr:1:0123456789abcdef:0:2:different")).toThrow();
    expect(() => new QrParts().add("https://example.com")).toThrow();
    expect(() =>
      new QrParts().add(`eloqr:1:0123456789abcdef:0:2:${"a".repeat(901)}`),
    ).toThrow();
    expect(() =>
      new QrParts().add(`eloqr:1:0123456789abcdef:0:99:part`),
    ).toThrow();
  });
});
