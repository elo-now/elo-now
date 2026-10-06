import { describe, it, expect } from "vitest";
import {
  QrParts,
  EXCHANGE_PREFIX,
  CONTACT_PREFIX,
  SPACE_PREFIX,
  SHORT_SPACE_PREFIX,
  normalizeInvitationLink,
} from "./invitationTransport";

function shortLink(version = 1, length = 65) {
  const bytes = Uint8Array.from({ length }, (_, index) => (index * 17) % 256);
  bytes[0] = version;
  return (
    SHORT_SPACE_PREFIX +
    btoa(String.fromCharCode(...bytes))
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "")
  );
}

function bootstrapLink(origin: string | Uint8Array, version = 3) {
  const encoded =
    typeof origin === "string" ? new TextEncoder().encode(origin) : origin;
  const bytes = Uint8Array.from(
    { length: 97 + encoded.length },
    (_, index) => (index * 17) % 256,
  );
  bytes[0] = version;
  bytes.set(encoded, 97);
  return (
    SHORT_SPACE_PREFIX +
    btoa(String.fromCharCode(...bytes))
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "")
  );
}

describe("invitation input classification", () => {
  it("routes self-contained hosting invitations through the existing Space flow", () => {
    for (const origin of [
      "https://hosting.example/",
      "https://hosting.example:9443/",
      "https://[2001:db8::1]:9443/",
    ]) {
      const link = bootstrapLink(origin);
      expect(normalizeInvitationLink(` \n${link}\t`)).toEqual({
        kind: "space",
        link,
      });
      expect(new QrParts().add(link)).toBe(link);
    }
  });

  it("rejects noncanonical or unsafe bootstrap origins before native resolution", () => {
    for (const origin of [
      "",
      "http://hosting.example/",
      "HTTPS://hosting.example/",
      "https://HOSTING.example/",
      "https://hosting.example",
      "https://hosting.example:443/",
      "https://user:password@hosting.example/",
      "https://hosting.example/path",
      "https://hosting.example/?query=secret",
      "https://hosting.example/#fragment",
      "https://hosting.example/?",
      "https://hosting.example/#",
      " https://hosting.example/",
      "\ufeffhttps://hosting.example/",
      "https://hosting.example/\n",
      "https://hosting.example/\u0000",
    ]) {
      expect(normalizeInvitationLink(bootstrapLink(origin))).toBeNull();
      expect(() => new QrParts().add(bootstrapLink(origin))).toThrow(
        "invitationInvalidCode",
      );
    }
    expect(
      normalizeInvitationLink(bootstrapLink(new Uint8Array([0xff]))),
    ).toBeNull();
    expect(normalizeInvitationLink(shortLink(3, 97))).toBeNull();
    expect(
      normalizeInvitationLink(bootstrapLink("https://hosting.example/", 4)),
    ).toBeNull();
  });

  it("bounds bootstrap origins and preserves strict unpadded base64 framing", () => {
    const origin = `https://${"a".repeat(2039)}/`;
    const link = bootstrapLink(origin);
    expect(origin).toHaveLength(2048);
    expect(link.slice(SHORT_SPACE_PREFIX.length)).toHaveLength(2860);
    expect(normalizeInvitationLink(link)).toEqual({ kind: "space", link });
    const chunks = link.match(/.{1,900}/g)!;
    const parts = new QrParts();
    for (const [index, chunk] of chunks.entries()) {
      const decoded = parts.add(
        `eloqr:1:0123456789abcdef:${index}:${chunks.length}:${chunk}`,
      );
      expect(decoded).toBe(index === chunks.length - 1 ? link : null);
    }
    expect(
      normalizeInvitationLink(bootstrapLink(`https://${"a".repeat(2040)}/`)),
    ).toBeNull();
    for (const invalid of [`${link}=`, `${link}#extra`, `${link}\nextra`])
      expect(normalizeInvitationLink(invalid)).toBeNull();
  });

  it("preserves the full private-host selector without fetching or trusting it", () => {
    const link = shortLink(2, 97);
    expect(link.slice(SHORT_SPACE_PREFIX.length)).toHaveLength(130);
    expect(normalizeInvitationLink(link)).toEqual({ kind: "space", link });
    expect(normalizeInvitationLink(shortLink(1, 97))).toBeNull();
    expect(normalizeInvitationLink(shortLink(2))).toBeNull();
  });
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

  it("routes compact contact codes through exchange handling for paste and QR", () => {
    const payload = "AQIDBA";
    const link = `${CONTACT_PREFIX}${payload}`;
    expect(normalizeInvitationLink(` \n${link}\t`)).toEqual({
      kind: "exchange",
      link,
    });
    expect(new QrParts().add(` ${link}\n`)).toBe(link);

    const parts = new QrParts();
    expect(parts.add(`eloqr:1:0123456789abcdef:1:2:${payload}`)).toBeNull();
    expect(parts.add(`eloqr:1:0123456789abcdef:0:2:${CONTACT_PREFIX}`)).toBe(
      link,
    );
  });

  it("rejects empty, non-ASCII, oversized and unknown-version contact codes", () => {
    for (const invalid of [
      CONTACT_PREFIX,
      `${CONTACT_PREFIX}é`,
      `${CONTACT_PREFIX}a\u0000b`,
      `${CONTACT_PREFIX}a\nb`,
      `${CONTACT_PREFIX}${"a".repeat(2 * 1024 * 1024)}`,
      "elo://contact/v0#AQIDBA",
      "elo://contact/v2#AQIDBA",
      "elo://contact/v10#AQIDBA",
    ]) {
      expect(normalizeInvitationLink(invalid)).toBeNull();
      expect(() => new QrParts().add(invalid)).toThrow("invitationInvalidCode");
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
  it("applies version and assembled-size limits to animated contact codes", () => {
    const unknownVersion = new QrParts();
    expect(
      unknownVersion.add("eloqr:1:0123456789abcdef:0:2:elo://contact/v2#"),
    ).toBeNull();
    expect(() =>
      unknownVersion.add("eloqr:1:0123456789abcdef:1:2:AQIDBA"),
    ).toThrow("invitationInvalidCode");

    const link = `${CONTACT_PREFIX}${"a".repeat(64 * 1024)}`;
    const chunks = link.match(/.{1,900}/g)!;
    const parts = new QrParts();
    for (const [index, chunk] of chunks.entries()) {
      const frame = `eloqr:1:0123456789abcdef:${index}:${chunks.length}:${chunk}`;
      if (index === chunks.length - 1)
        expect(() => parts.add(frame)).toThrow("invitationInvalidCode");
      else expect(parts.add(frame)).toBeNull();
    }
  });

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
