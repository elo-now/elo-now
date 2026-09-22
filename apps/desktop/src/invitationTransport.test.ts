import { describe, it, expect } from "vitest";
import { QrParts, EXCHANGE_PREFIX } from "./invitationTransport";
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
