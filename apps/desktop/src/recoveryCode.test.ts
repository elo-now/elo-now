import { describe, expect, it } from "vitest";
import { parseRecoveryCode, recoveryCode } from "./recoveryCode";

const card = {
  identity_id: "ab".repeat(32),
  phrase: "abandon ".repeat(23) + "art",
};

describe("copyable recovery code", () => {
  it("round-trips all 24 words and the identity without numbering", () => {
    const code = recoveryCode(card);
    expect(code).toBe(
      `${card.identity_id}|${Array(23).fill("abandon").join(",")},art`,
    );
    expect(parseRecoveryCode(code)).toEqual(card);
  });
  it("normalizes whitespace around separators and uppercase without changing order", () => {
    expect(
      parseRecoveryCode(
        ` \n${recoveryCode(card).toUpperCase().replaceAll(",", ", \n").replace("|", " | ")}  `,
      ),
    ).toEqual(card);
  });
  it("rejects incomplete, ambiguous and oversized combined codes", () => {
    for (const code of [
      "",
      `${card.identity_id}|abandon`,
      recoveryCode(card) + ",art",
      recoveryCode(card) + "|",
      recoveryCode(card).replace("abandon", "1.abandon"),
      "x".repeat(64) + recoveryCode(card).slice(64),
      " ".repeat(2049),
    ]) {
      expect(parseRecoveryCode(code)).toBeNull();
    }
  });
});
