import { describe, expect, it } from "vitest";
import { messageStatusKind } from "./MessageStatus";

describe("Message status presentation", () => {
  it("does not claim that a targetless local message is queued", () => {
    expect(messageStatusKind("LOCAL")).toBe("pending");
    expect(messageStatusKind("QUEUED")).toBe("queued");
  });
  it("groups verified incoming records and acknowledged storage as synced", () => {
    expect(messageStatusKind("ACCEPTED")).toBe("synced");
    expect(messageStatusKind("STORED")).toBe("synced");
  });
  it("keeps missing copies and security holds distinct from successful sync", () => {
    for (const state of [
      "REPAIR_PENDING",
      "HELD_STALE_CONFIG",
      "QUARANTINED_STALE",
      "WAITING_FOR_PROOF",
    ])
      expect(messageStatusKind(state)).toBe("pending");
  });
  it("shows rejected and unknown states as issues without implying delivery", () => {
    for (const state of ["REJECTED", "new-state", "", "__proto__", "toString"])
      expect(messageStatusKind(state)).toBe("issue");
  });
});
