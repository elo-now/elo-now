import { describe, expect, it } from "vitest";
import { formatMessageDay, formatMessageTime, messageDayKey } from "./i18n";

describe("conversation date dividers", () => {
  it("groups messages on the same local day and separates midnight", () => {
    const zone = "Europe/Warsaw";
    expect(messageDayKey("2026-09-08T22:05:00Z", zone)).toBe("2026-09-09");
    expect(messageDayKey("2026-09-09T21:59:00Z", zone)).toBe("2026-09-09");
    expect(messageDayKey("2026-09-09T22:00:00Z", zone)).toBe("2026-09-10");
    expect(messageDayKey("2026-09-09T01:00:00Z", "America/Los_Angeles")).toBe(
      "2026-09-08",
    );
  });

  it("keeps both occurrences of a repeated daylight-saving hour on one day", () => {
    expect(messageDayKey("2026-10-25T00:30:00Z", "Europe/Warsaw")).toBe(
      messageDayKey("2026-10-25T01:30:00Z", "Europe/Warsaw"),
    );
  });

  it("shows only hours and minutes beside a valid message", () => {
    expect(formatMessageTime("2026-09-09T09:04:00Z")).toMatch(/^\d{2}:\d{2}$/);
    expect(formatMessageTime("2026-09-09T09:04:00Z", true)).toContain("Sep");
    expect(formatMessageTime("2026-09-09T09:04:00Z", true)).not.toContain(
      "2026",
    );
    expect(formatMessageDay("2026-09-09T09:04:00Z")).not.toContain("2026");
  });

  it("does not invent a date for absent or invalid timestamps", () => {
    expect(messageDayKey(undefined)).toBe("unknown");
    expect(messageDayKey("not a date")).toBe("unknown");
    expect(formatMessageDay(undefined)).toBe("Date unavailable");
    expect(formatMessageTime("invalid timestamp")).toBe("invalid timestamp");
  });
});
