import { describe, it, expect } from "vitest";
import { t, warningText, formatTimestamp, formatFileSize } from "./i18n";

describe("English presentation without changing user data", () => {
  it("inserts user values literally and requires every named value", () => {
    expect(t("preview.recipient", { recipient: "A {count} <B>" })).toBe(
      "Recipient: A {count} <B>",
    );
    expect(() => t("preview.recipient")).toThrow("Missing message value");
    expect(t("thread.replies", { count: 1000 })).toBe("1,000 replies");
  });
  it("keeps unknown warnings visible and preserves recovery limitations", () => {
    expect(
      warningText("future_warning", "Additional verification needed"),
    ).toBe("Additional verification needed");
    const recovery = warningText("recovery_requires_review", "fallback");
    expect(recovery).toContain("old keys and history are not recovered");
    expect(recovery).toContain("Offline clients may not know");
    expect(warningText("history_may_be_incomplete", "fallback")).toContain(
      "does not prove",
    );
  });
  it("formats valid timestamps in UTC and preserves unrecognized input", () => {
    const original = "2026-09-09T12:00:00Z";
    expect(formatTimestamp(original, "UTC")).toContain("Sep 9, 2026");
    expect(formatTimestamp(original, "UTC")).toContain("12:00:00 UTC");
    expect(original).toBe("2026-09-09T12:00:00Z");
    expect(formatTimestamp("unknown")).toBe("unknown");
    expect(formatTimestamp(undefined)).toBe("");
  });
  it("shows compact attachment sizes without exposing raw byte counts", () => {
    expect(formatFileSize(512)).toBe("512 B");
    expect(formatFileSize(1024)).toBe("1 KB");
    expect(formatFileSize(1153434)).toBe("1.1 MB");
    expect(formatFileSize(5 * 1024 * 1024)).toBe("5 MB");
  });
});
