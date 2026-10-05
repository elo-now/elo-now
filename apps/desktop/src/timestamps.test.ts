import { expect, test } from "vitest";
import {
  isExpiryTimestamp,
  MAX_TIMESTAMP_MS,
  timestampIso,
} from "./timestamps";

test("numeric timestamps stay inside the Date range, including its last millisecond", () => {
  expect(timestampIso(0)).toBe("1970-01-01T00:00:00.000Z");
  expect(isExpiryTimestamp(0)).toBe(false);
  expect(isExpiryTimestamp(1)).toBe(true);
  expect(timestampIso(MAX_TIMESTAMP_MS)).toBe("+275760-09-13T00:00:00.000Z");
  expect(isExpiryTimestamp(MAX_TIMESTAMP_MS)).toBe(true);
  for (const value of [
    MAX_TIMESTAMP_MS + 1,
    Number.MAX_SAFE_INTEGER,
    Infinity,
    -Infinity,
    NaN,
    -1,
    1.5,
    "2026-10-02",
    "8640000000000001",
    null,
    undefined,
    {},
  ]) {
    expect(timestampIso(value)).toBeUndefined();
    expect(isExpiryTimestamp(value)).toBe(false);
  }
});
