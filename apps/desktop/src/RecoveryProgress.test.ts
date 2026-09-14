import { expect, test } from "vitest";
import { acceptsRecoveryStep } from "./RecoveryProgress";
test("progress accepts only the active recovery and bounded complete event fields", () => {
  const event = { request: "current", stage: "saving", done: 2, total: 8 };
  expect(acceptsRecoveryStep(event, "current")).toBe(true);
  expect(acceptsRecoveryStep(event, "previous")).toBe(false);
  for (const value of [
    null,
    {},
    { ...event, stage: "unknown" },
    { ...event, done: 9 },
    { ...event, total: Infinity },
    { ...event, done: -1 },
  ])
    expect(acceptsRecoveryStep(value, "current")).toBe(false);
});
