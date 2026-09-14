import { describe, expect, it } from "vitest";
import { distinctErrorDetail, presentError } from "./errors";
import { en } from "./locales/en";

describe("native error presentation", () => {
  it("does not repeat known explanations in recovery, profile, membership or chat dialogs", () => {
    const messages = [
      "The recovery QR password is incorrect or the code is damaged",
      "The password is incorrect",
      "This person is already in the chat.",
      "chat group name already exists",
      "The profile is locked",
      "This device code has expired. Create a new one",
    ];
    for (const message of messages)
      for (const error of [
        message,
        new Error(message),
        { message },
        JSON.stringify({ message }),
      ]) {
        const result = presentError(error);
        expect(result.message).not.toBe(en["error.generic"]);
        expect(result.detail).toBeUndefined();
      }
  });
  it("keeps extra diagnostic data while removing its repeated message field", () => {
    const message = en["error.profileLocked"];
    expect(presentError({ message, requestId: "synthetic-request" })).toEqual({
      message,
      detail: JSON.stringify({ requestId: "synthetic-request" }, null, 2),
    });
    expect(
      distinctErrorDetail("The profile is locked.", "the profile is locked"),
    ).toBeUndefined();
    expect(
      distinctErrorDetail(message, JSON.stringify({ message })),
    ).toBeUndefined();
    expect(distinctErrorDetail(message, "SQLite diagnostic: busy")).toBe(
      "SQLite diagnostic: busy",
    );
    expect(distinctErrorDetail(message, '{"message":broken')).toBe(
      '{"message":broken',
    );
  });
  it("shows notification setup guidance once for native string and JSON errors", () => {
    for (const message of [
      "Could not register notifications. Try again.",
      "Could not register notifications",
    ]) {
      for (const error of [
        message,
        new Error(message),
        { message },
        JSON.stringify({ message }),
      ])
        expect(presentError(error)).toEqual({
          message: en["notifications.error.registration"],
        });
    }
    expect(
      presentError({ message: "Allow notifications in system settings." }),
    ).toEqual({
      message: en["notifications.error.permission"],
    });
    const unknown = JSON.stringify({
      message: "Unrecognized native failure",
      code: 999,
    });
    expect(presentError(unknown).detail).toBe(unknown);
  });
  it("explains an own contact code directly without a technical details dialog", () => {
    for (const error of [
      "This is your own contact code.",
      new Error("This is your own contact code."),
    ])
      expect(presentError(error)).toEqual({
        message: en["contacts.error.ownCode"],
      });
  });
  it("explains an unavailable camera without a redundant technical payload", () => {
    const error = {
      message: "No camera available on this device (e.g., iOS Simulator)",
      code: "cameraUnavailable",
    };
    const result = presentError(error);
    expect(result.message).toBe(en["invite.cameraUnavailable"]);
    expect(result.detail).toBeUndefined();
  });

  it("shows camera permission guidance without technical details", () => {
    const message = "Camera permission denied or not yet requested";
    for (const error of [message, new Error(message), { message }]) {
      expect(presentError(error)).toEqual({
        message: en["invite.cameraDenied"],
      });
    }
  });

  it("maps Error messages and keeps unknown native errors inspectable", () => {
    expect(presentError(new Error("The profile is locked")).message).toBe(
      en["error.profileLocked"],
    );
    const unknown = {
      code: "newNativeFailure",
      message: "Native operation failed",
    };
    const result = presentError(unknown);
    expect(result.message).toBe(en["error.generic"]);
    expect(JSON.parse(result.detail!)).toEqual(unknown);
  });

  it("explains a transport timeout without displaying the technical payload", () => {
    expect(presentError("transport request failed: Timeout")).toEqual({
      message: en["error.serverTimeout"],
    });
  });
});

describe("recovery error presentation", () => {
  it("distinguishes wrong QR passwords, wrong identity and expired device codes", () => {
    expect(
      presentError(
        "The recovery QR password is incorrect or the code is damaged",
      ).message,
    ).toBe(en["recover.error.qrPassword"]);
    expect(
      presentError("The recovery words and identity ID do not match").message,
    ).toBe(en["recover.error.identity"]);
    expect(
      presentError("This device code has expired. Create a new one").message,
    ).toBe(en["recover.error.pairExpired"]);
  });
});
