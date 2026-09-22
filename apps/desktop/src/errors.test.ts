import { describe, expect, it } from "vitest";
import { distinctErrorDetail, presentError } from "./errors";
import { en } from "./locales/en";

describe("native error presentation", () => {
  it("explains a full Space without exposing the HTTP error or duplicate details", () => {
    for (const message of [
      "mailbox quota exceeded",
      "transport request failed: Http(507)",
    ])
      expect(presentError({ message })).toEqual({
        message: en["error.replicaFull"],
      });
  });
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
  it("never exposes raw payloads or diagnostic identifiers", () => {
    const message = en["error.profileLocked"];
    expect(
      presentError({
        message,
        requestId: "synthetic-request",
        token: "not-for-display",
      }),
    ).toEqual({ message });
    for (const detail of [
      "SQLite diagnostic: busy",
      '{"message":broken',
      JSON.stringify({ message }),
      JSON.stringify({ code: 503 }),
    ])
      expect(distinctErrorDetail(message, detail)).toBeUndefined();
  });
  it("shows notification setup guidance once for native string and JSON errors", () => {
    for (const message of [
      "Could not register notifications. Try again.",
      "Could not register notifications",
      "Could not refresh notifications",
    ]) {
      for (const error of [
        message,
        new Error(message),
        { message },
        JSON.stringify({ message }),
        JSON.stringify(message),
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
    expect(presentError(unknown)).toEqual({ message: en["error.generic"] });
  });
  it("presents notification maintenance errors once, including serialized strings", () => {
    for (const [message, key] of [
      [
        "Could not update notifications. Try again.",
        "notifications.error.update",
      ],
      [
        "Could not share notification availability",
        "notifications.error.update",
      ],
      ["Could not read notification preferences", "notifications.error.update"],
      [
        "Could not connect to notifications. Try again.",
        "notifications.error.connection",
      ],
    ] as const) {
      for (const error of [
        message,
        new Error(message),
        { message },
        JSON.stringify({ message }),
        JSON.stringify(message),
      ])
        expect(presentError(error)).toEqual({ message: en[key] });
    }
    expect(
      distinctErrorDetail(
        "Couldn’t confirm this action.",
        "Couldn't confirm this action",
      ),
    ).toBeUndefined();
    expect(presentError(JSON.stringify(en["error.generic"]))).toEqual({
      message: en["error.generic"],
    });
    const generic = en["error.generic"];
    for (const detail of [
      { error: generic },
      { error: { message: generic } },
      { message: generic, detail: generic },
    ])
      expect(
        distinctErrorDetail(generic, JSON.stringify(detail)),
      ).toBeUndefined();
    expect(
      distinctErrorDetail(
        generic,
        JSON.stringify({
          error: { message: generic, code: 503 },
          requestId: "test-request",
        }),
      ),
    ).toBeUndefined();
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

  it("maps Error messages and hides unknown native payloads", () => {
    expect(presentError(new Error("The profile is locked")).message).toBe(
      en["error.profileLocked"],
    );
    const unknown = {
      code: "newNativeFailure",
      message: "Native operation failed",
    };
    const result = presentError(unknown);
    expect(result.message).toBe(en["error.generic"]);
    expect(result.detail).toBeUndefined();
  });

  it("unwraps nested, encoded and repeated errors without leaking JSON", () => {
    const message = "Could not register notifications. Try again.";
    for (const error of [
      { error: { cause: { message } } },
      JSON.stringify({ error: JSON.stringify({ message }) }),
      { message: en["error.generic"], cause: { message } },
      { error: [message, message] },
    ])
      expect(presentError(error)).toEqual({
        message: en["notifications.error.registration"],
      });
    const cyclic: { error?: unknown } = {};
    cyclic.error = cyclic;
    expect(presentError(cyclic)).toEqual({ message: en["error.generic"] });
    expect(
      presentError({
        message: "Enter a valid contact email address.",
        debug: { email: "private@example.test" },
      }),
    ).toEqual({ message: en["spaces.contactInvalid"] });
    expect(
      presentError("passphrase must contain 12..=1024 UTF-8 bytes", 4),
    ).toEqual({ message: en["error.passwordShort"] });
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
