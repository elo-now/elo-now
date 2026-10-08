import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  BiometryType,
  checkStatus,
  hasData,
  getData,
  setData,
  removeData,
} from "@choochmeque/tauri-plugin-biometry-api";
import { invoke } from "@tauri-apps/api/core";
import capability from "../src-tauri/capabilities/main.json";
import {
  biometricName,
  readBiometricState,
  readBiometricCredential,
  enableBiometricUnlock,
  disableBiometricUnlock,
  clearLegacyBiometricUnlock,
  shouldOfferBiometricUnlock,
  markBiometricOfferHandled,
  changeProfilePassword,
} from "./biometric";
vi.mock("@tauri-apps/api/core", () => ({ invoke: vi.fn() }));
const first = { id: "profile", identity: "identity-one" };
const second = { id: "profile-second", identity: "identity-two" };
let selected = first;
let mobile = true;
const keychain = new Map<string, string>();
const preferences = new Map<string, string>();

// Enforce the pinned native plugin's exact domain/name scope against the
// shipped capability, so permissive storage mocks cannot hide ACL failures.
function requireStoragePermission(
  command: string,
  entry: { domain: string; name: string },
): void {
  type Scope = { domain: string; name?: string };
  const permissions = capability.permissions.filter(
    (permission) =>
      typeof permission !== "string" &&
      permission.identifier === `biometry:allow-${command}`,
  ) as { allow?: Scope[]; deny?: Scope[] }[];
  const matches = (scope: Scope) =>
    scope.domain === entry.domain &&
    (scope.name === undefined || scope.name === entry.name);
  if (
    permissions.some((permission) => permission.deny?.some(matches)) ||
    !permissions.some((permission) => permission.allow?.some(matches))
  )
    throw new Error("scopeDenied");
}

beforeEach(() => {
  vi.clearAllMocks();
  keychain.clear();
  preferences.clear();
  selected = first;
  mobile = true;
  vi.stubGlobal("localStorage", {
    getItem: (key: string) => preferences.get(key) ?? null,
    setItem: (key: string, value: string) => preferences.set(key, value),
    removeItem: (key: string) => preferences.delete(key),
  });
  vi.mocked(invoke).mockImplementation(async (command, args) => {
    if (command === "profile_task") {
      const request = (args as { request: { op: string; id: string } }).request;
      return request.op === "biometric_enroll"
        ? { key: `AGE-SECRET-KEY-1${request.id}` }
        : {};
    }
    return { mobile, saved_profiles: [{ ...selected, active: true }] };
  });
  vi.mocked(checkStatus).mockResolvedValue({
    isAvailable: true,
    biometryType: 2,
  });
  vi.mocked(hasData).mockImplementation(async (entry) => {
    requireStoragePermission("has-data", entry);
    return keychain.has(entry.name);
  });
  vi.mocked(setData).mockImplementation(async (entry) => {
    requireStoragePermission("set-data", entry);
    keychain.set(entry.name, entry.data);
  });
  vi.mocked(getData).mockImplementation(async (entry) => {
    requireStoragePermission("get-data", entry);
    return {
      domain: entry.domain,
      name: entry.name,
      data: keychain.get(entry.name)!,
    };
  });
  vi.mocked(removeData).mockImplementation(async (entry) => {
    requireStoragePermission("remove-data", entry);
    keychain.delete(entry.name);
  });
});
afterEach(() => vi.unstubAllGlobals());

vi.mock("@choochmeque/tauri-plugin-biometry-api", async (original) => ({
  ...(await original<
    typeof import("@choochmeque/tauri-plugin-biometry-api")
  >()),
  checkStatus: vi.fn(),
  hasData: vi.fn(),
  getData: vi.fn(),
  setData: vi.fn(),
  removeData: vi.fn(),
}));

describe("mobile biometric bridge", () => {
  it("does not offer an OS key whose local envelope was invalidated", async () => {
    keychain.set(`vault-key-v3:${first.identity}:${first.id}`, "stale key");
    vi.mocked(invoke).mockResolvedValue({
      mobile,
      saved_profiles: [{ ...first, active: true, biometric_enrolled: false }],
    });
    expect((await readBiometricState(first.identity)).enabled).toBe(false);
    expect(hasData).not.toHaveBeenCalled();
  });
  it.each([
    [1, "Touch ID", BiometryType.TouchID],
    [2, "Face ID", BiometryType.FaceID],
    [3, "Iris recognition", BiometryType.Iris],
  ])(
    "interprets native modality %s without using the mismatched JS enum",
    async (raw, name, expected) => {
      vi.mocked(checkStatus).mockResolvedValue({
        isAvailable: true,
        biometryType: raw,
      });
      vi.mocked(hasData).mockResolvedValue(true);
      const state = await readBiometricState();
      expect(state.type).toBe(expected);
      expect(biometricName(state.type)).toBe(name);
      expect(state.enabled).toBe(true);
    },
  );

  it("uses Android names rather than Apple biometric brands", () => {
    expect(biometricName(BiometryType.TouchID, "Android")).toBe("Fingerprint");
    expect(biometricName(BiometryType.FaceID, "Android")).toBe("Face unlock");
  });

  it("does not offer unavailable biometrics or read saved credentials", async () => {
    vi.mocked(checkStatus).mockResolvedValue({
      isAvailable: false,
      biometryType: 0,
    });
    vi.mocked(hasData).mockClear();
    expect(await readBiometricState()).toMatchObject({
      available: false,
      enabled: false,
      type: BiometryType.None,
    });
    expect(hasData).not.toHaveBeenCalled();
  });
});

describe("password changes and biometric enrollment", () => {
  const entry = `vault-key-v3:${first.identity}:${first.id}`;
  const oldPassword = "old synthetic profile password";
  const newPassword = "new synthetic profile password";
  function passwordReply(reply: () => unknown) {
    const previous = vi.mocked(invoke).getMockImplementation()!;
    vi.mocked(invoke).mockImplementation(async (command, args) => {
      if (
        command === "profile_task" &&
        (args as { request: { op: string } }).request.op === "change_password"
      )
        return reply();
      return previous(command, args);
    });
  }
  it("changes a password without enabling biometrics that were off", async () => {
    passwordReply(() => ({ biometric_refresh_required: false }));
    await expect(
      changeProfilePassword(oldPassword, newPassword, first.identity),
    ).resolves.toEqual({ biometricNeedsSetup: false });
    expect(invoke).toHaveBeenCalledWith("profile_task", {
      request: {
        op: "change_password",
        ...first,
        current_password: oldPassword,
        new_password: newPassword,
      },
    });
    expect(setData).not.toHaveBeenCalled();
    expect(getData).not.toHaveBeenCalled();
  });
  it("renews an existing enrollment with the new password after commit", async () => {
    keychain.set(entry, "old encrypted enrollment");
    passwordReply(() => ({ biometric_refresh_required: true }));
    const previous = vi.mocked(invoke).getMockImplementation()!;
    vi.mocked(invoke).mockImplementation(async (command, args) => {
      if (
        command === "profile_task" &&
        (args as { request: { op: string } }).request.op === "biometric_enroll"
      )
        expect(keychain.has(entry)).toBe(false);
      return previous(command, args);
    });
    await expect(
      changeProfilePassword(oldPassword, newPassword, first.identity),
    ).resolves.toEqual({ biometricNeedsSetup: false });
    expect(invoke).toHaveBeenCalledWith("profile_task", {
      request: {
        op: "biometric_enroll",
        ...first,
        password: newPassword,
      },
    });
    expect(keychain.get(entry)).toContain("elo-biometry:v3:");
    expect(getData).not.toHaveBeenCalled();
  });
  it("does not create a new envelope if the previous OS key cannot be removed", async () => {
    keychain.set(entry, "old encrypted enrollment");
    passwordReply(() => ({ biometric_refresh_required: true }));
    vi.mocked(removeData).mockRejectedValue(new Error("keychainUnavailable"));
    await expect(
      changeProfilePassword(oldPassword, newPassword, first.identity),
    ).resolves.toEqual({ biometricNeedsSetup: true });
    expect(invoke).not.toHaveBeenCalledWith("profile_task", {
      request: {
        op: "biometric_enroll",
        ...first,
        password: newPassword,
      },
    });
    expect(setData).not.toHaveBeenCalled();
  });
  it("leaves biometric storage unchanged when the current password is rejected", async () => {
    keychain.set(entry, "keep this enrollment");
    passwordReply(() => {
      throw new Error("password_change_incorrect");
    });
    await expect(
      changeProfilePassword(oldPassword, newPassword, first.identity),
    ).rejects.toThrow("password_change_incorrect");
    expect(keychain.get(entry)).toBe("keep this enrollment");
    expect(setData).not.toHaveBeenCalled();
    expect(removeData).not.toHaveBeenCalled();
  });
  it("reports a committed change separately from failed OS enrollment", async () => {
    keychain.set(entry, "old encrypted enrollment");
    passwordReply(() => ({ biometric_refresh_required: true }));
    vi.mocked(setData).mockRejectedValue(new Error("keychainUnavailable"));
    await expect(
      changeProfilePassword(oldPassword, newPassword, first.identity),
    ).resolves.toEqual({ biometricNeedsSetup: true });
    expect(keychain.has(entry)).toBe(false);
    const changes = vi
      .mocked(invoke)
      .mock.calls.filter(
        ([command, args]) =>
          command === "profile_task" &&
          (args as { request: { op: string } }).request.op ===
            "change_password",
      );
    expect(changes).toHaveLength(1);
    expect(invoke).toHaveBeenCalledWith("profile_task", {
      request: {
        op: "biometric_forget",
        ...first,
      },
    });
  });
  it("does not change a different selected identity", async () => {
    selected = second;
    passwordReply(() => ({ biometric_refresh_required: true }));
    await expect(
      changeProfilePassword(oldPassword, newPassword, first.identity),
    ).rejects.toThrow("dataNeedsReenrollment");
    expect(invoke).not.toHaveBeenCalledWith("profile_task", expect.anything());
  });
  it("does not enroll or remove another profile after a concurrent switch", async () => {
    keychain.set(entry, "old encrypted enrollment");
    const otherEntry = `vault-key-v3:${second.identity}:${second.id}`;
    keychain.set(otherEntry, "keep other enrollment");
    passwordReply(() => {
      selected = second;
      return { biometric_refresh_required: true };
    });
    await expect(
      changeProfilePassword(oldPassword, newPassword, first.identity),
    ).resolves.toEqual({ biometricNeedsSetup: true });
    expect(setData).not.toHaveBeenCalled();
    expect(keychain.get(otherEntry)).toBe("keep other enrollment");
    expect(keychain.has(entry)).toBe(false);
  });
});

describe("macOS biometric bridge", () => {
  beforeEach(() => {
    mobile = false;
  });

  it("keeps native Touch ID distinct from the mobile Face ID enum", async () => {
    vi.mocked(checkStatus).mockResolvedValue({
      isAvailable: true,
      biometryType: BiometryType.TouchID,
    });
    await enableBiometricUnlock("profile password", undefined, first);
    const state = await readBiometricState();
    expect(state).toMatchObject({
      available: true,
      enabled: true,
      type: BiometryType.TouchID,
    });
    expect(biometricName(state.type)).toBe("Touch ID");
    expect(await readBiometricCredential("Unlock", first)).toEqual({
      key: "AGE-SECRET-KEY-1profile",
    });
    expect(vi.mocked(getData).mock.lastCall?.[0]).toMatchObject({
      reason: "Unlock",
      cancelTitle: "Cancel",
    });
  });

  it("does not offer enrollment when the app signature cannot access the protected keychain", async () => {
    vi.mocked(hasData).mockRejectedValue(
      "[keychainUnavailable] - This app signature cannot access the protected keychain",
    );
    expect(await readBiometricState()).toMatchObject({
      available: false,
      enabled: false,
      error: "keychainUnavailable",
    });
    expect(getData).not.toHaveBeenCalled();
    expect(setData).not.toHaveBeenCalled();
  });

  it("does not offer enrollment when native status detects an ad hoc app signature", async () => {
    vi.mocked(checkStatus).mockResolvedValue({
      isAvailable: false,
      biometryType: BiometryType.TouchID,
      error: "keychainUnavailable",
    });
    expect(await readBiometricState()).toMatchObject({
      available: false,
      enabled: false,
      error: "keychainUnavailable",
    });
    expect(hasData).not.toHaveBeenCalled();
  });

  it("preserves other keychain failures instead of treating them as missing enrollment", async () => {
    vi.mocked(hasData).mockRejectedValue(new Error("keychainError"));
    await expect(readBiometricState()).rejects.toThrow("keychainError");
  });

  it("removes the local wrapper if the protected keychain rejects enrollment", async () => {
    vi.mocked(setData).mockRejectedValue(new Error("keychainUnavailable"));
    await expect(
      enableBiometricUnlock("profile password", undefined, first),
    ).rejects.toThrow("keychainUnavailable");
    expect(invoke).toHaveBeenLastCalledWith("profile_task", {
      request: { op: "biometric_forget", ...first },
    });
    expect((await readBiometricState()).enabled).toBe(false);
  });
});

describe("profile-bound biometric unlock", () => {
  it("awaits the guarded presentation acknowledgement and ends it before returning a key", async () => {
    await enableBiometricUnlock("first password", undefined, first);
    const originalInvoke = vi.mocked(invoke).getMockImplementation()!;
    const events: string[] = [];
    let acknowledge!: () => void;
    const acknowledgement = new Promise<void>((resolve) => {
      acknowledge = resolve;
    });
    vi.mocked(invoke).mockImplementation(async (command, args) => {
      const op = (args as { request?: { op?: string } } | undefined)?.request
        ?.op;
      if (op === "biometric_prompt_begin") {
        events.push("begin");
        await acknowledgement;
      } else if (op === "biometric_prompt_end") {
        events.push("end");
      }
      return originalInvoke(command, args);
    });
    const originalGetData = vi.mocked(getData).getMockImplementation()!;
    vi.mocked(getData).mockImplementation(async (options) => {
      events.push("get_data");
      return originalGetData(options);
    });

    const pending = readBiometricCredential("Unlock", first);
    await vi.waitFor(() => expect(events).toEqual(["begin"]));
    expect(getData).not.toHaveBeenCalled();
    acknowledge();
    expect(await pending).toEqual({ key: "AGE-SECRET-KEY-1profile" });
    expect(events).toEqual(["begin", "get_data", "end"]);
    expect(getData).toHaveBeenCalledTimes(1);
    expect(invoke).toHaveBeenCalledWith("profile_task", {
      request: { op: "biometric_prompt_begin", ...first },
    });
    expect(invoke).toHaveBeenCalledWith("profile_task", {
      request: { op: "biometric_prompt_end" },
    });
    expect(invoke).not.toHaveBeenCalledWith("profile_task", {
      request: { op: "biometric_prompt_reset" },
    });
  });

  it.each(["userCancel", "authenticationFailed"])(
    "resets the presentation exception after Keychain error %s",
    async (failure) => {
      vi.mocked(getData).mockRejectedValueOnce(new Error(failure));
      await expect(readBiometricCredential("Unlock", first)).rejects.toThrow(
        failure,
      );
      expect(getData).toHaveBeenCalledTimes(1);
      expect(invoke).toHaveBeenLastCalledWith("profile_task", {
        request: { op: "biometric_prompt_reset" },
      });
      expect(invoke).not.toHaveBeenCalledWith("profile_task", {
        request: { op: "biometric_prompt_end" },
      });
    },
  );

  it("keeps authentication and key validation when presentation calls fail", async () => {
    await enableBiometricUnlock("first password", undefined, first);
    const originalInvoke = vi.mocked(invoke).getMockImplementation()!;
    vi.mocked(invoke).mockImplementation(async (command, args) => {
      const op = (args as { request?: { op?: string } } | undefined)?.request
        ?.op;
      if (
        op === "biometric_prompt_begin" ||
        op === "biometric_prompt_end" ||
        op === "biometric_prompt_reset"
      )
        throw new Error("Native privacy operation failed.");
      return originalInvoke(command, args);
    });
    expect(await readBiometricCredential("Unlock", first)).toEqual({
      key: "AGE-SECRET-KEY-1profile",
    });
    expect(getData).toHaveBeenCalledTimes(1);
    expect(invoke).not.toHaveBeenCalledWith("profile_task", {
      request: { op: "biometric_prompt_reset" },
    });
    const name = vi.mocked(setData).mock.lastCall![0].name;
    keychain.set(name, "unbound credential");
    await expect(readBiometricCredential("Unlock", first)).rejects.toThrow(
      "dataNeedsReenrollment",
    );
    expect(invoke).toHaveBeenLastCalledWith("profile_task", {
      request: { op: "biometric_prompt_reset" },
    });
  });

  it("resets the exception when the post-authentication profile check fails", async () => {
    await enableBiometricUnlock("first password", undefined, first);
    const originalInvoke = vi.mocked(invoke).getMockImplementation()!;
    let profileChecks = 0;
    vi.mocked(invoke).mockImplementation(async (command, args) => {
      if (command === "profile_environment" && ++profileChecks === 2)
        throw new Error("Local profile check failed");
      return originalInvoke(command, args);
    });
    await expect(readBiometricCredential("Unlock", first)).rejects.toThrow(
      "Local profile check failed",
    );
    expect(getData).toHaveBeenCalledTimes(1);
    expect(invoke).toHaveBeenCalledWith("profile_task", {
      request: { op: "biometric_prompt_end" },
    });
    expect(invoke).toHaveBeenLastCalledWith("profile_task", {
      request: { op: "biometric_prompt_reset" },
    });
  });

  it("keeps biometric storage access confined to the app profile domain", async () => {
    const entry = { domain: "other.application", name: "vault-password-v1" };
    await expect(hasData(entry)).rejects.toThrow("scopeDenied");
    await expect(getData({ ...entry, reason: "Unlock" })).rejects.toThrow(
      "scopeDenied",
    );
    await expect(
      setData({ ...entry, data: "unrelated credential" }),
    ).rejects.toThrow("scopeDenied");
    await expect(removeData(entry)).rejects.toThrow("scopeDenied");
  });

  it("keeps wrapping keys and enrollment offers separate when profiles switch", async () => {
    await enableBiometricUnlock("first password", undefined, first);
    expect([...keychain.values()].join()).not.toContain("first password");
    markBiometricOfferHandled(first);
    selected = second;
    expect((await readBiometricState()).enabled).toBe(false);
    expect(shouldOfferBiometricUnlock(second)).toBe(true);
    await enableBiometricUnlock("second password", undefined, second);
    markBiometricOfferHandled(second);
    expect(await readBiometricCredential("Unlock", second)).toEqual({
      key: "AGE-SECRET-KEY-1profile-second",
    });
    selected = first;
    expect((await readBiometricState()).enabled).toBe(true);
    expect(await readBiometricCredential("Unlock", first)).toEqual({
      key: "AGE-SECRET-KEY-1profile",
    });
    expect(shouldOfferBiometricUnlock(first)).toBe(false);
    await disableBiometricUnlock();
    expect((await readBiometricState()).enabled).toBe(false);
    selected = second;
    expect((await readBiometricState()).enabled).toBe(true);
    expect(await readBiometricCredential("Unlock", second)).toEqual({
      key: "AGE-SECRET-KEY-1profile-second",
    });
  });

  it("separates a recovered local copy even when it has the same identity", async () => {
    await enableBiometricUnlock("original password", undefined, first);
    selected = { id: "profile-restored", identity: first.identity };
    expect((await readBiometricState()).enabled).toBe(false);
    await enableBiometricUnlock("recovery password", undefined, selected);
    expect(await readBiometricCredential("Unlock", selected)).toEqual({
      key: "AGE-SECRET-KEY-1profile-restored",
    });
    selected = first;
    expect(await readBiometricCredential("Unlock", first)).toEqual({
      key: "AGE-SECRET-KEY-1profile",
    });
  });

  it("does not read or reuse the old unbound password for a new profile", async () => {
    keychain.set("vault-password-v1", "old password");
    preferences.set("elo.biometricOffer.v1", "handled");
    expect((await readBiometricState()).enabled).toBe(false);
    expect(shouldOfferBiometricUnlock(first)).toBe(true);
    expect(getData).not.toHaveBeenCalled();
    await enableBiometricUnlock("current password", undefined, first);
    await clearLegacyBiometricUnlock();
    expect(keychain.has("vault-password-v1")).toBe(false);
    expect((await readBiometricState()).enabled).toBe(true);
  });

  it("rejects a different profile before authentication and a switch during Face ID", async () => {
    await enableBiometricUnlock("first password", undefined, first);
    selected = second;
    await expect(readBiometricCredential("Unlock", first)).rejects.toThrow(
      "dataNeedsReenrollment",
    );
    await expect(
      enableBiometricUnlock("wrong password", undefined, first),
    ).rejects.toThrow("dataNeedsReenrollment");
    expect(getData).not.toHaveBeenCalled();
    selected = first;
    vi.mocked(getData).mockImplementationOnce(async ({ domain, name }) => {
      selected = second;
      return { domain, name, data: keychain.get(name)! };
    });
    await expect(readBiometricCredential("Unlock", first)).rejects.toThrow(
      "dataNeedsReenrollment",
    );
    expect(invoke).toHaveBeenCalledWith("profile_task", {
      request: { op: "biometric_prompt_end" },
    });
    expect(invoke).toHaveBeenLastCalledWith("profile_task", {
      request: { op: "biometric_prompt_reset" },
    });
  });

  it("rejects unbound or mismatched data even when the native key lookup succeeds", async () => {
    await enableBiometricUnlock("first password", undefined, first);
    const name = vi.mocked(setData).mock.lastCall![0].name;
    for (const value of [
      "raw password",
      "elo-biometry:v1:{}",
      "elo-biometry:v2:null",
      "elo-biometry:v3:null",
      "elo-biometry:v3:{",
      "elo-biometry:v3:" +
        JSON.stringify({ version: 3, ...second, key: "AGE-SECRET-KEY-1wrong" }),
      "elo-biometry:v3:" +
        JSON.stringify({ version: 3, ...first, key: "wrong key format" }),
      "elo-biometry:v2:" +
        JSON.stringify({ version: 2, ...second, password: "other password" }),
    ]) {
      keychain.set(name, value);
      await expect(readBiometricCredential("Unlock", first)).rejects.toThrow(
        "dataNeedsReenrollment",
      );
      expect(invoke).toHaveBeenLastCalledWith("profile_task", {
        request: { op: "biometric_prompt_reset" },
      });
    }
  });
});
