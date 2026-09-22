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
} from "./biometric";
vi.mock("@tauri-apps/api/core", () => ({ invoke: vi.fn() }));
const first = { id: "profile", identity: "identity-one" };
const second = { id: "profile-second", identity: "identity-two" };
let selected = first;
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
  vi.stubGlobal("localStorage", {
    getItem: (key: string) => preferences.get(key) ?? null,
    setItem: (key: string, value: string) => preferences.set(key, value),
    removeItem: (key: string) => preferences.delete(key),
  });
  vi.mocked(invoke).mockImplementation(async () => ({
    saved_profiles: [{ ...selected, active: true }],
  }));
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

describe("profile-bound biometric unlock", () => {
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

  it("keeps passwords and enrollment offers separate when profiles switch", async () => {
    await enableBiometricUnlock("first password", undefined, first);
    markBiometricOfferHandled(first);
    selected = second;
    expect((await readBiometricState()).enabled).toBe(false);
    expect(shouldOfferBiometricUnlock(second)).toBe(true);
    await enableBiometricUnlock("second password", undefined, second);
    markBiometricOfferHandled(second);
    expect(await readBiometricCredential("Unlock", second)).toEqual({
      password: "second password",
    });
    selected = first;
    expect((await readBiometricState()).enabled).toBe(true);
    expect(await readBiometricCredential("Unlock", first)).toEqual({
      password: "first password",
    });
    expect(shouldOfferBiometricUnlock(first)).toBe(false);
    await disableBiometricUnlock();
    expect((await readBiometricState()).enabled).toBe(false);
    selected = second;
    expect((await readBiometricState()).enabled).toBe(true);
    expect(await readBiometricCredential("Unlock", second)).toEqual({
      password: "second password",
    });
  });

  it("separates a recovered local copy even when it has the same identity", async () => {
    await enableBiometricUnlock("original password", undefined, first);
    selected = { id: "profile-restored", identity: first.identity };
    expect((await readBiometricState()).enabled).toBe(false);
    await enableBiometricUnlock("recovery password", undefined, selected);
    expect(await readBiometricCredential("Unlock", selected)).toEqual({
      password: "recovery password",
    });
    selected = first;
    expect(await readBiometricCredential("Unlock", first)).toEqual({
      password: "original password",
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
  });

  it("rejects unbound or mismatched data even when the native key lookup succeeds", async () => {
    await enableBiometricUnlock("first password", undefined, first);
    const name = vi.mocked(setData).mock.lastCall![0].name;
    for (const value of [
      "raw password",
      "elo-biometry:v1:{}",
      "elo-biometry:v2:null",
      "elo-biometry:v2:" +
        JSON.stringify({ version: 2, ...second, password: "other password" }),
    ]) {
      keychain.set(name, value);
      await expect(readBiometricCredential("Unlock", first)).rejects.toThrow(
        "dataNeedsReenrollment",
      );
    }
  });
});
