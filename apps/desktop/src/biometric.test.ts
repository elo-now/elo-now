import { describe, expect, it, vi } from "vitest";
import {
  BiometryType,
  checkStatus,
  hasData,
} from "@choochmeque/tauri-plugin-biometry-api";
import { biometricName, readBiometricState } from "./biometric";

vi.mock("@choochmeque/tauri-plugin-biometry-api", async (original) => ({
  ...(await original<
    typeof import("@choochmeque/tauri-plugin-biometry-api")
  >()),
  checkStatus: vi.fn(),
  hasData: vi.fn(),
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
