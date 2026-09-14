import { t } from "./i18n";
import {
  BiometryType,
  checkStatus,
  getData,
  hasData,
  removeData,
  setData,
  type Status,
} from "@choochmeque/tauri-plugin-biometry-api";

const secret = {
  domain: "now.elo.profile",
  name: "vault-password-v1",
} as const;
const credentialPrefix = "elo-biometry:v1:";
const offerKey = "elo.biometricOffer.v1";

export type BiometricState = {
  available: boolean;
  enabled: boolean;
  type: BiometryType;
  error?: string;
};

export type BiometricCredential = {
  password: string;
  demoProfile?: string;
};

export async function readBiometricState(): Promise<BiometricState> {
  const status: Status = await checkStatus();
  return {
    available: status.isAvailable,
    enabled: status.isAvailable ? await hasData(secret) : false,
    type: mobileBiometryType(status.biometryType),
    error: status.error,
  };
}

/** Pinned plugin 0.3.0-rc.3: Swift/Kotlin return 0/1/2/3 for
 * none/fingerprint/face/iris, unlike the package's newer JS/Rust enum.
 * This adapter is used only by mobile callers; desktop has no plugin. */
export function mobileBiometryType(raw: number): BiometryType {
  switch (raw) {
    case 1:
      return BiometryType.TouchID;
    case 2:
      return BiometryType.FaceID;
    case 3:
      return BiometryType.Iris;
    default:
      return BiometryType.None;
  }
}

export function biometricName(
  type: BiometryType,
  userAgent = globalThis.navigator?.userAgent ?? "",
): string {
  if (/Android/i.test(userAgent)) {
    if (type === BiometryType.TouchID) return t("biometric.fingerprint");
    if (type === BiometryType.FaceID) return t("biometric.faceUnlock");
  }
  switch (type) {
    case BiometryType.FaceID:
      return "Face ID";
    case BiometryType.TouchID:
      return "Touch ID";
    case BiometryType.Iris:
      return "Iris recognition";
    default:
      return "Biometrics";
  }
}

export async function enableBiometricUnlock(
  password: string,
  demoProfile?: string,
): Promise<void> {
  await setData({
    ...secret,
    data:
      credentialPrefix + JSON.stringify({ version: 1, password, demoProfile }),
  });
}

export async function disableBiometricUnlock(): Promise<void> {
  await removeData(secret);
}

export async function readBiometricCredential(
  reason: string,
): Promise<BiometricCredential> {
  const data = (await getData({ ...secret, reason, cancelTitle: "Cancel" }))
    .data;
  if (data.startsWith(credentialPrefix)) {
    const decoded = JSON.parse(data.slice(credentialPrefix.length)) as {
      version?: unknown;
      password?: unknown;
      demoProfile?: unknown;
    };
    if (
      decoded.version === 1 &&
      typeof decoded.password === "string" &&
      (decoded.demoProfile === undefined ||
        typeof decoded.demoProfile === "string")
    ) {
      return {
        password: decoded.password,
        demoProfile: decoded.demoProfile,
      };
    }
  }
  // Entries written by the first biometric build contain the raw password.
  return { password: data };
}

export function shouldOfferBiometricUnlock(): boolean {
  return localStorage.getItem(offerKey) !== "handled";
}

export function markBiometricOfferHandled(): void {
  localStorage.setItem(offerKey, "handled");
}

export function biometricCancelled(error: unknown): boolean {
  const value = String(error).toLocaleLowerCase();
  return ["usercancel", "user cancel", "systemcancel", "appcancel"].some(
    (code) => value.includes(code),
  );
}
