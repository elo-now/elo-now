import { t } from "./i18n";
import { invoke } from "@tauri-apps/api/core";
import {
  BiometryType,
  checkStatus,
  getData,
  hasData,
  removeData,
  setData,
  type Status,
} from "@choochmeque/tauri-plugin-biometry-api";

const legacySecret = {
  domain: "now.elo.profile",
  name: "vault-password-v1",
} as const;
const credentialPrefix = "elo-biometry:v2:";
const offerKey = "elo.biometricOffer.v2:";

export type BiometricProfile = { id: string; identity: string };

const profileKey = (profile: BiometricProfile) =>
  `${profile.identity}:${profile.id}`;
const secret = (profile: BiometricProfile) => ({
  domain: "now.elo.profile",
  name: `vault-password-v2:${profileKey(profile)}`,
});
async function activeProfile(
  expectedIdentity?: string,
): Promise<BiometricProfile | undefined> {
  const environment = await invoke<{
    saved_profiles: (BiometricProfile & { active: boolean })[];
  }>("profile_environment");
  const profile = environment.saved_profiles.find((entry) => entry.active);
  if (expectedIdentity && profile?.identity !== expectedIdentity)
    throw new Error("dataNeedsReenrollment");
  return profile && { id: profile.id, identity: profile.identity };
}
async function requireActiveProfile(profile: BiometricProfile): Promise<void> {
  const current = await activeProfile(profile.identity);
  if (!current || profileKey(current) !== profileKey(profile))
    throw new Error("dataNeedsReenrollment");
}

/** The old global entry has no profile binding and must never unlock another profile. */
export async function clearLegacyBiometricUnlock(): Promise<void> {
  await removeData(legacySecret);
  localStorage.removeItem("elo.biometricOffer.v1");
}

export type BiometricState = {
  available: boolean;
  enabled: boolean;
  type: BiometryType;
  error?: string;
  profile?: BiometricProfile;
};

export type BiometricCredential = {
  password: string;
  demoProfile?: string;
};

export async function readBiometricState(
  expectedIdentity?: string,
): Promise<BiometricState> {
  const status: Status = await checkStatus();
  const profile = await activeProfile(expectedIdentity);
  return {
    available: status.isAvailable,
    enabled:
      status.isAvailable && profile ? await hasData(secret(profile)) : false,
    profile,
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
  demoProfile: string | undefined,
  profile: BiometricProfile,
): Promise<void> {
  await requireActiveProfile(profile);
  await setData({
    ...secret(profile),
    data:
      credentialPrefix +
      JSON.stringify({ version: 2, ...profile, password, demoProfile }),
  });
}

export async function disableBiometricUnlock(
  profile?: BiometricProfile,
): Promise<void> {
  const target = profile ?? (await activeProfile());
  if (!target) return;
  await removeData(secret(target));
  localStorage.removeItem(offerKey + profileKey(target));
}

export async function readBiometricCredential(
  reason: string,
  profile: BiometricProfile,
): Promise<BiometricCredential> {
  await requireActiveProfile(profile);
  const data = (
    await getData({
      ...secret(profile),
      reason,
      cancelTitle: t("dialog.cancel"),
    })
  ).data;
  await requireActiveProfile(profile);
  try {
    if (data.startsWith(credentialPrefix)) {
      const decoded = JSON.parse(data.slice(credentialPrefix.length));
      if (
        decoded?.version === 2 &&
        decoded.id === profile.id &&
        decoded.identity === profile.identity &&
        typeof decoded.password === "string" &&
        (decoded.demoProfile === undefined ||
          typeof decoded.demoProfile === "string")
      )
        return { password: decoded.password, demoProfile: decoded.demoProfile };
    }
  } catch {
    /* Invalid or unbound entries require explicit reenrollment. */
  }
  throw new Error("dataNeedsReenrollment");
}

export function shouldOfferBiometricUnlock(profile: BiometricProfile): boolean {
  return localStorage.getItem(offerKey + profileKey(profile)) !== "handled";
}

export function markBiometricOfferHandled(profile: BiometricProfile): void {
  localStorage.setItem(offerKey + profileKey(profile), "handled");
}

export function biometricCancelled(error: unknown): boolean {
  const value = String(error).toLocaleLowerCase();
  return ["usercancel", "user cancel", "systemcancel", "appcancel"].some(
    (code) => value.includes(code),
  );
}
