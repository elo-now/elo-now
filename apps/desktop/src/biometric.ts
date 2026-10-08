import { t } from "./i18n";
import { invoke } from "./diagnosticInvoke";
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
const credentialPrefix = "elo-biometry:v3:";
const offerKey = "elo.biometricOffer.v3:";

export type BiometricProfile = { id: string; identity: string };
type BiometricEnvironment = {
  mobile: boolean;
  saved_profiles: (BiometricProfile & {
    active: boolean;
    biometric_enrolled?: boolean;
  })[];
};

const profileKey = (profile: BiometricProfile) =>
  `${profile.identity}:${profile.id}`;
const secret = (profile: BiometricProfile) => ({
  domain: "now.elo.profile",
  name: `vault-key-v3:${profileKey(profile)}`,
});
async function activeProfile(
  expectedIdentity?: string,
): Promise<BiometricProfile | undefined> {
  return profileFromEnvironment(
    await invoke<BiometricEnvironment>("profile_environment"),
    expectedIdentity,
  );
}
function profileFromEnvironment(
  environment: BiometricEnvironment,
  expectedIdentity?: string,
): BiometricProfile | undefined {
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
  const environment = await invoke<{ saved_profiles: BiometricProfile[] }>(
    "profile_environment",
  );
  for (const profile of environment.saved_profiles) {
    await removeData({
      domain: "now.elo.profile",
      name: `vault-password-v2:${profileKey(profile)}`,
    });
  }
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
  key: string;
  demoProfile?: string;
};

export async function readBiometricState(
  expectedIdentity?: string,
): Promise<BiometricState> {
  const status: Status = await checkStatus();
  const environment = await invoke<BiometricEnvironment>("profile_environment");
  const profile = profileFromEnvironment(environment, expectedIdentity);
  let available = status.isAvailable;
  let enabled = false;
  let error = status.error;
  if (available && profile) {
    try {
      const saved = environment.saved_profiles.find(
        (entry) =>
          entry.id === profile.id && entry.identity === profile.identity,
      );
      // A password change invalidates the local envelope before replacing the
      // OS entry. A terminated app must not offer that stale biometric key.
      enabled =
        saved?.biometric_enrolled !== false && (await hasData(secret(profile)));
    } catch (reason) {
      if (environment.mobile || !String(reason).includes("keychainUnavailable"))
        throw reason;
      // Ad hoc builds can have Touch ID hardware but no entitlement to
      // the protected keychain. Do not offer an enrollment that cannot persist.
      available = false;
      error = "keychainUnavailable";
    }
  }
  return {
    available,
    enabled,
    profile,
    type: environment.mobile
      ? mobileBiometryType(status.biometryType)
      : status.biometryType,
    error,
  };
}

/** Pinned plugin 0.3.0-rc.3: Swift/Kotlin return 0/1/2/3 for
 * none/fingerprint/face/iris, unlike the package's newer JS/Rust enum.
 * macOS uses the JS/Rust enum directly and must not pass through this adapter. */
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
  const { key } = await invoke<{ key: string }>("profile_task", {
    request: { op: "biometric_enroll", ...profile, password },
  });
  try {
    await setData({
      ...secret(profile),
      data:
        credentialPrefix +
        JSON.stringify({ version: 3, ...profile, key, demoProfile }),
    });
    await removeData({
      domain: "now.elo.profile",
      name: `vault-password-v2:${profileKey(profile)}`,
    });
  } catch (error) {
    await invoke("profile_task", {
      request: { op: "biometric_forget", ...profile },
    });
    throw error;
  }
}

export async function disableBiometricUnlock(
  profile?: BiometricProfile,
): Promise<void> {
  const target = profile ?? (await activeProfile());
  if (!target) return;
  await invoke("profile_task", {
    request: { op: "biometric_forget", ...target },
  });
  await removeData(secret(target));
  localStorage.removeItem(offerKey + profileKey(target));
}

/** Commit the local password once, then renew an existing biometric enrollment.
 * An OS storage failure after commit must never be reported as a failed password
 * change: the new password is already authoritative at that point. */
export async function changeProfilePassword(
  currentPassword: string,
  newPassword: string,
  expectedIdentity: string,
): Promise<{ biometricNeedsSetup: boolean }> {
  const profile = await activeProfile(expectedIdentity);
  if (!profile) throw new Error("dataNeedsReenrollment");
  let wasEnabled = false;
  try {
    wasEnabled = (await readBiometricState(expectedIdentity)).enabled;
  } catch {
    // OS keychain availability does not prevent a password-authenticated change.
  }
  const result = await invoke<{ biometric_refresh_required: boolean }>(
    "profile_task",
    {
      request: {
        op: "change_password",
        ...profile,
        current_password: currentPassword,
        new_password: newPassword,
      },
    },
  );
  if (!result.biometric_refresh_required) return { biometricNeedsSetup: false };
  if (wasEnabled) {
    try {
      // A crash between native enrollment and saving its new OS key must
      // leave biometrics disabled, never pair a new envelope with an old key.
      await removeData(secret(profile));
      await enableBiometricUnlock(newPassword, undefined, profile);
      return { biometricNeedsSetup: false };
    } catch {
      // Enrollment removes its new envelope on failure. Remove only this
      // profile's old OS key, even if the user has since switched profiles.
    }
  }
  await removeData(secret(profile)).catch(() => {});
  await removeData({
    domain: "now.elo.profile",
    name: `vault-password-v2:${profileKey(profile)}`,
  }).catch(() => {});
  return { biometricNeedsSetup: true };
}

export async function readBiometricCredential(
  reason: string,
  profile: BiometricProfile,
): Promise<BiometricCredential> {
  await requireActiveProfile(profile);
  // Presentation is best-effort; it never replaces protected Keychain access.
  await invoke("profile_task", {
    request: { op: "biometric_prompt_begin", ...profile },
  }).catch(() => {});
  try {
    const data = (
      await getData({
        ...secret(profile),
        reason,
        cancelTitle: t("dialog.cancel"),
      })
    ).data;
    await invoke("profile_task", {
      request: { op: "biometric_prompt_end" },
    }).catch(() => {});
    await requireActiveProfile(profile);
    try {
      if (data.startsWith(credentialPrefix)) {
        const decoded = JSON.parse(data.slice(credentialPrefix.length));
        if (
          decoded?.version === 3 &&
          decoded.id === profile.id &&
          decoded.identity === profile.identity &&
          typeof decoded.key === "string" &&
          decoded.key.startsWith("AGE-SECRET-KEY-1") &&
          (decoded.demoProfile === undefined ||
            typeof decoded.demoProfile === "string")
        )
          return { key: decoded.key, demoProfile: decoded.demoProfile };
      }
    } catch {
      /* Invalid or unbound entries require explicit reenrollment. */
    }
    throw new Error("dataNeedsReenrollment");
  } catch (error) {
    // Failed authentication or binding checks cannot leave the presentation
    // exception active for a later profile operation.
    await invoke("profile_task", {
      request: { op: "biometric_prompt_reset" },
    }).catch(() => {});
    throw error;
  }
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
