import { errorText, t, type MessageKey } from "./i18n";
import { en } from "./locales/en";

const known: Record<string, MessageKey> = {
  "Could not register notifications. Try again.":
    "notifications.error.registration",
  "Could not register notifications": "notifications.error.registration",
  "Allow notifications in system settings.": "notifications.error.permission",
  "This is your own contact code.": "contacts.error.ownCode",
  "Add a sync server before changing members.": "members.error.server",
  "Add this person's contact code first.": "members.error.contact",
  "A chat can have up to 1000 people.": "members.error.full",
  "There are too many devices for this chat.": "members.error.devices",
  "This person is already in the chat.": "members.error.alreadyAdded",
  "Add a sync server before adding people.": "members.error.server",
  "This selection has changed. Start a new one.": "members.error.changed",
  "A selected person was removed. Start a new addition.":
    "members.error.changed",
  "The chat changed. Review its members before trying again.":
    "members.error.changed",
  "There are too many pending deliveries. Try again after syncing.":
    "members.error.pending",
  "This recovered chat requires a membership review.": "members.error.review",
  "invalid reply target": "thread.error.target",
  "reply target unavailable in this chat": "thread.error.target",
  "thread original unavailable in this chat": "thread.error.root",
  "invalid thread root": "thread.error.root",
  "The recovery QR password is incorrect or the code is damaged":
    "recover.error.qrPassword",
  "Enter all 24 recovery words": "recover.error.words",
  "Invalid recovery key": "recover.error.words",
  "The recovery words and identity ID do not match": "recover.error.identity",
  "Scan a recovery QR, not a contact or device code": "recover.error.qrType",
  "Invalid recovery QR": "recover.error.qrInvalid",
  "Invalid recovery QR or password": "recover.error.qrInvalid",
  "Use at least 12 characters for the recovery QR password":
    "recover.error.qrPasswordLength",
  "Use the password chosen when recovery started":
    "recover.error.resumePassword",
  "Select the same backup to continue recovery": "recover.error.resumeBackup",
  "Invalid recovery checkpoint signature": "recover.error.checkpoint",
  "Invalid recovery checkpoint": "recover.error.checkpoint",
  "Incomplete recovery checkpoint": "recover.error.checkpoint",
  "Recovery checkpoint does not match this backup": "recover.error.checkpoint",
  "Unsafe recovery directory": "recover.error.checkpoint",
  "Unsafe recovery file": "recover.error.checkpoint",
  "Unexpected file in recovery directory": "recover.error.checkpoint",
  "This directory is not a resumable recovery": "recover.error.checkpoint",
  "Invalid profile backup": "recover.error.backupInvalid",
  "Invalid or incomplete profile backup": "recover.error.backupInvalid",
  "Incomplete profile backup": "recover.error.backupInvalid",
  "The backup could not be unlocked with this recovery key":
    "recover.error.backupPassword",
  "This backup belongs to a different profile or is invalid":
    "recover.error.backupIdentity",
  "Invalid profile backup identity": "recover.error.backupIdentity",
  "Profile backup is too large": "recover.error.backupSize",
  "Profile settings and security data exceed the backup size limit.":
    "recover.error.backupRequiredDataSize",
  "Choose an image with one recovery or device code": "recover.error.qrImage",
  "No recovery code found": "recover.error.qrImage",
  "This device code has expired. Create a new one": "recover.error.pairExpired",
  "This device code has already been used": "recover.error.pairUsed",
  "This code has already been used for another device":
    "recover.error.pairUsed",
  "Compare and confirm the code on both devices": "recover.error.pairCode",
  "Invalid device code or name": "recover.error.pairType",
  "Invalid device code": "recover.error.pairType",
  "Scan a device-linking code, not a public contact code":
    "recover.error.pairType",
  "Add a Replica before linking another device": "recover.error.pairReplica",
  "Approve this device on your other device first":
    "recover.error.pairApproval",
  "The profile transfer is incomplete": "recover.error.pairIncomplete",
  "Confirm removal and enter your profile password":
    "recover.error.removeConfirm",
  "This profile contains additional files. Move them before removing it":
    "recover.error.removeFiles",
  "Only the selected app-managed profile can be removed here":
    "recover.error.removeManaged",
  "Remove an unused saved profile before adding another":
    "recover.error.profileLimit",
  "Saved profile not found": "recover.error.savedMissing",
  "Confirm the device and enter your profile password":
    "recover.error.pairPassword",
  "Choose a smaller PNG or JPEG image": "recover.imageTooLarge",
  "Choose a PNG or JPEG image": "recover.imageInvalid",
  "Invalid image": "recover.imageInvalid",
  "Missing profile input": "error.required",
  "invalid invitation duration": "invite.error.duration",
  "invalid profile name": "profile.nameInvalid",
  "invalid profile photo": "profile.photoInvalid",
  "invalid profile details": "error.profileData",
  "No camera available on this device (e.g., iOS Simulator)":
    "invite.cameraUnavailable",
  "Camera permission denied or not yet requested": "invite.cameraDenied",
  "There are too many saved invitations. Remove an old entry first.":
    "invite.error.tooMany",
  "unknown chat group": "error.groupMissing",
  "invalid chat group name": "error.groupName",
  "chat group name already exists": "error.groupDuplicate",
  "chat group limit": "error.groupLimit",
  "reserved chat group name": "error.groupReserved",
  "invalid vault, passphrase, key binding or recovery card":
    "error.profileOpen",
  "vault file unavailable, unsafe permissions, or output already exists":
    "error.profileFile",
  "The profile is locked": "error.profileLocked",
  "profile directory already exists": "error.profileExists",
  "Choose an absolute profile directory": "error.profilePath",
  "Lock the open profile first": "error.lockFirst",
  "Save your recovery words and identity ID first": "error.saveRecovery",
  "Prepare a recovery card first": "error.prepareRecovery",
  "Profile initialization was interrupted; keep this directory for diagnosis and choose a new profile directory":
    "error.interruptedProfile",
  "invalid workspace": "error.profileData",
  "client directory is already open by another worker/process":
    "error.profileBusy",
  "database is not an unmodified elo.now client schema; refusing to adopt it":
    "error.profileData",
  "required SQLite configuration could not be verified":
    "error.storageSettings",
  "stored object does not match its content identifier": "error.damagedData",
  "stored record/source mismatch": "error.damagedData",
  "store is closed; operation was not enqueued": "error.profileLocked",
  "worker response lost; outcome is unknown; retry the exact same input":
    "error.unknownOutcome",
  "delivery attempt is stale or no longer INFLIGHT": "error.syncChanged",
  "mailbox authorization denied": "error.replicaAccess",
  "mailbox quota exceeded": "error.replicaFull",
  "object unavailable": "error.fileUnavailable",
  "storage unavailable": "error.storageUnavailable",
  "invalid peer endpoint or bounded response": "error.replicaConnection",
  "network request failed": "error.network",
  "transport request failed: Timeout": "error.serverTimeout",
  "invalid object, request or receipt": "error.verification",
  "delivery conflicts with existing immutable data": "error.conflictingData",
  "replica directory is already open or belongs to a client":
    "error.profileBusy",
  "peer mailbox already configured": "error.replicaExists",
  "invalid object size or recipient set": "error.contentRecipients",
  "age encryption failed": "error.encryption",
  "age decryption or final authentication failed": "error.decryption",
  "recipient credentials do not match the signed record": "error.verification",
  "invalid ELO1 framing or size": "error.invalidData",
  "invalid strict JSON or record schema": "error.invalidData",
  "unsupported record version or kind": "error.unsupportedData",
  "invalid record signature or signing key": "error.verification",
  "record does not match trusted authority context": "error.verification",
  "record is not authorized in the supplied context": "error.notAllowed",
  "randomness unavailable": "error.randomness",
  "root recovery needs the expected public identity fingerprint":
    "error.confirmIdentity",
  "confirm the Space and root fingerprint out of band": "error.confirmSpace",
  "Space controller transition incomplete or conflicting":
    "error.channelConflict",
  "controller unavailable, retired, restored follower, or forked":
    "error.channelControl",
  "no active personal chat controller": "error.newChatControl",
  "new chat after controller recovery is not supported":
    "error.newChatRecovery",
  "device requires explicit membership approval": "error.membershipApproval",
  "invitation scope mismatch": "error.invitationMismatch",
  "recipient is not a current member": "error.notMember",
  "member not found": "error.notMember",
  "history request changed after preview": "error.historyChanged",
  "explicit history selection required": "error.historySelection",
  "selected original unavailable": "error.historyUnavailable",
  "stored source unavailable": "error.historyUnavailable",
  "file metadata unavailable": "error.fileUnavailable",
  "unavailable: no reachable replica supplied the file in the bounded inventory":
    "error.fileUnavailable",
  "File picker closed unexpectedly": "error.pickerClosed",
  "Exchange files must not exceed 12 MiB": "error.exchangeSize",
  "exchange file too large": "error.exchangeSize",
  "exchange file is unsafe or too large": "error.exchangeFile",
  "Unsafe exchange directory": "error.exchangeFolder",
  "This operation does not export a file": "error.invalidExport",
  "Only an app-created exchange file may be exported": "error.invalidExport",
  "Invalid export file": "error.invalidExport",
  "Invalid export name": "error.invalidExport",
  "invalid channel name": "error.channelName",
  "invalid chat type": "chat.kindInvalid",
  "invalid channel name or limit": "error.channelNameLimit",
  "stream limit": "error.channelLimit",
  "unknown pinned stream": "error.channelUnavailable",
  "authority snapshot unavailable": "error.channelUnavailable",
  "missing text field": "error.required",
  "The password is incorrect": "error.passwordCheck",
  "choose 20, 50 or 100": "error.historyCount",
  "unsupported operation": "error.unsupportedAction",
};

const patterns: [RegExp, MessageKey][] = [
  [
    /^identifier must contain exactly \d+ lower-case hexadecimal characters$/,
    "error.identifier",
  ],
  [/^unsupported schema version \d+; expected \d+$/, "error.profileVersion"],
  [/^invalid storage input: /, "error.invalidData"],
  [/^invalid identifier in local database: /, "error.profileData"],
  [/^I\/O error: /, "error.fileAccess"],
  [
    /^SQLite error \(no local success confirmed\): /,
    "error.storageUnconfirmed",
  ],
  [/^retry differs from the original local commit: /, "error.retryChanged"],
  [
    /(biometryNotAvailable|biometryNotEnrolled|passcodeNotSet)/i,
    "error.biometricUnavailable",
  ],
  [
    /(authenticationFailed|invalidContext|notInteractive)/i,
    "error.biometricFailed",
  ],
  [/biometryLockout/i, "error.biometricLocked"],
  [
    /(itemNotFound|keychainError|dataNeedsReenrollment)/i,
    "error.savedUnlockInvalid",
  ],
];

/** Remove a repeated explanation while retaining additional diagnostic fields. */
export function distinctErrorDetail(
  message: string,
  detail?: string,
): string | undefined {
  if (!detail?.trim()) return;
  const comparable = (text: string) =>
    errorText(text.trim()).replace(/[.!…]+$/, "");
  const repeats = (text: string) => {
    const translated = Object.prototype.hasOwnProperty.call(known, text)
      ? t(known[text])
      : text;
    return comparable(translated) === comparable(message);
  };
  if (repeats(detail)) return;
  try {
    const decoded: unknown = JSON.parse(detail);
    if (typeof decoded === "string" && repeats(decoded)) return;
    if (
      decoded &&
      typeof decoded === "object" &&
      !Array.isArray(decoded) &&
      "message" in decoded &&
      typeof decoded.message === "string" &&
      repeats(decoded.message)
    ) {
      const extra = Object.fromEntries(
        Object.entries(decoded).filter(([key]) => key !== "message"),
      );
      return Object.keys(extra).length
        ? JSON.stringify(extra, null, 2)
        : undefined;
    }
  } catch {
    /* Plain-text diagnostics remain useful when they add information. */
  }
  return detail;
}

/** Known explanations are presented once; unknown failures remain inspectable. */
export function presentError(error: unknown, passwordBytes?: number) {
  let detail: string;
  try {
    detail =
      error instanceof Error
        ? error.message
        : typeof error === "string"
          ? error
          : (JSON.stringify(error, null, 2) ?? String(error));
  } catch {
    detail = t("error.generic");
  }
  let source = error;
  if (typeof source === "string" && source.trimStart().startsWith("{")) {
    try {
      source = JSON.parse(source);
    } catch {
      /* Keep unknown diagnostics intact. */
    }
  }
  const reason =
    source &&
    typeof source === "object" &&
    "message" in source &&
    typeof source.message === "string"
      ? source.message
      : detail;
  // Application-authored messages are already translated and actionable.
  if (Object.values(en).some((message) => message === reason))
    return {
      message: reason,
      ...withDetail(distinctErrorDetail(reason, detail)),
    };
  if (reason === "passphrase must contain 12..=1024 UTF-8 bytes") {
    return {
      message: t(
        passwordBytes !== undefined && passwordBytes < 12
          ? "error.passwordShort"
          : passwordBytes !== undefined && passwordBytes > 1024
            ? "error.passwordLong"
            : "error.passwordCheck",
      ),
      detail,
    };
  }
  const key = Object.prototype.hasOwnProperty.call(known, reason)
    ? known[reason]
    : (patterns.find(([pattern]) => pattern.test(reason))?.[1] ??
      "error.generic");
  if (
    key === "invite.cameraUnavailable" ||
    key === "invite.cameraDenied" ||
    key === "error.serverTimeout" ||
    key === "contacts.error.ownCode" ||
    key === "notifications.error.registration" ||
    key === "notifications.error.permission" ||
    key === "recover.error.backupRequiredDataSize"
  )
    return { message: t(key) };
  const message = t(key);
  return { message, ...withDetail(distinctErrorDetail(message, detail)) };
}

function withDetail(detail: string | undefined) {
  return detail ? { detail } : {};
}
