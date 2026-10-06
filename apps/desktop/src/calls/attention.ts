import type { ActiveCall } from "./types";
import { callKey } from "./types";

const LIMIT = 128;
const storageKey = (identity: string) => `elo.call-dismissed.v1:${identity}`;
export const sessionKey = (call: ActiveCall) =>
  `${callKey(call)}:${call.call_id}`;

/** A dismissal affects presentation on this device, never membership or media. */
export function readDismissed(identity: string): string[] {
  try {
    const value: unknown = JSON.parse(
      localStorage.getItem(storageKey(identity)) ?? "[]",
    );
    return Array.isArray(value)
      ? value
          .filter(
            (entry): entry is string =>
              typeof entry === "string" && entry.length <= 512,
          )
          .slice(-LIMIT)
      : [];
  } catch {
    return [];
  }
}

export function saveDismissed(identity: string, values: string[]) {
  const bounded = [...new Set(values)].slice(-LIMIT);
  try {
    localStorage.setItem(storageKey(identity), JSON.stringify(bounded));
  } catch {}
  return bounded;
}

export function isRingingFor(
  call: ActiveCall,
  identity: string,
  now = Date.now(),
) {
  const invitation = call.invitations?.[identity];
  return (
    call.ready === true &&
    !call.participants[identity] &&
    (call.kind !== "direct" || call.phase === "ringing") &&
    !!invitation &&
    typeof invitation.invitation_id === "string" &&
    invitation.invitation_id.length > 0 &&
    invitation.invited_by !== identity &&
    !!call.participants[invitation.invited_by] &&
    Number.isSafeInteger(invitation.expires_at) &&
    now < invitation.expires_at * 1000
  );
}

export const invitationKey = (call: ActiveCall, identity: string) =>
  `${sessionKey(call)}:${call.invitations?.[identity]?.invitation_id ?? ""}`;
