/** Seen receipts describe the rendered list, never approval or membership changes. */
export function invitationSeenRequest(
  page: string,
  activity: {
    received?: { id: string }[];
    incoming?: { id: string }[];
    outgoing?: { id: string; status: string; seen?: boolean }[];
    notices?: { id: string; seen: boolean }[];
  },
) {
  if (page === "activity") {
    const ids = [
      ...(activity.received ?? []).map((entry) => `invitation:${entry.id}`),
      ...(activity.incoming ?? []).map((entry) => `request:${entry.id}`),
      ...(activity.outgoing ?? [])
        .filter((entry) => entry.status === "approved")
        .map((entry) => `approved:${entry.id}`),
    ];
    return ids.length ? { op: "invitation_activity_seen", ids } : undefined;
  }
  if (page === "notifications") {
    const ids = [
      ...(activity.notices ?? [])
        .filter((entry) => !entry.seen)
        .map((entry) => entry.id),
      ...(activity.outgoing ?? [])
        .filter((entry) => entry.status === "declined" && entry.seen === false)
        .map((entry) => entry.id),
    ];
    return ids.length
      ? { op: "invitation_notifications_seen", ids }
      : undefined;
  }
}
