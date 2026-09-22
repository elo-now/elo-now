/** Service decisions must not be presented as generic connectivity failures. */
export function callErrorCopy(code: string) {
  switch (code) {
    case "already_joined":
      return {
        title: "calls.alreadyJoinedTitle",
        message: "calls.alreadyJoined",
      } as const;
    case "ended":
      return { title: "calls.endedTitle", message: "calls.ended" } as const;
    case "screen_unavailable":
      return {
        title: "calls.screenFailed",
        message: "calls.screenRetry",
      } as const;
    case "encryption_unavailable":
      return { title: "calls.failed", message: "calls.unsupported" } as const;
    case "NotAllowedError":
      return { title: "calls.failed", message: "calls.permission" } as const;
    case "unauthorized":
      return { title: "calls.failed", message: "calls.unauthorized" } as const;
    case "full":
      return { title: "calls.failed", message: "calls.full" } as const;
    case "media_limit":
      return { title: "calls.failed", message: "calls.mediaLimit" } as const;
    default:
      return { title: "calls.failed", message: "calls.retry" } as const;
  }
}
