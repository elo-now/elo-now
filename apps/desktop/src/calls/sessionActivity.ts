import { invoke, isTauri } from "../diagnosticInvoke";
import { listen } from "@tauri-apps/api/event";

const mobile = () =>
  isTauri() && /Android|iPhone|iPad|iPod/.test(navigator.userAgent);

export async function nativeCallState(state: {
  identity: string;
  sessionId: string;
  activation: string;
  active: boolean;
  camera: boolean;
  context: Record<string, unknown>;
}): Promise<void> {
  if (!mobile()) return;
  await invoke("native_call_state", state);
}

export async function listenNativeSessionEnd(
  ended: (sessionId: string, activation: string) => void,
) {
  if (!mobile()) return () => {};
  return listen<{ sessionId: string; activation: string }>(
    "call-session-ended",
    ({ payload }) => ended(payload.sessionId, payload.activation),
  );
}
