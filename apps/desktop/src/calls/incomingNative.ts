import { invoke, isTauri } from "../diagnosticInvoke";
import { listen } from "@tauri-apps/api/event";
import type { ActiveCall, MediaState } from "./types";

export type NativeCallAction = {
  action: "answer" | "decline" | "end";
  call_id: string;
  hosting_space_id: string;
  space: string;
  stream: string;
  invitation_id?: string;
  activation?: string;
};
export type NativeActiveCall = {
  identity: string;
  call: ActiveCall;
  session_id: string;
  activation: string;
  media: MediaState;
};
export type NativeIncomingStatus = {
  active?: NativeActiveCall | null;
  presented?: { call_id: string; invitation_id: string }[];
};
const supported = () =>
  isTauri() && /Android|iPhone|iPad|iPod/.test(navigator.userAgent);
export async function incomingStatus(
  identity: string,
): Promise<NativeIncomingStatus> {
  return supported()
    ? invoke("native_call_incoming", { identity, op: "status" })
    : {};
}
export async function listenIncomingCalls(
  action: (event: NativeCallAction) => void,
  presentation: () => void,
) {
  if (!supported()) return () => {};
  const first = await listen<NativeCallAction>(
    "elo-call-action",
    ({ payload }) => action(payload),
  );
  try {
    const second = await listen("elo-call-presentation", presentation);
    return () => {
      first();
      second();
    };
  } catch (error) {
    first();
    throw error;
  }
}
