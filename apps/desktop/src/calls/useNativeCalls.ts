import { useLayoutEffect, useRef } from "react";
import { invoke } from "@tauri-apps/api/core";
import type { View } from "../model";
import type { Calls } from "./controller";
import { callRinger, type Ringtone } from "./ringtone";
import { NativeCallSession, type NativeCall } from "./native";
import { usesNativePeer } from "./nativePeer";
import type { ActiveCall } from "./types";

/** Native Answer uses the open profile; a cold start waits for normal unlock. */
export function useNativeCalls(
  calls: Calls,
  view: View | null | undefined,
  ringtone: Ringtone,
) {
  const nativeRinging = useRef(false);
  useLayoutEffect(() => {
    nativeRinging.current = false;
    if (!view) return;
    calls.setNativeAnswerChecked(false);
    const identity = view.identity;
    let stopped = false,
      running = false,
      toneSaved = false;
    let visibilityEpoch = 0;
    const action = (op: string) =>
      invoke("push_task", { op, expectedIdentity: identity });
    const session = new NativeCallSession(calls, identity, action);
    const tick = async () => {
      if (running || stopped) return;
      running = true;
      const epoch = visibilityEpoch;
      try {
        if (usesNativePeer()) {
          const native = await invoke<{
            incoming?: {
              id: string;
              call_id: string;
              phase: "connecting" | "connected";
              call?: ActiveCall;
            };
          }>("native_call_media", {
            identity,
            request: { op: "incoming_status" },
          });
          if (stopped || epoch !== visibilityEpoch) return;
          if (native.incoming) {
            const incoming = native.incoming;
            nativeRinging.current = true;
            callRinger.stop();
            await calls.adoptIncoming(incoming, () => {
              void invoke("native_call_media", {
                identity,
                request: { op: "stop", id: incoming.id },
              });
              calls.setNativeAnswer(undefined);
            });
            return;
          }
          await calls.finishManagedIncoming();
        }
        const { incoming } = await invoke<{ incoming?: NativeCall }>(
          "push_task",
          { op: "calls_status", expectedIdentity: identity },
        );
        if (stopped || epoch !== visibilityEpoch) return;
        nativeRinging.current = !!incoming?.id;
        if (nativeRinging.current) callRinger.stop();
        await session.consume(incoming);
        if (!toneSaved && !stopped) {
          await action(`calls_ringtone:${ringtone}`);
          toneSaved = true;
        }
      } catch {
        // Native calls are optional. Network/provider failures never bypass unlock.
      } finally {
        running = false;
        if (!stopped && document.visibilityState === "visible") {
          if (epoch === visibilityEpoch) calls.setNativeAnswerChecked(true);
          else void tick();
        }
      }
    };
    void tick();
    const timer = setInterval(() => void tick(), 1000);
    const unsubscribe = calls.subscribe(() => void tick());
    const visibilityChanged = () => {
      visibilityEpoch++;
      calls.setNativeAnswerChecked(false);
      if (document.visibilityState === "visible") void tick();
    };
    document.addEventListener("visibilitychange", visibilityChanged);
    return () => {
      stopped = true;
      session.stop();
      calls.setNativeAnswerChecked(false);
      nativeRinging.current = false;
      clearInterval(timer);
      unsubscribe();
      document.removeEventListener("visibilitychange", visibilityChanged);
    };
  }, [calls, view?.identity, ringtone]);
  return nativeRinging;
}
