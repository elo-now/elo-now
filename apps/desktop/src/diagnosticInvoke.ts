import { invoke as nativeInvoke } from "@tauri-apps/api/core";
import { diagnostic } from "./diagnostics";
export * from "@tauri-apps/api/core";

export const invoke: typeof nativeInvoke = async (...parameters) => {
  const [command] = parameters;
  const started = performance.now();
  diagnostic("event", "ipc", command);
  try {
    return await nativeInvoke(...parameters);
  } catch (error) {
    diagnostic("error", "ipc", command, performance.now() - started);
    throw error;
  }
};
