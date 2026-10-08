import { invoke, isTauri } from "../diagnosticInvoke";
import { listen } from "@tauri-apps/api/event";
import { useEffect, useRef, useState } from "react";

export type AudioOutputContext = {
  identity: string;
  sessionId: string;
  activation: string;
};
export type AudioOutput = {
  id: string;
  kind: "receiver" | "speaker" | "headphones" | "bluetooth" | "system";
  name?: string;
};
export type AudioOutputs = { selected: string | null; outputs: AudioOutput[] };

export const supportsAudioOutput = () =>
  isTauri() && /Android|iPhone|iPad|iPod/.test(navigator.userAgent);

/** Route replies belong to one activation and must never update a successor session. */
export class AudioOutputRequests {
  private revision = 0;
  private selecting = false;
  private disposed = false;
  constructor(
    private context: AudioOutputContext,
    private changed: (outputs: AudioOutputs) => void,
    private failed: () => void,
    private request = (args: AudioOutputContext & { outputId?: string }) =>
      invoke<AudioOutputs>("native_call_audio", args),
  ) {}
  async refresh() {
    if (this.selecting || this.disposed) return;
    await this.run();
  }
  async select(outputId: string) {
    if (this.selecting || this.disposed) return;
    this.selecting = true;
    try {
      await this.run(outputId);
    } finally {
      this.selecting = false;
    }
  }
  private async run(outputId?: string) {
    const revision = ++this.revision;
    try {
      const result = await this.request({
        ...this.context,
        ...(outputId ? { outputId } : {}),
      });
      if (!this.disposed && revision === this.revision) this.changed(result);
    } catch {
      if (!this.disposed && revision === this.revision) this.failed();
    }
  }
  dispose() {
    this.disposed = true;
    ++this.revision;
  }
}

export function useAudioOutput(context?: AudioOutputContext) {
  const supported = supportsAudioOutput();
  const [state, setState] = useState<AudioOutputs>({
    selected: null,
    outputs: [],
  });
  const [error, setError] = useState(false);
  const [busy, setBusy] = useState(false);
  const requests = useRef<AudioOutputRequests | null>(null);
  useEffect(() => {
    setState({ selected: null, outputs: [] });
    setError(false);
    setBusy(false);
    if (!supported || !context) return;
    let disposed = false;
    let unlisten: (() => void) | undefined;
    const current = new AudioOutputRequests(
      context,
      (outputs) => {
        setState(outputs);
        setError(false);
      },
      () => setError(true),
    );
    requests.current = current;
    void current.refresh();
    void listen<{ sessionId: string; activation: string }>(
      "call-audio-route-changed",
      ({ payload }) => {
        if (
          payload.sessionId === context.sessionId &&
          payload.activation === context.activation
        )
          void current.refresh();
      },
    )
      .then((stop) => {
        if (disposed) stop();
        else {
          unlisten = stop;
          void current.refresh();
        }
      })
      .catch(() => {});
    const refresh = () => {
      if (document.visibilityState !== "hidden") void current.refresh();
    };
    document.addEventListener("visibilitychange", refresh);
    return () => {
      disposed = true;
      current.dispose();
      if (requests.current === current) requests.current = null;
      unlisten?.();
      document.removeEventListener("visibilitychange", refresh);
    };
  }, [supported, context?.identity, context?.sessionId, context?.activation]);
  return {
    ...state,
    supported,
    ready: !!context,
    error,
    busy,
    refresh: () => requests.current?.refresh(),
    select: async (id: string) => {
      const current = requests.current;
      if (!current || busy) return;
      setError(false);
      setBusy(true);
      await current.select(id);
      if (requests.current === current) setBusy(false);
    },
  };
}
