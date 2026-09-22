import tones from "./ringtone-notes.json";
export const ringtones = ["classic", "chime", "pulse", "silent"] as const;
export type Ringtone = (typeof ringtones)[number];
export type AudibleRingtone = Exclude<Ringtone, "silent">;
export const isRingtone = (value: unknown): value is Ringtone =>
  ringtones.includes(value as Ringtone);

type Stop = () => void;
type Play = (tone: AudibleRingtone) => Stop;

/** One sound owner: incoming calls take priority over the bounded preview. */
export class CallRinger {
  private incoming?: string;
  private tone?: Ringtone;
  private busy = false;
  private stopRing?: Stop;
  private stopPreview?: Stop;
  private previewTimer?: ReturnType<typeof setTimeout>;
  private previewEnded?: () => void;
  constructor(private play: Play) {}

  update(incoming: string | undefined, tone: Ringtone, busy = false) {
    const busyChanged = this.busy !== busy;
    this.busy = busy;
    if (incoming || busy) this.cancelPreview();
    if (this.incoming === incoming && this.tone === tone && !busyChanged)
      return;
    this.stopRing?.();
    this.stopRing = undefined;
    this.incoming = incoming;
    this.tone = tone;
    if (incoming && !busy && tone !== "silent") this.stopRing = this.play(tone);
  }

  preview(tone: Ringtone, onEnd: () => void): boolean {
    this.cancelPreview();
    if (this.incoming || this.busy || tone === "silent") return false;
    this.previewEnded = onEnd;
    this.stopPreview = this.play(tone);
    this.previewTimer = setTimeout(() => this.cancelPreview(), 3000);
    return true;
  }

  cancelPreview() {
    clearTimeout(this.previewTimer);
    this.stopPreview?.();
    this.stopPreview = undefined;
    const ended = this.previewEnded;
    this.previewEnded = undefined;
    ended?.();
  }

  stop() {
    this.cancelPreview();
    this.stopRing?.();
    this.stopRing = undefined;
    this.incoming = undefined;
    this.tone = undefined;
    this.busy = false;
  }
}

// Local synthesized tones require no file download or microphone permission.
let context: AudioContext | undefined;
function audioContext() {
  if (!context || context.state === "closed") context = new AudioContext();
  return context;
}
export function unlockRingtoneAudio() {
  try {
    const audio = audioContext();
    if (audio.state !== "running") void audio.resume().catch(() => {});
  } catch {
    // Audio support must never prevent answering a call.
  }
}

const notes: Record<AudibleRingtone, readonly (readonly number[])[]> = tones;
function playTone(tone: AudibleRingtone): Stop {
  const sources = new Set<OscillatorNode>();
  let stopped = false;
  const cycle = () => {
    if (stopped) return;
    try {
      const audio = audioContext();
      // Do not accumulate scheduled sound while the OS suspends the webview.
      if (audio.state !== "running") return;
      for (const [offset, frequency, length] of notes[tone]) {
        const start = audio.currentTime + offset;
        const oscillator = audio.createOscillator();
        const volume = audio.createGain();
        oscillator.type = "sine";
        oscillator.frequency.value = frequency;
        volume.gain.setValueAtTime(0, start);
        volume.gain.linearRampToValueAtTime(0.13, start + 0.02);
        volume.gain.exponentialRampToValueAtTime(0.001, start + length);
        oscillator.connect(volume).connect(audio.destination);
        sources.add(oscillator);
        oscillator.onended = () => {
          sources.delete(oscillator);
          oscillator.disconnect();
          volume.disconnect();
        };
        oscillator.start(start);
        oscillator.stop(start + length + 0.02);
      }
    } catch {
      // Keep the visual Answer/Decline prompt available if audio is unavailable.
    }
  };
  unlockRingtoneAudio();
  // resume() may complete asynchronously even from an authorized user gesture.
  void context
    ?.resume()
    .then(cycle)
    .catch(() => {});
  const timer = setInterval(cycle, 3000);
  return () => {
    stopped = true;
    clearInterval(timer);
    for (const source of sources) {
      source.stop();
      source.disconnect();
    }
    sources.clear();
  };
}
export const callRinger = new CallRinger(playTone);
