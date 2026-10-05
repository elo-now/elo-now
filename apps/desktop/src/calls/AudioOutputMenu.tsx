import {
  Bluetooth,
  Check,
  Ear,
  EarOff,
  Headphones,
  Phone,
  Volume2,
} from "lucide-react";
import { ActionDialog } from "../ActionDialog";
import { t } from "../i18n";
import type { AudioOutput, useAudioOutput } from "./audioOutput";

export function audioOutputLabel(output?: AudioOutput) {
  if (
    output?.name &&
    (output.kind === "headphones" || output.kind === "bluetooth")
  )
    return output.name;
  return t(`calls.output.${output?.kind ?? "system"}`);
}

export function AudioOutputIcon({
  output,
  muted = false,
}: {
  output?: AudioOutput;
  muted?: boolean;
}) {
  if (muted) return <EarOff />;
  switch (output?.kind) {
    case "receiver":
      return <Phone />;
    case "speaker":
      return <Volume2 />;
    case "bluetooth":
      return <Bluetooth />;
    case "headphones":
      return <Headphones />;
    default:
      return <Ear />;
  }
}

export function AudioOutputMenu({
  audio,
  muted,
  onMute,
  onClose,
}: {
  audio: ReturnType<typeof useAudioOutput>;
  muted: boolean;
  onMute: () => void;
  onClose: () => void;
}) {
  return (
    <ActionDialog title={t("calls.audioOutput")} onClose={onClose}>
      <div
        className="call-output-options"
        role="group"
        aria-label={t("calls.audioOutput")}
      >
        {audio.outputs.map((output) => (
          <button
            type="button"
            className="secondary"
            key={output.id}
            aria-pressed={audio.selected === output.id}
            disabled={audio.busy}
            onClick={() => void audio.select(output.id)}
          >
            <AudioOutputIcon output={output} />
            <span>{audioOutputLabel(output)}</span>
            {audio.selected === output.id && <Check aria-hidden="true" />}
          </button>
        ))}
      </div>
      {audio.error && (
        <p className="error" role="alert">
          {t("calls.outputFailed")}
        </p>
      )}
      <div className="call-output-mute">
        <button
          type="button"
          className="secondary"
          aria-pressed={muted}
          onClick={onMute}
        >
          {muted ? <Ear /> : <EarOff />}
          <span>{t(muted ? "calls.unmuteSpeaker" : "calls.muteSpeaker")}</span>
        </button>
      </div>
    </ActionDialog>
  );
}
