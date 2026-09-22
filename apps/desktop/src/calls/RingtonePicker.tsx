import { useEffect, useState } from "react";
import { ChevronDown, Play, Square } from "lucide-react";
import { t } from "../i18n";
import { callRinger, ringtones, type Ringtone } from "./ringtone";

export function RingtonePicker({
  value,
  onChange,
}: {
  value: Ringtone;
  onChange: (value: Ringtone) => void;
}) {
  const [previewing, setPreviewing] = useState(false);
  useEffect(() => () => callRinger.cancelPreview(), []);
  return (
    <>
      <h3 id="call-ringtone-label">{t("settings.callRingtone")}</h3>
      <div className="ringtone-picker">
        <div className="ringtone-select">
          <select
            className="ringtone-select-input"
            aria-labelledby="call-ringtone-label"
            value={value}
            onChange={(event) => {
              callRinger.cancelPreview();
              onChange(event.target.value as Ringtone);
            }}
          >
            {ringtones.map((tone) => (
              <option key={tone} value={tone}>
                {t(`ringtone.${tone}`)}
              </option>
            ))}
          </select>
          <ChevronDown className="ringtone-chevron" aria-hidden="true" />
        </div>
        <button
          type="button"
          className="secondary ringtone-preview"
          disabled={value === "silent"}
          aria-label={t(
            previewing ? "ringtone.stopPreview" : "ringtone.preview",
          )}
          title={t(previewing ? "ringtone.stopPreview" : "ringtone.preview")}
          onClick={() => {
            if (previewing) callRinger.cancelPreview();
            else
              setPreviewing(
                callRinger.preview(value, () => setPreviewing(false)),
              );
          }}
        >
          {previewing ? <Square size={20} /> : <Play size={20} />}
        </button>
      </div>
    </>
  );
}
