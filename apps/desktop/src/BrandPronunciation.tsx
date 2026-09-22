import { useEffect, useId, useRef, useState } from "react";
import { Icon } from "./Icon";
import { t } from "./i18n";

export function BrandPronunciation() {
  const audioRef = useRef<HTMLAudioElement>(null);
  const [playing, setPlaying] = useState(false);
  const [failed, setFailed] = useState(false);
  const statusId = useId();
  useEffect(() => {
    const audio = audioRef.current;
    const pauseWhenHidden = () => {
      if (document.hidden) audio?.pause();
    };
    document.addEventListener("visibilitychange", pauseWhenHidden);
    return () => {
      document.removeEventListener("visibilitychange", pauseWhenHidden);
      audio?.pause();
    };
  }, []);
  const play = async () => {
    const audio = audioRef.current;
    if (!audio) return;
    setFailed(false);
    try {
      audio.pause();
      if (audio.error) audio.load();
      audio.currentTime = 0;
      await audio.play();
    } catch (error) {
      if (error instanceof DOMException && error.name === "AbortError") return;
      setFailed(true);
      setPlaying(false);
    }
  };
  return (
    <div className="brand-pronunciation">
      <button
        type="button"
        className="pronunciation-button"
        aria-label={t("brand.pronunciation.play")}
        aria-describedby={failed ? statusId : undefined}
        data-playing={playing}
        onClick={() => void play()}
      >
        <Icon name="volume" />
        <span>{t("brand.pronunciation.spelling")}</span>
      </button>
      <audio
        ref={audioRef}
        src="/brand/elo.mp3"
        preload="none"
        hidden
        onPlaying={() => setPlaying(true)}
        onPause={() => setPlaying(false)}
        onEnded={() => setPlaying(false)}
        onError={() => {
          setPlaying(false);
          setFailed(true);
        }}
      />
      <span id={statusId} className="pronunciation-status" role="status">
        {failed ? t("brand.pronunciation.error") : ""}
      </span>
    </div>
  );
}
