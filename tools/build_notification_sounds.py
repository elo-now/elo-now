#!/usr/bin/env python3
"""Rebuild small, offline notification sounds from owner-provided recordings and synthesized chimes."""

from pathlib import Path
import math
import struct
import subprocess
import wave

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "apps/desktop/public/sounds"
RATE = 44100


def chime(name: str, notes: list[tuple[float, float]], duration: float) -> None:
    samples = []
    for index in range(round(duration * RATE)):
        time = index / RATE
        value = 0.0
        for start, frequency in notes:
            age = time - start
            if age >= 0:
                envelope = min(1, age / 0.008) * math.exp(-age * 15)
                value += 0.19 * envelope * math.sin(2 * math.pi * frequency * age)
        value *= min(1, (duration - time) / 0.03)
        samples.append(struct.pack("<h", round(max(-1, min(1, value)) * 32767)))
    with wave.open(str(OUTPUT / name), "wb") as output:
        output.setnchannels(1)
        output.setsampwidth(2)
        output.setframerate(RATE)
        output.writeframes(b"".join(samples))


def main() -> None:
    OUTPUT.mkdir(parents=True, exist_ok=True)
    chime("default.wav", [(0, 880), (0.105, 1174.659)], 0.43)
    chime("soft.wav", [(0, 659.255)], 0.34)
    # Preserve the supplied performances, pitch, duration and level. The app
    # applies a common playback volume; native notifications use these PCM files.
    for name in ("elo-male", "elo-female"):
        subprocess.run(
            ["ffmpeg", "-v", "error", "-nostdin", "-y", "-i",
             str(ROOT / "apps/desktop/assets/notification-sounds" / f"{name}.mp3"),
             "-ar", str(RATE), "-ac", "1", "-c:a", "pcm_s16le",
             str(OUTPUT / f"{name}.wav")],
            check=True,
        )


if __name__ == "__main__":
    main()
