import { useEffect, useLayoutEffect, useRef, useState } from "react";
import { brandIntroFrames } from "./locales/en";

const introSteps: {
  frame: number;
  caret?: number;
  hold: [number, number];
}[] = [
  { frame: 0, hold: [1000, 1400] },
  { frame: 1, hold: [250, 480] },
  { frame: 2, hold: [180, 370] },
  { frame: 3, hold: [220, 450] },
  { frame: 4, hold: [130, 260] },
  { frame: 5, hold: [780, 1100] },
  // Move behind the second l, then backspace it: hell|o → hel|o.
  { frame: 5, caret: 4, hold: [220, 300] },
  { frame: 6, caret: 3, hold: [140, 250] },
  // Move behind h, then backspace it: h|elo → |elo.
  { frame: 6, caret: 1, hold: [260, 400] },
  { frame: 7, caret: 0, hold: [200, 300] },
  { frame: 7, hold: [600, 800] },
  { frame: 8, hold: [300, 600] },
  { frame: 9, hold: [200, 420] },
  { frame: 10, hold: [180, 380] },
  { frame: 11, hold: [600, 900] },
];
const complete = introSteps.length;
const reducedMotionQuery = "(prefers-reduced-motion: reduce)";

/** Owned by ProfileGate: form switches retain progress; logout mounts a new intro. */
export function useBrandIntro() {
  const [frame, setFrame] = useState(() =>
    window.matchMedia(reducedMotionQuery).matches ? complete : 0,
  );
  useEffect(() => {
    const motion = window.matchMedia(reducedMotionQuery);
    let alive = true;
    let finished = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const finish = () => {
      finished = true;
      clearTimeout(timer);
      if (alive) setFrame(complete);
    };
    const changeMotion = () => {
      if (motion.matches) finish();
    };
    const advance = (index: number) => {
      if (!alive || finished) return;
      setFrame(index);
      if (index < complete) {
        const step = introSteps[index];
        const [min, max] = step.hold;
        const pause = ["hello", "elo"].includes(brandIntroFrames[step.frame]);
        timer = setTimeout(
          () => advance(index + 1),
          (min + Math.random() * (max - min)) * (pause ? 1 : 0.85),
        );
      }
    };
    if (motion.matches) finish();
    else {
      // Wait for the bundled wordmark font, without delaying the form itself.
      void document.fonts
        .load("700 72px Manrope")
        .then(() => advance(0), finish);
    }
    motion.addEventListener("change", changeMotion);
    return () => {
      alive = false;
      clearTimeout(timer);
      motion.removeEventListener("change", changeMotion);
    };
  }, []);
  return frame;
}

export function Brand({ introFrame }: { introFrame?: number }) {
  const live = introFrame !== undefined;
  const frame = introFrame ?? complete;
  const typing = frame < complete;
  const step = introSteps[Math.min(frame, complete - 1)];
  const text = brandIntroFrames[step.frame];
  const caret = step.caret ?? text.length;
  const movingCaret = introSteps[frame - 1]?.frame === step.frame;
  const textRef = useRef<SVGTextElement>(null);
  const fullTextRef = useRef<SVGTextElement>(null);
  const [metrics, setMetrics] = useState(() =>
    typing
      ? { offset: -133, width: 0, caret: 279 }
      : { offset: 0, width: 256.56, caret: 279 },
  );
  useLayoutEffect(() => {
    if (!live) return;
    const width = textRef.current?.getComputedTextLength() ?? 0;
    const fullWidth = fullTextRef.current?.getComputedTextLength() ?? 1;
    // Start the star at the center; finish at its exact supplied-logo position.
    const ratio = width / Math.max(1, fullWidth);
    const scaledWidth = 256.56 * ratio;
    // Use glyph advances, including kerning, rather than equal-width letters.
    const caretAdvance =
      caret < text.length
        ? (textRef.current?.getStartPositionOfChar(caret).x ?? 0)
        : width;
    setMetrics({
      offset: -133 * (1 - Math.min(1, ratio)),
      width: scaledWidth,
      caret:
        272.56 -
        scaledWidth +
        (caretAdvance * 256.56) / Math.max(1, fullWidth) +
        (caret === text.length ? 6.44 : 0),
    });
  }, [text, caret, live]);
  const [word, suffix] = text.split(".");
  return (
    <div className="wordmark">
      <span
        className="brand-logo"
        role="img"
        aria-label="elo.now"
        data-intro={live}
      >
        <img className="brand-light" src="/brand/elo-logo-primary.svg" alt="" />
        <img className="brand-dark" src="/brand/elo-logo-dark.svg" alt="" />
        {live && (
          <svg
            className="brand-intro"
            viewBox="0 0 362 84"
            aria-hidden="true"
            focusable="false"
          >
            <text
              ref={fullTextRef}
              className="brand-intro-text"
              visibility="hidden"
            >
              elo.now
            </text>
            <text
              ref={textRef}
              className="brand-intro-text"
              visibility="hidden"
            >
              {text}
            </text>
            <g
              className="brand-intro-line"
              style={{ transform: `translateX(${metrics.offset}px)` }}
            >
              <text
                className="brand-intro-text"
                x="272.56"
                y="64"
                textAnchor="end"
                textLength={metrics.width || undefined}
                lengthAdjust="spacingAndGlyphs"
              >
                {word}
                {suffix !== undefined && (
                  <tspan className="brand-intro-accent">.</tspan>
                )}
                {suffix}
              </text>
              {typing && text.length > 0 && (
                <g
                  className="brand-intro-caret"
                  data-moving={movingCaret}
                  style={{ transform: `translateX(${metrics.caret}px)` }}
                >
                  <rect
                    key={frame}
                    className="brand-intro-cursor"
                    x="-1"
                    y="12"
                    width="2"
                    height="54"
                    rx="1"
                  />
                </g>
              )}
              <g
                transform="translate(282 6)"
                fill="none"
                className="brand-intro-star"
                strokeWidth="5"
                strokeLinecap="round"
              >
                <path d="M32 14v36M14 32h36M19 19l26 26M19 45l26-26" />
              </g>
            </g>
          </svg>
        )}
      </span>
    </div>
  );
}
