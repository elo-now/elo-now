import { useLayoutEffect, useRef, useState } from "react";

/** Fit complete names first; reserve the omitted-person count even at large scale. */
export function ParticipantTitle({ names }: { names: string[] }) {
  const ref = useRef<HTMLSpanElement>(null);
  const [visible, setVisible] = useState(names.length);
  const key = JSON.stringify(names);
  useLayoutEffect(() => {
    const root = ref.current!;
    let active = true;
    const measure = () => {
      if (!active) return;
      const candidates = [
        ...root.querySelectorAll<HTMLElement>(".participant-title-measure"),
      ];
      let count = 1;
      candidates.forEach((candidate, index) => {
        if (candidate.getBoundingClientRect().width <= root.clientWidth)
          count = index + 1;
      });
      setVisible(count);
    };
    const observer = new ResizeObserver(measure);
    observer.observe(root);
    measure();
    void document.fonts.ready.then(measure);
    document.fonts.addEventListener("loadingdone", measure);
    return () => {
      active = false;
      observer.disconnect();
      document.fonts.removeEventListener("loadingdone", measure);
    };
  }, [key]);
  const count = Math.min(visible, names.length);
  return (
    <span ref={ref} className="participant-title" aria-label={names.join(", ")}>
      <span className="participant-title-visible" aria-hidden="true">
        <span>{names.slice(0, count).join(", ")}</span>
        {count < names.length && (
          <span className="participant-title-count">
            +{names.length - count}
          </span>
        )}
      </span>
      {names.map((_, index) => (
        <span
          className="participant-title-measure"
          aria-hidden="true"
          key={index}
        >
          {names.slice(0, index + 1).join(", ")}
          {index + 1 < names.length ? ` +${names.length - index - 1}` : ""}
        </span>
      ))}
    </span>
  );
}
