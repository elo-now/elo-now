import { flushSync } from "react-dom";
import "./navigationFade.css";

let running = false;

/** Fade the stable app layer, so replacing/unmounting a page cannot interrupt
 * the reveal. Top-layer dialogs need their own animation outside root opacity. */
export async function navigateBackWithFade(
  navigate: () => void,
  stillCurrent: () => boolean,
): Promise<void> {
  if (running || !stillCurrent()) return;
  const root = document.getElementById("root");
  if (
    !root?.animate ||
    innerWidth > 760 ||
    matchMedia("(prefers-reduced-motion: reduce)").matches
  ) {
    navigate();
    return;
  }
  running = true;
  const animations: Animation[] = [];
  const fade = (from: number, to: number, duration: number) => {
    const surfaces = [
      root,
      ...document.querySelectorAll<HTMLDialogElement>("dialog[open]"),
    ];
    const next = surfaces.map((surface) => {
      const animation = surface.animate([{ opacity: from }, { opacity: to }], {
        duration,
        easing: "ease-out",
        fill: "forwards",
      });
      animations.push(animation);
      return animation;
    });
    return next;
  };
  document.documentElement.classList.add("back-fading");
  try {
    const outgoing = fade(1, 0, 80);
    await Promise.all(outgoing.map((animation) => animation.finished));
    if (stillCurrent()) flushSync(navigate);
    // Mount the destination before revealing it, with no timer or blank hold.
    const incoming = fade(0, 1, 120);
    outgoing.forEach((animation) => animation.cancel());
    await Promise.all(incoming.map((animation) => animation.finished));
  } catch (error) {
    // WebView/OS cancellation must leave the app visible and interactive.
    if (!(error instanceof DOMException && error.name === "AbortError"))
      throw error;
  } finally {
    animations.forEach((animation) => animation.cancel());
    document.documentElement.classList.remove("back-fading");
    running = false;
  }
}
