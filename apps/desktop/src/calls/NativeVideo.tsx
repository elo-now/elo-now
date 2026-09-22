import { useEffect, useRef } from "react";
import type { MediaTile } from "./types";

type Binding = { element: HTMLElement; tile: MediaTile };
const bindings = new Set<Binding>();
let frame = 0;
let last = "";
let busy = false;
let retryAfter = 0;
let current: MediaTile["native"];

/** Native video stays behind the transparent full-screen call surface. The
 * existing HTML badges and controls remain above it, without forwarding frames. */
async function layout() {
  frame = 0;
  const visible = [...bindings].filter(({ element }) => element.isConnected);
  const media = visible[0]?.tile.native;
  const frames = visible
    .filter(({ tile }) => tile.native?.session === media?.session)
    .map(({ element, tile }) => {
      const r = element.getBoundingClientRect();
      return {
        track: tile.native!.track,
        x: r.x,
        y: r.y,
        width: r.width,
        height: r.height,
        viewport_width: innerWidth,
        fit: tile.source === "screen",
        mirror: tile.local && tile.source === "camera",
      };
    });
  const key = JSON.stringify([media?.session, frames]);
  if (!busy && performance.now() >= retryAfter && key !== last) {
    busy = true;
    try {
      if (current && current.session !== media?.session)
        await current.render([]);
      current = media;
      if (media) await media.render(frames);
      last = key;
      const unchanged =
        visible.length === bindings.size &&
        visible.every(
          (binding) => bindings.has(binding) && binding.element.isConnected,
        );
      document.documentElement.classList.toggle(
        "native-call-video",
        unchanged && !!frames.length,
      );
    } catch {
      retryAfter = performance.now() + 1000;
      if (!bindings.size) {
        current = undefined;
        last = JSON.stringify([undefined, []]);
      }
      document.documentElement.classList.remove("native-call-video");
    } finally {
      busy = false;
    }
  }
  if (bindings.size || busy || last !== JSON.stringify([undefined, []]))
    frame = requestAnimationFrame(() => void layout());
}
export function NativeVideo({ tile, name }: { tile: MediaTile; name: string }) {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const binding = { element: ref.current!, tile };
    bindings.add(binding);
    if (!frame) frame = requestAnimationFrame(() => void layout());
    return () => {
      bindings.delete(binding);
      if (!bindings.size)
        document.documentElement.classList.remove("native-call-video");
      if (!frame) frame = requestAnimationFrame(() => void layout());
    };
  }, [tile.native?.session, tile.native?.track]);
  return (
    <div className="call-tile call-native-video" data-source={tile.source}>
      <div ref={ref} className="native-video-frame" aria-label={name} />
      <span>{name}</span>
    </div>
  );
}
