export type Point = { x: number; y: number };
export type FloatingBounds = {
  left: number;
  top: number;
  width: number;
  height: number;
};
export type FloatingSize = { width: number; height: number };

const unit = (value: number) => Math.max(0, Math.min(1, value));

export function floatingPosition(
  bounds: FloatingBounds,
  size: FloatingSize,
  anchor: Point,
): Point {
  return {
    x: bounds.left + Math.max(0, bounds.width - size.width) * unit(anchor.x),
    y: bounds.top + Math.max(0, bounds.height - size.height) * unit(anchor.y),
  };
}

export function floatingAnchor(
  bounds: FloatingBounds,
  size: FloatingSize,
  point: Point,
): Point {
  return {
    x: unit((point.x - bounds.left) / Math.max(1, bounds.width - size.width)),
    y: unit((point.y - bounds.top) / Math.max(1, bounds.height - size.height)),
  };
}

/** Slow drags keep their position; deliberate flicks dock in their direction. */
export function floatingReleaseAnchor(
  bounds: FloatingBounds,
  size: FloatingSize,
  point: Point,
  motion: Point & { duration: number },
): Point {
  const anchor = floatingAnchor(bounds, size, point);
  const dx = Math.abs(motion.x);
  const dy = Math.abs(motion.y);
  const distance = Math.hypot(dx, dy);
  const flick =
    motion.duration > 0 &&
    motion.duration <= 180 &&
    distance >= 24 &&
    distance / motion.duration >= 0.45;
  const nearEdge = (value: number, travel: number) => {
    if (travel <= 0) return 0;
    const magnet = Math.min(16, travel / 3);
    if (value * travel <= magnet) return 0;
    if ((1 - value) * travel <= magnet) return 1;
    return value;
  };
  if (!flick)
    return {
      x: nearEdge(anchor.x, bounds.width - size.width),
      y: nearEdge(anchor.y, bounds.height - size.height),
    };
  if (dy > dx * 1.25)
    return { x: anchor.x < 0.5 ? 0 : 1, y: motion.y < 0 ? 0 : 1 };
  if (dx > dy * 1.25)
    return {
      x: motion.x < 0 ? 0 : 1,
      y: nearEdge(anchor.y, bounds.height - size.height),
    };
  return { x: motion.x < 0 ? 0 : 1, y: motion.y < 0 ? 0 : 1 };
}
