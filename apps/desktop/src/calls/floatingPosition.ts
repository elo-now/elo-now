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
