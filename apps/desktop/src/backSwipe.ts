/** The left third starts Back; the remaining content keeps its own gestures. */
export function backSwipeStartArea(width: number): number {
  return width / 3;
}

export function backSwipeDirection(
  dx: number,
  dy: number,
): "wait" | "cancel" | "back" {
  if (dx < -8 || (Math.abs(dy) > 12 && Math.abs(dy) > Math.max(0, dx) * 0.75))
    return "cancel";
  return dx >= 12 && dx >= Math.abs(dy) * 1.5 ? "back" : "wait";
}

export function shouldFinishBackSwipe(
  distance: number,
  width: number,
  velocity: number,
): boolean {
  return (
    distance >= Math.max(64, Math.min(width * 0.28, 120)) ||
    (distance >= 40 && velocity > 0.5)
  );
}
