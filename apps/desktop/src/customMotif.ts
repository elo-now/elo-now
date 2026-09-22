// Store bounded coordinates, never imported SVG or executable markup.
export type DrawPoint = [number, number];
export type DrawStroke = DrawPoint[];
export type CustomMotif = { v: 1; smooth: boolean; strokes: DrawStroke[] };

export const DRAW_SIZE = 256;
export const DRAW_WIDTH = 7;
export const MAX_DRAW_STROKES = 128;
export const MAX_DRAW_POINTS = 8192;

export function readCustomMotif(value: unknown): CustomMotif | null {
  if (!value || typeof value !== "object") return null;
  const drawing = value as Partial<CustomMotif>;
  if (
    drawing.v !== 1 ||
    typeof drawing.smooth !== "boolean" ||
    !Array.isArray(drawing.strokes) ||
    !drawing.strokes.length ||
    drawing.strokes.length > MAX_DRAW_STROKES
  )
    return null;
  let count = 0;
  const strokes: DrawStroke[] = [];
  for (const stroke of drawing.strokes) {
    if (!Array.isArray(stroke) || !stroke.length) return null;
    count += stroke.length;
    if (count > MAX_DRAW_POINTS) return null;
    const points: DrawStroke = [];
    for (const point of stroke) {
      if (
        !Array.isArray(point) ||
        point.length !== 2 ||
        point.some(
          (n) =>
            typeof n !== "number" ||
            !Number.isFinite(n) ||
            n < 0 ||
            n > DRAW_SIZE,
        )
      )
        return null;
      points.push([round(point[0]), round(point[1])]);
    }
    strokes.push(points);
  }
  return { v: 1, smooth: drawing.smooth, strokes };
}

const round = (n: number) => Math.round(n * 100) / 100;
const pair = (p: DrawPoint) => `${round(p[0])} ${round(p[1])}`;
const midpoint = (a: DrawPoint, b: DrawPoint): DrawPoint => [
  (a[0] + b[0]) / 2,
  (a[1] + b[1]) / 2,
];

export function strokePath(points: DrawStroke, smooth: boolean): string {
  if (!points.length) return "";
  const start = `M${pair(points[0])}`;
  // A round zero-length segment preserves a deliberate tap as a dot.
  if (points.length === 1) return `${start}h0`;
  if (!smooth || points.length === 2)
    return (
      start +
      points
        .slice(1)
        .map((p) => `L${pair(p)}`)
        .join("")
    );
  // A short symmetric filter suppresses touch jitter. Quadratic midpoints
  // join with continuous tangents, stay inside the sampled bounds and retain
  // both endpoints. Only the live tail changes as samples arrive.
  const filtered = points.map((p, i): DrawPoint =>
    i === 0 || i === points.length - 1
      ? p
      : [
          (points[i - 1][0] + 2 * p[0] + points[i + 1][0]) / 4,
          (points[i - 1][1] + 2 * p[1] + points[i + 1][1]) / 4,
        ],
  );
  let path = start;
  for (let i = 1; i < filtered.length - 1; i++)
    path += `Q${pair(filtered[i])} ${pair(midpoint(filtered[i], filtered[i + 1]))}`;
  return path + `L${pair(filtered[filtered.length - 1])}`;
}

export function customMotifPaths(drawing: CustomMotif): string {
  return `<g transform="scale(${24 / DRAW_SIZE})" stroke-width="${DRAW_WIDTH}">${drawing.strokes
    .map((stroke) => `<path d="${strokePath(stroke, drawing.smooth)}"/>`)
    .join("")}</g>`;
}
