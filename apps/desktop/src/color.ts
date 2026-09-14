export type Hsv = { h: number; s: number; v: number };

export function normalizeHex(value: string): string | null {
  const digits = value.trim().replace(/^#/, "");
  if (/^[\da-f]{6}$/i.test(digits)) return `#${digits.toLowerCase()}`;
  if (/^[\da-f]{3}$/i.test(digits)) {
    return `#${[...digits]
      .map((digit) => digit.repeat(2))
      .join("")
      .toLowerCase()}`;
  }
  return null;
}

export function hexToHsv(hex: string): Hsv {
  const normalized = normalizeHex(hex);
  if (!normalized) throw new Error("Invalid RGB color");
  const [r, g, b] = [1, 3, 5].map(
    (offset) => parseInt(normalized.slice(offset, offset + 2), 16) / 255,
  );
  const max = Math.max(r, g, b);
  const delta = max - Math.min(r, g, b);
  let h = 0;
  if (delta !== 0) {
    if (max === r) h = (g - b) / delta;
    else if (max === g) h = (b - r) / delta + 2;
    else h = (r - g) / delta + 4;
    h = (h * 60 + 360) % 360;
  }
  return { h, s: max === 0 ? 0 : delta / max, v: max };
}

export function hsvToHex({ h, s, v }: Hsv): string {
  const hue = (((h % 360) + 360) % 360) / 60;
  const saturation = Math.min(1, Math.max(0, s));
  const brightness = Math.min(1, Math.max(0, v));
  const chroma = brightness * saturation;
  const x = chroma * (1 - Math.abs((hue % 2) - 1));
  const components =
    hue < 1
      ? [chroma, x, 0]
      : hue < 2
        ? [x, chroma, 0]
        : hue < 3
          ? [0, chroma, x]
          : hue < 4
            ? [0, x, chroma]
            : hue < 5
              ? [x, 0, chroma]
              : [chroma, 0, x];
  return `#${components
    .map((component) =>
      Math.round((component + brightness - chroma) * 255)
        .toString(16)
        .padStart(2, "0"),
    )
    .join("")}`;
}
