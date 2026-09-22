import { customMotifPaths, type CustomMotif } from "./customMotif";

// Line art from lucide-react 1.44.0 (ISC), except the elo brand star.
// Full Lucide/Feather notices: public/licenses/lucide.txt.
// Keep this small curated set independent of the color preferences.
const artwork = {
  elo: '<path d="M12 3v18M3 12h18M5.5 5.5l13 13M5.5 18.5l13-13"/>',
  none: null,
  cat: '<path d="M12 5c.67 0 1.35.09 2 .26 1.78-2 5.03-2.84 6.42-2.26 1.4.58-.42 7-.42 7 .57 1.07 1 2.24 1 3.44C21 17.9 16.97 21 12 21s-9-3-9-7.56c0-1.25.5-2.4 1-3.44 0 0-1.89-6.42-.5-7 1.39-.58 4.72.23 6.5 2.23A9.04 9.04 0 0 1 12 5Z"/><path d="M8 14v.5"/><path d="M16 14v.5"/><path d="M11.25 16.25h1.5L12 17l-.75-.75Z"/>',
  rabbit:
    '<path d="M13 16a3 3 0 0 1 2.24 5"/><path d="M18 12h.01"/><path d="M18 21h-8a4 4 0 0 1-4-4 7 7 0 0 1 7-7h.2L9.6 6.4a1 1 0 1 1 2.8-2.8L15.8 7h.2c3.3 0 6 2.7 6 6v1a2 2 0 0 1-2 2h-1a3 3 0 0 0-3 3"/><path d="M20 8.54V4a2 2 0 1 0-4 0v3"/><path d="M7.612 12.524a3 3 0 1 0-1.6 4.3"/>',
  dog: '<path d="M11.25 16.25h1.5L12 17z"/><path d="M16 14v.5"/><path d="M4.42 11.247A13.152 13.152 0 0 0 4 14.556C4 18.728 7.582 21 12 21s8-2.272 8-6.444a11.702 11.702 0 0 0-.493-3.309"/><path d="M8 14v.5"/><path d="M8.5 8.5c-.384 1.05-1.083 2.028-2.344 2.5-1.931.722-3.576-.297-3.656-1-.113-.994 1.177-6.53 4-7 1.923-.321 3.651.845 3.651 2.235A7.497 7.497 0 0 1 14 5.277c0-1.39 1.844-2.598 3.767-2.277 2.823.47 4.113 6.006 4 7-.08.703-1.725 1.722-3.656 1-1.261-.472-1.855-1.45-2.239-2.5"/>',
  ghost:
    '<path d="M15 10v1"/><path d="M7.528 20.472a1.6 1.6 0 012.277 0l1.057 1.056a1.6 1.6 0 002.276 0l1.057-1.056a1.6 1.6 0 012.277 0l1.114 1.114a1.4 1.4 0 002.414-1V10a8 8 0 00-16 0v10.586a1.4 1.4 0 002.414 1z"/><path d="M9 10v1"/>',
  rocket:
    '<path d="M12 15v5s3.03-.55 4-2c1.08-1.62 0-5 0-5"/><path d="M4.5 16.5c-1.5 1.26-2 5-2 5s3.74-.5 5-2c.71-.84.7-2.13-.09-2.91a2.18 2.18 0 0 0-2.91-.09"/><path d="M9 12a22 22 0 0 1 2-3.95A12.88 12.88 0 0 1 22 2c0 2.72-.78 7.5-6 11a22.4 22.4 0 0 1-4 2z"/><path d="M9 12H4s.55-3.03 2-4c1.62-1.08 5 .05 5 .05"/>',
  gamepad:
    '<line x1="6" x2="10" y1="11" y2="11"/><line x1="8" x2="8" y1="9" y2="13"/><line x1="15" x2="15.01" y1="12" y2="12"/><line x1="18" x2="18.01" y1="10" y2="10"/><path d="M17.32 5H6.68a4 4 0 0 0-3.978 3.59c-.006.052-.01.101-.017.152C2.604 9.416 2 14.456 2 16a3 3 0 0 0 3 3c1 0 1.5-.5 2-1l1.414-1.414A2 2 0 0 1 9.828 16h4.344a2 2 0 0 1 1.414.586L17 18c.5.5 1 1 2 1a3 3 0 0 0 3-3c0-1.545-.604-6.584-.685-7.258-.007-.05-.011-.1-.017-.151A4 4 0 0 0 17.32 5z"/>',
  swords:
    '<path d="m13 19 6-6"/><path d="M14.5 17.5 3.586 6.586A2 2 0 013 5.172V3h2.172a2 2 0 011.414.586L17.5 14.5"/><path d="m14.828 6.172 2.586-2.586A2 2 0 0118.828 3H21v2.172a2 2 0 01-.586 1.414l-2.586 2.586"/><path d="m16 16 4 4"/><path d="m19 21 2-2"/><path d="m5 14 4 4"/><path d="m5 21-2-2"/><path d="M7.5 16.5 4 20"/>',
  flower:
    '<path d="M12 5a3 3 0 1 1 3 3m-3-3a3 3 0 1 0-3 3m3-3v1M9 8a3 3 0 1 0 3 3M9 8h1m5 0a3 3 0 1 1-3 3m3-3h-1m-2 3v-1"/><circle cx="12" cy="8" r="2"/><path d="M12 10v12"/><path d="M12 22c4.2 0 7-1.667 7-5-4.2 0-7 1.667-7 5Z"/><path d="M12 22c-4.2 0-7-1.667-7-5 4.2 0 7 1.667 7 5Z"/>',
  fish: '<path d="M6.5 12c.94-3.46 4.94-6 8.5-6 3.56 0 6.06 2.54 7 6-.94 3.47-3.44 6-7 6s-7.56-2.53-8.5-6Z"/><path d="M18 12v.5"/><path d="M16 17.93a9.77 9.77 0 0 1 0-11.86"/><path d="M7 10.67C7 8 5.58 5.97 2.73 5.5c-1 1.5-1 5 .23 6.5-1.24 1.5-1.24 5-.23 6.5C5.58 18.03 7 16 7 13.33"/><path d="M10.46 7.26C10.2 5.88 9.17 4.24 8 3h5.8a2 2 0 0 1 1.98 1.67l.23 1.4"/><path d="m16.01 17.93-.23 1.4A2 2 0 0 1 13.8 21H9.5a5.96 5.96 0 0 0 1.49-3.98"/>',
  orbit:
    '<path d="M20.341 6.484A10 10 0 0 1 10.266 21.85"/><path d="M3.659 17.516A10 10 0 0 1 13.74 2.152"/><circle cx="12" cy="12" r="3"/><circle cx="19" cy="5" r="2"/><circle cx="5" cy="19" r="2"/>',
} as const;

// Unicode emoji use the device's emoji font, just like message reactions.
// No third-party emoji artwork or remote assets are bundled.
const emojiArtwork = {
  emojiSmile: "😀",
  emojiLaugh: "😂",
  emojiWink: "😉",
  emojiLove: "🥰",
  emojiCool: "😎",
  emojiParty: "🥳",
  emojiThink: "🤔",
  emojiSleep: "😴",
  emojiHeart: "❤️",
  emojiFire: "🔥",
  emojiSparkles: "✨",
  emojiRainbow: "🌈",
  emojiCat: "😺",
  emojiPanda: "🐼",
  emojiFox: "🦊",
  emojiUnicorn: "🦄",
  emojiGhost: "👻",
  emojiAlien: "👽",
  emojiRobot: "🤖",
  emojiSkull: "💀",
  emojiRocket: "🚀",
  emojiPizza: "🍕",
  emojiCoffee: "☕",
  emojiAvocado: "🥑",
} as const;

export type Motif = keyof typeof artwork | keyof typeof emojiArtwork | "custom";
export const motifs = [
  ...Object.keys(artwork),
  ...Object.keys(emojiArtwork),
] as Motif[];

export function motifEmoji(motif: Motif): string | null {
  return Object.hasOwn(emojiArtwork, motif)
    ? emojiArtwork[motif as keyof typeof emojiArtwork]
    : null;
}

export function isMotif(value: unknown): value is Motif {
  return (
    typeof value === "string" &&
    (value === "custom" ||
      Object.hasOwn(artwork, value) ||
      Object.hasOwn(emojiArtwork, value))
  );
}

export function motifImage(
  motif: Motif,
  color = "#000000",
  opacity = 1,
  angle = 0,
  custom: CustomMotif | null = null,
): string {
  const emoji = motifEmoji(motif);
  const paths =
    motif === "custom"
      ? custom && customMotifPaths(custom)
      : emoji
        ? null
        : artwork[motif as keyof typeof artwork];
  if (!paths && !emoji) return "none";
  // Palette values are local preferences; only a color may enter the SVG.
  const stroke = /^#[a-f\d]{6}$/i.test(color) ? color : "#6f8f7b";
  // The generous viewBox keeps rotated pictograms whole, including their strokes.
  const content = emoji
    ? `<text x="12" y="20" text-anchor="middle" font-family="Apple Color Emoji, Segoe UI Emoji, Noto Color Emoji, sans-serif" font-size="24" fill="${stroke}" stroke="none">${emoji}</text>`
    : paths;
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="-5 -5 34 34"><g fill="none" stroke="${stroke}" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" opacity="${opacity}" transform="rotate(${angle} 12 12)">${content}</g></svg>`;
  return `url("data:image/svg+xml,${encodeURIComponent(svg)}")`;
}
