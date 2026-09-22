import { isRingtone, type Ringtone } from "./calls/ringtone";
import { isMotif, motifImage, type Motif } from "./motifs";
import { readCustomMotif, type CustomMotif } from "./customMotif";

export type UiScale = "compact" | "system" | "large";
export type LanguagePreference = "system" | "en";
export type ColorScheme =
  "mint" | "ocean" | "sunset" | "violet" | "pink" | "black";
export type PaletteKey =
  "background" | "surface" | "text" | "accent" | "button";
export type Palette = Record<PaletteKey, string>;

export type UserPreferences = {
  uiScale: UiScale;
  language: LanguagePreference;
  colorScheme: ColorScheme;
  colorOverrides: Partial<Record<"light" | "dark", Partial<Palette>>>;
  hideAvatars: boolean;
  highlightMyMessages: boolean;
  callRingtone: Ringtone;
  motif: Motif;
  motifOpacity: number;
  customMotif: CustomMotif | null;
};

const key = "elo.userPreferences.v1";

export const defaultPreferences: UserPreferences = {
  uiScale: "system",
  language: "en",
  colorScheme: "mint",
  colorOverrides: {},
  hideAvatars: false,
  highlightMyMessages: false,
  callRingtone: "classic",
  motif: "elo",
  motifOpacity: 0.14,
  customMotif: null,
};

export const colorSchemes: Record<
  ColorScheme,
  { light: Palette; dark: Palette }
> = {
  mint: {
    light: {
      background: "#f7f9f6",
      surface: "#ffffff",
      text: "#2f493d",
      accent: "#6f8f7b",
      button: "#c3e3cf",
    },
    dark: {
      background: "#15231d",
      surface: "#1e3027",
      text: "#f7f9f6",
      accent: "#9ab5a1",
      button: "#c3e3cf",
    },
  },
  ocean: {
    light: {
      background: "#f5f8fa",
      surface: "#ffffff",
      text: "#263f4a",
      accent: "#527d8f",
      button: "#c7e3ec",
    },
    dark: {
      background: "#10242c",
      surface: "#19343e",
      text: "#f3f8fa",
      accent: "#8eb9c8",
      button: "#b9dce7",
    },
  },
  sunset: {
    light: {
      background: "#fbf7f3",
      surface: "#ffffff",
      text: "#543b32",
      accent: "#a46d55",
      button: "#efd1bf",
    },
    dark: {
      background: "#2b1d19",
      surface: "#3a2822",
      text: "#fff7f1",
      accent: "#d49b7e",
      button: "#ecc8b4",
    },
  },
  violet: {
    light: {
      background: "#f8f6fb",
      surface: "#ffffff",
      text: "#463c57",
      accent: "#796a94",
      button: "#ddd2ed",
    },
    dark: {
      background: "#211b2b",
      surface: "#30263d",
      text: "#faf6ff",
      accent: "#aa98c4",
      button: "#d8c9eb",
    },
  },
  pink: {
    light: {
      background: "#fff7fb",
      surface: "#ffffff",
      text: "#503541",
      accent: "#9a5d7a",
      button: "#f3cade",
    },
    dark: {
      background: "#2b1722",
      surface: "#3b2130",
      text: "#fff5fa",
      accent: "#d9a0bd",
      button: "#edbfd6",
    },
  },
  black: {
    light: {
      background: "#f5f5f5",
      surface: "#ffffff",
      text: "#181818",
      accent: "#626262",
      button: "#242424",
    },
    dark: {
      background: "#000000",
      surface: "#141414",
      text: "#f5f5f5",
      accent: "#a3a3a3",
      button: "#e3e3e3",
    },
  },
};

const validScale = (value: unknown): value is UiScale =>
  value === "compact" || value === "system" || value === "large";
const validScheme = (value: unknown): value is ColorScheme =>
  value === "mint" ||
  value === "ocean" ||
  value === "sunset" ||
  value === "violet" ||
  value === "pink" ||
  value === "black";

export function readPreferences(): UserPreferences {
  try {
    const value = JSON.parse(
      localStorage.getItem(key) ?? "{}",
    ) as Partial<UserPreferences>;
    const customMotif = readCustomMotif(value.customMotif);
    return {
      ...defaultPreferences,
      uiScale: validScale(value.uiScale) ? value.uiScale : "system",
      language: value.language === "system" ? "system" : "en",
      colorScheme: validScheme(value.colorScheme) ? value.colorScheme : "mint",
      colorOverrides: value.colorOverrides ?? {},
      hideAvatars: value.hideAvatars === true,
      highlightMyMessages: value.highlightMyMessages === true,
      callRingtone: isRingtone(value.callRingtone)
        ? value.callRingtone
        : defaultPreferences.callRingtone,
      motif:
        isMotif(value.motif) && (value.motif !== "custom" || customMotif)
          ? value.motif
          : defaultPreferences.motif,
      customMotif,
      motifOpacity:
        typeof value.motifOpacity === "number" &&
        Number.isFinite(value.motifOpacity)
          ? Math.min(0.3, Math.max(0, value.motifOpacity))
          : defaultPreferences.motifOpacity,
    };
  } catch {
    return defaultPreferences;
  }
}

export function savePreferences(value: UserPreferences): boolean {
  try {
    localStorage.setItem(key, JSON.stringify(value));
    return true;
  } catch {
    // Keep preferences for this session if local storage is unavailable.
    return false;
  }
}

export function applyVisualPreferences(
  preferences: UserPreferences,
  theme: "light" | "dark",
  systemScale = 1,
): void {
  const root = document.documentElement;
  root.dataset.uiScale = preferences.uiScale;
  root.dataset.highlightMyMessages = String(preferences.highlightMyMessages);
  const scale = resolveUiScale(preferences.uiScale, systemScale);
  const palette = {
    ...colorSchemes[preferences.colorScheme][theme],
    ...preferences.colorOverrides[theme],
  };
  root.style.setProperty("--elo-ui-scale", String(scale));
  root.style.setProperty("--elo-background", palette.background);
  root.style.setProperty("--elo-surface", palette.surface);
  root.style.setProperty("--elo-text", palette.text);
  root.style.setProperty("--elo-accent", palette.accent);
  root.style.setProperty("--elo-button", palette.button);
  const motif = preferences.motif;
  [-12, 10, -6].forEach((angle, index) => {
    root.style.setProperty(
      `--elo-motif-${index + 1}`,
      motifImage(
        motif,
        palette.accent,
        preferences.motifOpacity,
        angle,
        preferences.customMotif,
      ),
    );
  });
  const channels = palette.button
    .match(/[a-f\d]{2}/gi)
    ?.map((value) => parseInt(value, 16)) ?? [255, 255, 255];
  const luminance =
    channels[0] * 0.299 + channels[1] * 0.587 + channels[2] * 0.114;
  root.style.setProperty(
    "--elo-onButton",
    luminance > 150 ? "#20352b" : "#ffffff",
  );
  root.style.setProperty(
    "--elo-line",
    `color-mix(in srgb, ${palette.text} 16%, ${palette.background})`,
  );
  root.style.setProperty(
    "--elo-muted",
    `color-mix(in srgb, ${palette.text} 68%, ${palette.background})`,
  );
}

export function resolveUiScale(
  preference: UiScale,
  systemScale: number,
): number {
  const value =
    preference === "compact"
      ? 0.88
      : preference === "large"
        ? 1.16
        : systemScale;
  return Math.min(3.5, Math.max(0.8, Number.isFinite(value) ? value : 1));
}

export function updateColorOverride(
  preferences: UserPreferences,
  theme: "light" | "dark",
  color: PaletteKey,
  value: string,
): UserPreferences {
  return {
    ...preferences,
    colorOverrides: {
      ...preferences.colorOverrides,
      [theme]: { ...preferences.colorOverrides[theme], [color]: value },
    },
  };
}

export function selectColorScheme(
  preferences: UserPreferences,
  colorScheme: ColorScheme,
): UserPreferences {
  return { ...preferences, colorScheme, colorOverrides: {} };
}

export function selectMotif(
  preferences: UserPreferences,
  motif: Motif,
): UserPreferences {
  return { ...preferences, motif };
}
