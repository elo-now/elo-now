import { describe, expect, it, vi } from "vitest";
import {
  defaultPreferences,
  colorSchemes,
  selectColorScheme,
  selectMotif,
  applyVisualPreferences,
  resolveUiScale,
  readPreferences,
  savePreferences,
  updateColorOverride,
} from "./preferences";

describe("user display preferences", () => {
  it("preserves custom colors in both modes when a motif is chosen, disabled or reloaded", () => {
    let stored = JSON.stringify({
      colorScheme: "pink",
      motifOpacity: 0.07,
      colorOverrides: {
        light: { accent: "#654321", button: "#fedcba" },
        dark: { accent: "#123456", background: "#030405" },
      },
    });
    const applied = new Map<string, string>();
    vi.stubGlobal("localStorage", {
      getItem: () => stored,
      setItem: (_key: string, value: string) => {
        stored = value;
      },
    });
    vi.stubGlobal("document", {
      documentElement: {
        dataset: {},
        style: {
          setProperty: (key: string, value: string) => applied.set(key, value),
        },
      },
    });
    try {
      const previous = readPreferences();
      expect(previous.motif).toBe("elo");
      for (const motif of [
        "cat",
        "none",
        "rocket",
        "emojiSmile",
        "emojiHeart",
      ] as const) {
        savePreferences(selectMotif(previous, motif));
        const reloaded = readPreferences();
        expect(reloaded.motif).toBe(motif);
        expect(reloaded.motifOpacity).toBe(0.07);
        expect(reloaded.colorScheme).toBe("pink");
        expect(reloaded.colorOverrides).toEqual(previous.colorOverrides);
        applyVisualPreferences(reloaded, "light");
        expect(applied.get("--elo-accent")).toBe("#654321");
        expect(applied.get("--elo-button")).toBe("#fedcba");
        applyVisualPreferences(reloaded, "dark");
        expect(applied.get("--elo-accent")).toBe("#123456");
        expect(applied.get("--elo-background")).toBe("#030405");
        if (motif === "none") expect(applied.get("--elo-motif-1")).toBe("none");
        expect(selectColorScheme(reloaded, "mint").motif).toBe(motif);
      }
      stored = JSON.stringify({ ...previous, motif: "unrecognized" });
      expect(readPreferences().motif).toBe("elo");
      stored = JSON.stringify({ ...previous, motif: "__proto__" });
      expect(readPreferences().motif).toBe("elo");
    } finally {
      vi.unstubAllGlobals();
    }
  });
  it("migrates and bounds watermark opacity while preserving a fully transparent choice", () => {
    let stored = "{}";
    vi.stubGlobal("localStorage", { getItem: () => stored });
    try {
      expect(readPreferences().motifOpacity).toBe(0.14);
      for (const [value, expected] of [
        [0, 0],
        [-1, 0],
        [5, 0.3],
        [0.09, 0.09],
        ["invalid", 0.14],
      ]) {
        stored = JSON.stringify({ motifOpacity: value });
        expect(readPreferences().motifOpacity).toBe(expected);
      }
    } finally {
      vi.unstubAllGlobals();
    }
  });
  it("defaults to English, preserves System and drops obsolete time zone overrides", () => {
    let stored = "{}";
    vi.stubGlobal("localStorage", { getItem: () => stored });
    try {
      expect(readPreferences().language).toBe("en");
      stored = JSON.stringify({
        language: "system",
        timeZone: "Asia/Tokyo",
        uiScale: "compact",
        hideAvatars: true,
      });
      const preferences = readPreferences();
      expect(preferences.language).toBe("system");
      expect(preferences.uiScale).toBe("compact");
      expect(preferences.hideAvatars).toBe(true);
      expect(preferences).not.toHaveProperty("timeZone");
      stored = JSON.stringify({ language: "unsupported" });
      expect(readPreferences().language).toBe("en");
    } finally {
      vi.unstubAllGlobals();
    }
  });
  it("preserves the avatar choice across reloads and old preference migration", () => {
    let stored = JSON.stringify({ colorScheme: "ocean" });
    vi.stubGlobal("localStorage", {
      getItem: () => stored,
      setItem: (_key: string, value: string) => {
        stored = value;
      },
    });
    try {
      const existing = readPreferences();
      expect(existing.hideAvatars).toBe(false);
      expect(existing.colorScheme).toBe("ocean");
      savePreferences({ ...existing, hideAvatars: true });
      const reloaded = readPreferences();
      expect(reloaded.hideAvatars).toBe(true);
      expect(
        updateColorOverride(reloaded, "light", "accent", "#123456").hideAvatars,
      ).toBe(true);
      stored = JSON.stringify({ hideAvatars: "false" });
      expect(readPreferences().hideAvatars).toBe(false);
    } finally {
      vi.unstubAllGlobals();
    }
  });
  it("uses system scale by default and keeps explicit compact/large overrides", () => {
    expect(resolveUiScale("system", 1.4)).toBe(1.4);
    expect(resolveUiScale("compact", 1.4)).toBe(0.88);
    expect(resolveUiScale("large", 0.9)).toBe(1.16);
    expect(resolveUiScale("system", Number.NaN)).toBe(1);
  });

  it("keeps overrides separate and restores either selected or different presets", () => {
    const changed = updateColorOverride(
      defaultPreferences,
      "dark",
      "accent",
      "#123456",
    );
    expect(changed.colorScheme).toBe("mint");
    expect(changed.colorOverrides.dark?.accent).toBe("#123456");
    expect(changed.colorOverrides.light).toBeUndefined();
    const bothThemes = updateColorOverride(changed, "light", "text", "#222222");
    expect(bothThemes.colorOverrides.dark?.accent).toBe("#123456");
    expect(selectColorScheme(bothThemes, "mint").colorOverrides).toEqual({});
    for (const colorScheme of ["pink", "black"] as const) {
      const selected = selectColorScheme(bothThemes, colorScheme);
      expect(selected.colorScheme).toBe(colorScheme);
      expect(selected.colorOverrides).toEqual({});
      expect(selected.uiScale).toBe(bothThemes.uiScale);
    }
    expect(colorSchemes.mint.dark.accent).toBe("#9ab5a1");
  });
});
