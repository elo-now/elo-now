import { describe, expect, it } from "vitest";
import { hexToHsv, hsvToHex, normalizeHex } from "./color";
import { colorSchemes } from "./preferences";

describe("color picker conversions", () => {
  it("accepts complete hex colors without accepting partial or non-color text", () => {
    expect(normalizeHex(" #AbC ")).toBe("#aabbcc");
    expect(normalizeHex("C3E3CF")).toBe("#c3e3cf");
    for (const value of [
      "",
      "#",
      "12",
      "#1234",
      "#12345678",
      "#gggggg",
      "red",
    ]) {
      expect(normalizeHex(value)).toBeNull();
    }
  });
  it("covers all hue sectors and the shared red endpoint", () => {
    const colors = [
      "#ff0000",
      "#ffff00",
      "#00ff00",
      "#00ffff",
      "#0000ff",
      "#ff00ff",
    ];
    colors.forEach((hex, index) => {
      expect(hsvToHex({ h: index * 60, s: 1, v: 1 })).toBe(hex);
      expect(hexToHsv(hex)).toEqual({ h: index * 60, s: 1, v: 1 });
    });
    expect(hsvToHex({ h: 360, s: 1, v: 1 })).toBe("#ff0000");
  });
  it("preserves every scheme color and neutral colors through round trips", () => {
    const colors = ["#000000", "#ffffff", "#808080", "#010203", "#fefffe"];
    for (const scheme of Object.values(colorSchemes)) {
      colors.push(
        ...Object.values(scheme.light),
        ...Object.values(scheme.dark),
      );
    }
    for (const hex of colors) expect(hsvToHex(hexToHsv(hex))).toBe(hex);
    expect(hexToHsv("#000000")).toEqual({ h: 0, s: 0, v: 0 });
    expect(hexToHsv("#ffffff")).toEqual({ h: 0, s: 0, v: 1 });
  });
});
