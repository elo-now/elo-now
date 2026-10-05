import { defineConfig } from "vite";

export default defineConfig({
  build: {
    // Keep the Vite 7 browser baseline when upgrading the bundler.
    target: ["chrome107", "edge107", "firefox104", "safari16"],
  },
});
