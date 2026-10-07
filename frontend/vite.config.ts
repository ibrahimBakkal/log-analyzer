import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";

// `vite build --mode demo` builds the demo: the interface with the sample logs
// inside and no server to talk to. Everything goes into as few files as
// possible (scripts/inline-demo.mjs then folds them into one page), and all
// addresses are relative, so the page works from any folder of any host.
export default defineConfig(({ mode }) => ({
  plugins: [react(), tailwindcss()],
  base: mode === "demo" ? "./" : "/",
  build:
    mode === "demo"
      ? {
          outDir: "dist-demo",
          assetsInlineLimit: Number.MAX_SAFE_INTEGER, // fonts become part of the stylesheet
          cssCodeSplit: false,
          rollupOptions: { output: { inlineDynamicImports: true } },
        }
      : {},
  test: {
    include: ["src/**/*.test.ts"],
  },
}));
