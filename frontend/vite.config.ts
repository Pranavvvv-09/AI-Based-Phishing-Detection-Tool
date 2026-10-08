import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

// The build lands inside the Python package, so `python -m phishguard.web` serves it
// without Node. During development (`npm run dev`), API calls go to the running backend.
const backend = "http://127.0.0.1:5000";

export default defineConfig({
  base: "/static/app/",
  plugins: [react(), tailwindcss()],
  build: {
    outDir: "../src/phishguard/static/app",
    emptyOutDir: true,
    sourcemap: false,
  },
  server: {
    proxy: {
      "/api": backend,
      "/login": backend,
      "/logout": backend,
      "/scan": backend,
      "/static/favicon.svg": backend,
    },
  },
});
