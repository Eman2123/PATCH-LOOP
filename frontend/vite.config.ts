import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Dev: run the backend on :8000 and `npm run dev`; these paths are proxied (same paths Caddy proxies in prod).
const api = { target: "http://localhost:8000", changeOrigin: true };
export default defineConfig({
  plugins: [react()],
  server: {
    proxy: { "/health": api, "/loops": api, "/loop": api, "/eval": api, "/policy": api, "/replay": api, "/containment": api },
  },
  test: { environment: "node" },
});
