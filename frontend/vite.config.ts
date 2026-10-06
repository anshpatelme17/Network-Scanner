import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    // Loopback-only: the dev server serves the local browser and proxies
    // /api to localhost:8000. Never bind 0.0.0.0 here — that exposes the
    // dev server (with HMR websocket) to the LAN and triggers firewall
    // prompts. Container serving is handled by nginx, not vite.
    host: "127.0.0.1",
    proxy: {
      "/api": {
        target: process.env.VITE_API_URL ?? "http://localhost:8000",
        changeOrigin: true,
      },
    },
  },
  preview: { port: 5173 },
  test: {
    environment: "jsdom",
    globals: true,
    setupFiles: ["./src/setupTests.ts"],
  },
});
