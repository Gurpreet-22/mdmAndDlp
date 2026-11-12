import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

/**
 * The dev server proxies /api and /healthz to the backend rather than having the
 * browser call it directly.
 *
 * That is not just convenience. The refresh token is an httpOnly cookie with
 * SameSite=Strict, so it is only sent on same-origin requests. Talking to
 * http://127.0.0.1:8000 from an app served on :5173 would be cross-origin, the
 * cookie would never be sent, and session refresh would silently never work.
 * Proxying keeps everything same-origin, which is also how it will be deployed:
 * nginx serving the built assets and the API under one origin.
 */
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    strictPort: true,
    proxy: {
      "/api": {
        target: "http://127.0.0.1:8000",
        changeOrigin: false,
      },
      "/healthz": { target: "http://127.0.0.1:8000" },
      "/readyz": { target: "http://127.0.0.1:8000" },
    },
  },
  build: {
    outDir: "dist",
    sourcemap: true,
  },
});
