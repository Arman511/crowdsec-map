import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";
import compression from "vite-plugin-compression2";

export default defineConfig({
  base: "./",
  plugins: [react(), compression({ algorithms: ["brotliCompress"] })],
  server: {
    port: 5173,
    proxy: {
      "/api": "http://127.0.0.1:8088",
    },
  },
  preview: {
    port: 4173,
  },
});
