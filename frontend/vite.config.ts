import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import path from "path";
import tailwindcss from "@tailwindcss/vite";

// https://vite.dev/config/
export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
  server: {
    host: "0.0.0.0",
    proxy: {
      "/api": {
        target: "http://tinyauth-backend:3000/api",
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/api/, ""),
      },
      "/resources": {
        target: "http://tinyauth-backend:3000/resources",
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/resources/, ""),
      },
      "/.well-known": {
        target: "http://tinyauth-backend:3000/.well-known",
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/.well-known/, ""),
      },
    },
    allowedHosts: true,
  },
});
