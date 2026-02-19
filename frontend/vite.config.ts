import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import path from "path";
import tailwindcss from "@tailwindcss/vite";
import { visualizer } from "rollup-plugin-visualizer";

// https://vite.dev/config/
export default defineConfig({
  plugins: [react(), tailwindcss(), visualizer()],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
  build: {
    rollupOptions: {
      output: {
        manualChunks(id) {
          if (id.includes("node_modules")) {
            if (id.includes("/react")) {
              return "vendor-react";
            }

            if (id.includes("/@radix-ui")) {
              return "vendor-radix";
            }

            if (id.includes("/i18next")) {
              return "vendor-i18next";
            }

            if (id.includes("/zod")) {
              return "vendor-zod";
            }

            return "vendor";
          }
        },
      },
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
        rewrite: (path) => path.replace(/^\/\.well-known/, ""),
      },
    },
    allowedHosts: true,
  },
});
