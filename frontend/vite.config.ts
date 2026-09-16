import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

// Dev server proxies the (prefix-less) FastAPI endpoints to the backend so the
// browser always talks to the same origin during development.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/health": "http://localhost:8000",
      "/alerts": "http://localhost:8000",
      "/incidents": "http://localhost:8000",
      "/simulate": "http://localhost:8000",
      "/metrics": "http://localhost:8000",
      "/reports": "http://localhost:8000",
    },
  },
});