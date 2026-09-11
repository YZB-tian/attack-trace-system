import { defineConfig, loadEnv } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, ".", "API_PROXY_");
  return {
    plugins: [react()],
    server: {
      port: 5173,
      proxy: {
        "/api": env.API_PROXY_TARGET || "http://127.0.0.1:8000",
      },
    },
  };
});
