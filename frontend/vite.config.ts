import { defineConfig } from "vite";

// En desarrollo, Vite reenvia /api y /ws al backend: el navegador ve un solo origen.
// 127.0.0.1 y no "localhost": en Windows, Node resuelve localhost a ::1 (IPv6) y uvicorn escucha en IPv4.
const backend = process.env.ARGOS_BACKEND ?? "http://127.0.0.1:8000";
const proxy = {
  "/api": backend,
  "/ws": { target: backend.replace(/^http/, "ws"), ws: true },
};

export default defineConfig({
  server: { port: 5173, proxy },
  preview: { port: 4173, proxy },
});
