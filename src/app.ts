/**
 * ATH Gateway — Hono app setup.
 * Separated from server startup so the app can be imported for testing.
 */
import { Hono } from "hono";
import { cors } from "hono/cors";
import { registryRoutes } from "./registry/routes.js";
import { authRoutes } from "./auth/routes.js";
import { proxyRoutes } from "./proxy/routes.js";
import { discoveryRoutes } from "./discovery/routes.js";
import { providerRoutes } from "./providers/routes.js";
import { uiRoutes } from "./ui/routes.js";
import { userRoutes } from "./users/routes.js";
import { requireAuth, requireAdmin, optionalAuth } from "./users/middleware.js";
import { ATHError } from "./types.js";
import type { AppEnv } from "./types.js";

const app = new Hono<AppEnv>();

app.use("*", cors());

// Public routes (no auth required)
app.route("/.well-known", discoveryRoutes);
app.get("/health", (c) => c.json({ status: "ok", version: "0.1.0" }));
app.get("/", (c) => c.redirect("/ui/dashboard"));

// User auth routes — signup/login are public; /auth/me requires auth
app.use("/auth/me", requireAuth);
app.route("/auth", userRoutes);

// ATH protocol routes — require authentication
// The /ath/callback is public (browser redirect from OAuth provider)
app.use("/ath/agents/*", requireAuth);
app.use("/ath/authorize", requireAuth);
app.use("/ath/token", requireAuth);
app.use("/ath/revoke", requireAuth);
app.use("/ath/proxy/*", requireAuth);

// Provider admin — all endpoints require auth; write ops need admin
app.use("/ath/admin/providers", requireAuth);
app.use("/ath/admin/providers/*", requireAuth);
app.post("/ath/admin/providers", requireAdmin);
app.put("/ath/admin/providers/:id", requireAdmin);
app.delete("/ath/admin/providers/:id", requireAdmin);

app.route("/ath/agents", registryRoutes);
app.route("/ath", authRoutes);
app.route("/ath/proxy", proxyRoutes);
app.route("/ath/admin/providers", providerRoutes);

// UI — optional auth (shows login or dashboard based on state)
app.use("/ui/*", optionalAuth);
app.route("/ui", uiRoutes);

// Global error handler
app.onError((err, c) => {
  if (err instanceof ATHError) {
    return c.json(
      {
        code: err.code,
        message: err.message,
        ...(err.details ? { details: err.details } : {}),
      },
      err.status as 400,
    );
  }

  console.error("Unhandled error:", err);
  return c.json(
    { code: "INTERNAL_ERROR", message: "Internal server error" },
    500,
  );
});

export { app };
