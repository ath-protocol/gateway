/**
 * Provider admin routes — CRUD for OAuth provider configurations.
 * Read: any authenticated user. Write: admin only (enforced via middleware in app.ts).
 */
import { Hono } from "hono";
import { providerStore, type ProviderConfig } from "./store.js";

export const providerRoutes = new Hono();

// GET /ath/admin/providers — List all providers (secrets masked)
providerRoutes.get("/", (c) => {
  const providers = providerStore.getAll();
  const safe = Object.fromEntries(
    Object.entries(providers).map(([id, p]) => [id, {
      ...p,
      client_secret: p.client_secret ? "••••••" : "",
    }]),
  );
  return c.json(safe);
});

// POST /ath/admin/providers — Add a provider (admin only via middleware)
providerRoutes.post("/", async (c) => {
  const body = await c.req.json() as { provider_id: string } & ProviderConfig;
  const { provider_id, ...config } = body;

  if (!provider_id || !config.authorize_endpoint || !config.token_endpoint || !config.client_id) {
    return c.json({ error: "Missing required fields: provider_id, authorize_endpoint, token_endpoint, client_id" }, 400);
  }

  providerStore.set(provider_id, config);
  return c.json({ message: "Provider added", provider_id }, 201);
});

// PUT /ath/admin/providers/:id — Update a provider
providerRoutes.put("/:id", async (c) => {
  const providerId = c.req.param("id");
  const existing = providerStore.get(providerId);
  if (!existing) return c.json({ error: "Provider not found" }, 404);

  const updates = await c.req.json() as Partial<ProviderConfig>;
  providerStore.set(providerId, { ...existing, ...updates });
  return c.json({ message: "Provider updated", provider_id: providerId });
});

// DELETE /ath/admin/providers/:id — Remove a provider
providerRoutes.delete("/:id", (c) => {
  const providerId = c.req.param("id");
  if (!providerStore.delete(providerId)) {
    return c.json({ error: "Provider not found" }, 404);
  }
  return c.json({ message: "Provider removed", provider_id: providerId });
});
