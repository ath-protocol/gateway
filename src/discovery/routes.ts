/**
 * Discovery routes — serves .well-known/ath.json
 */
import { Hono } from "hono";
import { oauthBridge } from "../oauth/client.js";
import { getAvailableProviders } from "../registry/policy.js";
import { loadConfig } from "../config.js";
import type { DiscoveryDocument } from "../types.js";

export const discoveryRoutes = new Hono();

let cachedDiscovery: DiscoveryDocument | null = null;
let cacheExpiry = 0;
const CACHE_TTL_MS = 5 * 60 * 1000;

discoveryRoutes.get("/ath.json", async (c) => {
  const now = Date.now();
  if (cachedDiscovery && now < cacheExpiry) {
    return c.json(cachedDiscovery);
  }

  const config = loadConfig();
  const providers = await oauthBridge.listProviders();
  const policyProviders = getAvailableProviders();

  const discovery: DiscoveryDocument = {
    ath_version: "0.1",
    gateway_id: config.gatewayUrl,
    agent_registration_endpoint: `${config.gatewayUrl}/ath/agents/register`,
    supported_providers: providers.map((p) => ({
      provider_id: p.provider_id,
      display_name: p.display_name,
      categories: [],
      available_scopes: policyProviders[p.provider_id] || [],
      auth_mode: p.auth_mode,
      agent_approval_required: true,
    })),
  };

  cachedDiscovery = discovery;
  cacheExpiry = now + CACHE_TTL_MS;

  return c.json(discovery);
});
