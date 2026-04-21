/**
 * Provider store — manages platform OAuth connections.
 *
 * Each provider represents a platform (GitHub, Tencent Docs, etc.)
 * that agents can be approved to access through the ATH gateway.
 *
 * The gateway acts as an OAuth 2.0 client registered at each provider.
 * ATH's trusted handshake adds the agent approval layer on top:
 *   - available_scopes controls what agents CAN be approved for (app-side)
 *   - OAuth endpoints handle user consent (user-side)
 */
import fs from "node:fs";
import path from "node:path";

export interface ProviderConfig {
  display_name: string;
  /** Scopes agents can be approved for on this platform (app-side authorization) */
  available_scopes: string[];
  /** OAuth 2.0 authorization endpoint */
  authorize_endpoint: string;
  /** OAuth 2.0 token endpoint */
  token_endpoint: string;
  /** API base URL for proxied requests (often different from OAuth endpoints) */
  api_base_url?: string;
  /** Gateway's OAuth client_id registered at this provider */
  client_id: string;
  /** Gateway's OAuth client_secret registered at this provider */
  client_secret: string;
}

const CONFIG_DIR = process.env.ATH_CONFIG_DIR || process.cwd();
const CONFIG_FILE = path.join(CONFIG_DIR, "providers.json");

let cache: Record<string, ProviderConfig> | null = null;

function readFile(): Record<string, ProviderConfig> {
  try {
    const data = fs.readFileSync(CONFIG_FILE, "utf-8");
    return JSON.parse(data) as Record<string, ProviderConfig>;
  } catch {
    return {};
  }
}

function readEnv(): Record<string, ProviderConfig> {
  const raw = process.env.ATH_PROVIDERS;
  if (!raw) return {};
  try {
    return JSON.parse(raw) as Record<string, ProviderConfig>;
  } catch {
    return {};
  }
}

function readLegacyEnv(): Record<string, ProviderConfig> {
  const baseUrl = process.env.OAUTH_BASE_URL;
  if (!baseUrl) return {};
  return {
    _default: {
      display_name: "OAuth Provider",
      available_scopes: [],
      authorize_endpoint: `${baseUrl}/authorize`,
      token_endpoint: `${baseUrl}/token`,
      client_id: process.env.OAUTH_CLIENT_ID || "ath-gateway-client",
      client_secret: process.env.OAUTH_CLIENT_SECRET || "ath-gateway-secret",
    },
  };
}

function load(): Record<string, ProviderConfig> {
  if (cache) return cache;
  const fromFile = readFile();
  if (Object.keys(fromFile).length > 0) { cache = fromFile; return cache; }
  const fromEnv = readEnv();
  if (Object.keys(fromEnv).length > 0) { cache = fromEnv; return cache; }
  cache = readLegacyEnv();
  return cache;
}

function save(providers: Record<string, ProviderConfig>): void {
  fs.writeFileSync(CONFIG_FILE, JSON.stringify(providers, null, 2), "utf-8");
  cache = providers;
}

export const providerStore = {
  getAll(): Record<string, ProviderConfig> {
    return { ...load() };
  },

  get(providerId: string): ProviderConfig | null {
    return load()[providerId] || null;
  },

  hasProviders(): boolean {
    return Object.keys(load()).length > 0;
  },

  set(providerId: string, config: ProviderConfig): void {
    const all = load();
    all[providerId] = config;
    save(all);
  },

  delete(providerId: string): boolean {
    const all = load();
    if (!all[providerId]) return false;
    delete all[providerId];
    save(all);
    return true;
  },

  clearCache(): void {
    cache = null;
  },
};
