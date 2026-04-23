/**
 * Gateway configuration — settings for the ATH gateway itself.
 * Provider configurations are managed by the provider store (providers/store.ts).
 */
import crypto from "node:crypto";
import { providerStore } from "./providers/store.js";

export interface GatewayConfig {
  port: number;
  host: string;
  gatewayUrl: string;
  /**
   * Base URL used in agent attestation JWT `aud` checks (authorize + token).
   * Defaults to `gatewayUrl`. Set `ATH_PUBLIC_GATEWAY_URL` when the gateway is
   * reached on a different host than OAuth redirect_uri (e.g. tests).
   */
  publicGatewayUrl: string;
  gatewaySecret: string;
  tokenExpirySeconds: number;
  sessionExpirySeconds: number;
  oauthMode: "direct" | "mock";
  signupEnabled: boolean;
  jwtSecret: string;
  sessionTokenTtl: number;
}

let generatedGatewaySecret: string | null = null;
let generatedJwtSecret: string | null = null;

function ensureSecret(envKey: string, generated: string | null): { value: string; wasGenerated: boolean } {
  const fromEnv = process.env[envKey];
  if (fromEnv) return { value: fromEnv, wasGenerated: false };
  if (!generated) generated = crypto.randomBytes(32).toString("hex");
  return { value: generated, wasGenerated: true };
}

export function loadConfig(): GatewayConfig {
  const hasProviders = providerStore.hasProviders();
  const hasLegacyOAuth = !!process.env.OAUTH_BASE_URL;

  const gw = ensureSecret("ATH_GATEWAY_SECRET", generatedGatewaySecret);
  generatedGatewaySecret = gw.value;

  const jwt = ensureSecret("ATH_JWT_SECRET", generatedJwtSecret);
  generatedJwtSecret = jwt.value;

  if (gw.wasGenerated || jwt.wasGenerated) {
    const missing = [gw.wasGenerated && "ATH_GATEWAY_SECRET", jwt.wasGenerated && "ATH_JWT_SECRET"].filter(Boolean);
    console.warn(`[config] ${missing.join(", ")} not set — using random ephemeral secret(s). Set in production.`);
  }

  const gatewayUrl = process.env.ATH_GATEWAY_HOST || "http://localhost:3000";
  return {
    port: parseInt(process.env.ATH_PORT || "3000", 10),
    host: process.env.ATH_HOST || "0.0.0.0",
    gatewayUrl,
    publicGatewayUrl: process.env.ATH_PUBLIC_GATEWAY_URL || gatewayUrl,
    gatewaySecret: gw.value,
    tokenExpirySeconds: parseInt(process.env.ATH_TOKEN_EXPIRY || "3600", 10),
    sessionExpirySeconds: parseInt(process.env.ATH_SESSION_EXPIRY || "600", 10),
    oauthMode: (hasProviders || hasLegacyOAuth) ? "direct" : "mock",
    signupEnabled: process.env.ATH_SIGNUP_ENABLED === "true",
    jwtSecret: jwt.value,
    sessionTokenTtl: parseInt(process.env.ATH_SESSION_TOKEN_TTL || "86400", 10),
  };
}
