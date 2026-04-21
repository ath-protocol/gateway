/**
 * OAuth Bridge — handles all OAuth 2.0 communication with providers.
 *
 * The ATH gateway acts as an OAuth 2.0 client registered at each provider.
 * **Product requirement:** provider flows in `direct` mode MUST go through
 * `openid-client` (no parallel ad-hoc token endpoint `fetch` for code exchange),
 * so behavior stays RFC-aligned and maintainable.
 *
 * This module uses openid-client for:
 *   - Authorization Code (RFC 6749) with form-encoded token requests
 *   - PKCE (RFC 7636) — auto-generated S256
 *   - Resource Indicators (RFC 8707)
 *
 * Mock mode returns fake data for development without any real providers.
 */
import * as oidc from "openid-client";
import crypto from "node:crypto";
import { loadConfig } from "../config.js";
import { providerStore, type ProviderConfig } from "../providers/store.js";

export interface OAuthCallbackResult {
  connection_id: string;
  token: {
    access_token: string;
    refresh_token?: string;
    scope?: string;
  };
}

/** In-memory store for provider tokens */
const providerTokens = new Map<string, {
  access_token: string;
  refresh_token?: string;
  provider_id: string;
}>();

/** openid-client Configuration cache */
const oidcConfigCache = new Map<string, oidc.Configuration>();

function getOidcConfig(provider: ProviderConfig): oidc.Configuration {
  const cacheKey = `${provider.authorize_endpoint}|${provider.client_id}`;
  const cached = oidcConfigCache.get(cacheKey);
  if (cached) return cached;

  const config = new oidc.Configuration(
    {
      issuer: new URL(provider.authorize_endpoint).origin,
      authorization_endpoint: provider.authorize_endpoint,
      token_endpoint: provider.token_endpoint,
    } as oidc.ServerMetadata,
    provider.client_id,
    provider.client_secret,
  );

  if (provider.authorize_endpoint.startsWith("http://")) {
    oidc.allowInsecureRequests(config);
  }

  oidcConfigCache.set(cacheKey, config);
  return config;
}

export const oauthBridge = {
  async getAuthUrl(
    providerId: string,
    scopes: string[],
    callbackUrl: string,
    state: string,
    options?: { resource?: string },
  ): Promise<{ url: string; code_verifier?: string }> {
    const config = loadConfig();
    const provider = providerStore.get(providerId);

    if (config.oauthMode === "direct" && provider) {
      const oidcConfig = getOidcConfig(provider);
      const code_verifier = oidc.randomPKCECodeVerifier();
      const code_challenge = await oidc.calculatePKCECodeChallenge(code_verifier);

      const params: Record<string, string> = {
        redirect_uri: callbackUrl,
        scope: scopes.join(" "),
        state,
        code_challenge,
        code_challenge_method: "S256",
      };
      if (options?.resource) params.resource = options.resource;

      const authUrl = oidc.buildAuthorizationUrl(oidcConfig, params);
      return { url: authUrl.toString(), code_verifier };
    }

    // Mock mode
    const params = new URLSearchParams({
      provider: providerId,
      scopes: scopes.join(","),
      callback: callbackUrl,
      state,
    });
    if (options?.resource) params.set("resource", options.resource);
    return { url: `${config.gatewayUrl}/ui/mock-consent?${params.toString()}` };
  },

  /**
   * @param callbackUrl Full callback URL with ?code=...&state=...
   */
  async handleCallback(
    providerId: string,
    callbackUrl: string,
    options?: { code_verifier?: string; expected_state?: string },
  ): Promise<OAuthCallbackResult> {
    const config = loadConfig();
    const provider = providerStore.get(providerId);

    if (config.oauthMode === "direct" && provider) {
      const oidcConfig = getOidcConfig(provider);

      const tokens = await oidc.authorizationCodeGrant(
        oidcConfig,
        new URL(callbackUrl),
        {
          pkceCodeVerifier: options?.code_verifier,
          expectedState: options?.expected_state,
        },
      );

      const connectionId = `direct_${crypto.randomBytes(8).toString("hex")}`;
      providerTokens.set(connectionId, {
        access_token: tokens.access_token,
        refresh_token: tokens.refresh_token,
        provider_id: providerId,
      });

      return {
        connection_id: connectionId,
        token: {
          access_token: tokens.access_token,
          refresh_token: tokens.refresh_token,
          scope: tokens.scope,
        },
      };
    }

    // Mock mode — callbackUrl may be absolute or scheme-relative
    const url = callbackUrl.startsWith("http")
      ? new URL(callbackUrl)
      : new URL(callbackUrl, "http://localhost");
    const code = url.searchParams.get("code") || "mock";
    return {
      connection_id: `mock_conn_${code}`,
      token: { access_token: `mock_token_${code}` },
    };
  },

  async proxy(
    providerId: string,
    connectionId: string,
    method: string,
    path: string,
    body?: unknown,
  ): Promise<{ status: number; headers: Record<string, string>; body: unknown }> {
    const config = loadConfig();
    const provider = providerStore.get(providerId);

    if (config.oauthMode === "direct" && provider) {
      const stored = providerTokens.get(connectionId);
      if (!stored) {
        return { status: 401, headers: {}, body: { error: "No token for this connection" } };
      }

      const apiBase = provider.api_base_url || new URL(provider.authorize_endpoint).origin;

      try {
        const res = await fetch(`${apiBase}${path}`, {
          method,
          headers: {
            Authorization: `Bearer ${stored.access_token}`,
            "Content-Type": "application/json",
          },
          body: body ? JSON.stringify(body) : undefined,
        });

        const responseBody = await res.json().catch(() => res.text());
        const responseHeaders: Record<string, string> = {};
        res.headers.forEach((v, k) => { responseHeaders[k] = v; });
        return { status: res.status, headers: responseHeaders, body: responseBody };
      } catch (err) {
        return {
          status: 502, headers: {},
          body: { error: "Proxy failed", message: err instanceof Error ? err.message : String(err) },
        };
      }
    }

    // Mock mode
    return {
      status: 200,
      headers: { "content-type": "application/json" },
      body: { mock: true, provider: providerId, path, message: "Mock response. Configure providers for real API calls." },
    };
  },

  async listProviders(): Promise<{ provider_id: string; display_name: string; auth_mode: string }[]> {
    const configured = providerStore.getAll();
    if (Object.keys(configured).length > 0) {
      return Object.entries(configured).map(([id, p]) => ({
        provider_id: id,
        display_name: p.display_name,
        auth_mode: "OAUTH2",
      }));
    }

    return [
      { provider_id: "github", display_name: "GitHub", auth_mode: "OAUTH2" },
      { provider_id: "google-mail", display_name: "Google Mail", auth_mode: "OAUTH2" },
      { provider_id: "slack", display_name: "Slack", auth_mode: "OAUTH2" },
      { provider_id: "google-calendar", display_name: "Google Calendar", auth_mode: "OAUTH2" },
    ];
  },

  clearTokens(): void {
    providerTokens.clear();
    oidcConfigCache.clear();
  },
};
