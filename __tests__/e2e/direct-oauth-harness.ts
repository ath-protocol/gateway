/**
 * E2E harness: gateway in direct OAuth mode against the standalone mock OAuth server only.
 * No gateway OAuth mock (/ui/mock-consent or fake callback codes).
 */
import { app as gatewayApp } from "../../src/app.js";
import { app as oauthApp } from "../../vendor/mock-oauth/server.js";
import { oauthBridge } from "../../src/oauth/client.js";
import { providerStore } from "../../src/providers/store.js";
import { serve } from "@hono/node-server";
import type { ServerType } from "@hono/node-server";

const DEFAULT_GATEWAY_PORT = 13110;
const DEFAULT_OAUTH_PORT = 14110;

export interface DirectOauthHarness {
  gatewayUrl: string;
  oauthUrl: string;
  /** Register agent redirect_uri for exact-match checks (must match authorize requests). */
  agentCallbackUrl: string;
  stop: () => Promise<void>;
}

/** Re-apply github provider after `resetProviders()` / clearCache (keeps gateway in direct OAuth mode). */
export function applyGithubDirectProvider(oauthUrl: string): void {
  providerStore.set("github", {
    display_name: "GitHub",
    available_scopes: ["repo", "read:user", "user:email", "read:org"],
    authorize_endpoint: `${oauthUrl}/authorize`,
    token_endpoint: `${oauthUrl}/token`,
    api_base_url: oauthUrl,
    client_id: "ath-gateway-client",
    client_secret: "ath-gateway-secret",
  });
}

let gatewayServer: ServerType | undefined;
let oauthServer: ServerType | undefined;

async function waitForOauthHealth(oauthUrl: string): Promise<void> {
  for (let i = 0; i < 30; i++) {
    try {
      if (await fetch(`${oauthUrl}/health`).then((r) => r.ok)) return;
    } catch {
      /* retry */
    }
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error("OAuth server did not become healthy in time");
}

async function waitForGatewayAndOauth(gatewayUrl: string, oauthUrl: string): Promise<void> {
  for (let i = 0; i < 30; i++) {
    try {
      const [gw, oauth] = await Promise.all([
        fetch(`${gatewayUrl}/health`).then((r) => r.ok),
        fetch(`${oauthUrl}/health`).then((r) => r.ok),
      ]);
      if (gw && oauth) return;
    } catch {
      /* retry */
    }
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error("Gateway or OAuth server did not become healthy in time");
}

/**
 * Complete browser consent by hitting the provider authorize URL with auto-approve,
 * then following the redirect back to the gateway /ath/callback using in-process `app.request`.
 */
export async function completeOAuthConsentViaProvider(
  authorizationUrl: string,
  appRequest: (method: string, path: string, body?: unknown, headers?: Record<string, string>) => Promise<Response>,
): Promise<{ code: string }> {
  const url = new URL(authorizationUrl);
  url.searchParams.set("auto_approve", "true");
  const res1 = await fetch(url.toString(), { redirect: "manual" });
  if (res1.status !== 302) {
    throw new Error(`Expected 302 from OAuth authorize, got ${res1.status}`);
  }
  const loc = res1.headers.get("location");
  if (!loc) throw new Error("Missing Location from OAuth authorize");
  const callbackUrl = new URL(loc);
  const code = callbackUrl.searchParams.get("code");
  if (!code) throw new Error("OAuth callback URL missing code parameter");

  const path = `${callbackUrl.pathname}${callbackUrl.search}`;
  const callbackRes = await appRequest("GET", path);
  if (callbackRes.status !== 302 && callbackRes.status !== 303) {
    throw new Error(`Expected redirect from /ath/callback, got ${callbackRes.status}`);
  }
  const final = callbackRes.headers.get("location") || "";
  if (!final.includes("success=true")) {
    throw new Error(`Expected success redirect, got: ${final}`);
  }
  return { code };
}

export async function startDirectOauthHarness(options?: {
  gatewayPort?: number;
  oauthPort?: number;
}): Promise<DirectOauthHarness> {
  const gatewayPort = options?.gatewayPort ?? DEFAULT_GATEWAY_PORT;
  const oauthPort = options?.oauthPort ?? DEFAULT_OAUTH_PORT;
  const gatewayUrl = `http://127.0.0.1:${gatewayPort}`;
  const oauthUrl = `http://127.0.0.1:${oauthPort}`;
  const agentCallbackUrl = `${gatewayUrl}/ath/callback`;
  const gatewayCallbackForOAuth = `${gatewayUrl}/ath/callback`;

  process.env.ATH_GATEWAY_HOST = gatewayUrl;

  oauthBridge.clearTokens();
  providerStore.clearCache();

  applyGithubDirectProvider(oauthUrl);

  oauthServer = serve({ fetch: oauthApp.fetch, port: oauthPort, hostname: "127.0.0.1" });
  await waitForOauthHealth(oauthUrl);

  const reg = await fetch(`${oauthUrl}/clients/redirect-uris`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      client_id: "ath-gateway-client",
      redirect_uri: gatewayCallbackForOAuth,
    }),
  });
  if (!reg.ok) {
    const text = await reg.text();
    oauthServer?.close();
    oauthServer = undefined;
    throw new Error(`OAuth redirect registration failed: ${reg.status} ${text}`);
  }

  gatewayServer = serve({ fetch: gatewayApp.fetch, port: gatewayPort, hostname: "127.0.0.1" });
  await waitForGatewayAndOauth(gatewayUrl, oauthUrl);

  return {
    gatewayUrl,
    oauthUrl,
    agentCallbackUrl,
    stop: async () => {
      await new Promise<void>((resolve) => {
        gatewayServer?.close(() => resolve());
      });
      await new Promise<void>((resolve) => {
        oauthServer?.close(() => resolve());
      });
      gatewayServer = undefined;
      oauthServer = undefined;
      providerStore.delete("github");
      providerStore.clearCache();
      oauthBridge.clearTokens();
    },
  };
}
