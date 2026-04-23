/**
 * E2E Test: Full ATH protocol flow with real OAuth server.
 * Tests require user authentication before any ATH operations.
 */
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { app as gatewayApp } from "../../src/app.js";
import { app as oauthApp } from "../../vendor/mock-oauth/server.js";
import { agentStore } from "../../src/registry/agent-store.js";
import { tokenStore } from "../../src/auth/token.js";
import { sessionStore } from "../../src/auth/session-store.js";
import { oauthBridge } from "../../src/oauth/client.js";
import { providerStore } from "../../src/providers/store.js";
import { userStore } from "../../src/users/store.js";
import { createSessionToken } from "../../src/users/middleware.js";
import * as jose from "jose";
import crypto from "node:crypto";
import { serve } from "@hono/node-server";
import type { ServerType } from "@hono/node-server";
import { clearJtiReplayStore } from "../../src/auth/jti-replay.js";

let gatewayServer: ServerType;
let oauthServer: ServerType;
const GATEWAY_PORT = 13000;
const OAUTH_PORT = 14000;
const GATEWAY_URL = `http://localhost:${GATEWAY_PORT}`;
const OAUTH_URL = `http://localhost:${OAUTH_PORT}`;

let authToken: string;

async function generateAttestation(agentId: string, audience?: string): Promise<string> {
  const { privateKey } = await jose.generateKeyPair("ES256");
  return new jose.SignJWT({ capabilities: [] })
    .setProtectedHeader({ alg: "ES256", kid: "test-key" })
    .setIssuer(agentId)
    .setSubject(agentId)
    .setAudience(audience ?? GATEWAY_URL)
    .setJti(crypto.randomUUID())
    .setIssuedAt()
    .setExpirationTime("1h")
    .sign(privateKey);
}

async function jsonReq(method: string, url: string, body?: unknown, headers?: Record<string, string>) {
  const init: RequestInit = {
    method,
    headers: {
      "Content-Type": "application/json",
      ...(authToken ? { "X-ATH-User-Token": authToken } : {}),
      ...headers,
    },
  };
  if (body) init.body = JSON.stringify(body);
  return fetch(url, init);
}

describe("E2E with Real OAuth Server", () => {
  beforeAll(async () => {
    process.env.ATH_GATEWAY_HOST = GATEWAY_URL;

    agentStore.clear();
    tokenStore.clear();
    sessionStore.clear();
    clearJtiReplayStore();
    oauthBridge.clearTokens();
    providerStore.clearCache();
    userStore.clear();

    // Create a test user and get auth token
    const user = await userStore.create("e2e-user", "e2e-pass", "admin");
    authToken = await createSessionToken(user.id, user.role);

    providerStore.set("github", {
      display_name: "GitHub",
      available_scopes: ["repo", "read:user", "user:email", "read:org"],
      authorize_endpoint: `${OAUTH_URL}/authorize`,
      token_endpoint: `${OAUTH_URL}/token`,
      api_base_url: OAUTH_URL,
      client_id: "ath-gateway-client",
      client_secret: "ath-gateway-secret",
    });

    oauthServer = serve({ fetch: oauthApp.fetch, port: OAUTH_PORT, hostname: "127.0.0.1" });
    gatewayServer = serve({ fetch: gatewayApp.fetch, port: GATEWAY_PORT, hostname: "127.0.0.1" });

    for (let i = 0; i < 20; i++) {
      try {
        const [gw, oauth] = await Promise.all([
          fetch(`${GATEWAY_URL}/health`).then((r) => r.ok),
          fetch(`${OAUTH_URL}/health`).then((r) => r.ok),
        ]);
        if (gw && oauth) break;
      } catch { /* retry */ }
      await new Promise((r) => setTimeout(r, 200));
    }
  });

  afterAll(async () => {
    gatewayServer?.close();
    oauthServer?.close();
    agentStore.clear();
    tokenStore.clear();
    sessionStore.clear();
    oauthBridge.clearTokens();
    providerStore.delete("github");
    providerStore.clearCache();
    userStore.clear();
  });

  const agentId = "https://e2e-real-oauth-agent.example.com/.well-known/agent.json";
  let clientId: string;
  let clientSecret: string;
  let sessionId: string;
  let authorizationUrl: string;
  let accessToken: string;

  it("1. Mock OAuth server is healthy", async () => {
    const res = await fetch(`${OAUTH_URL}/health`);
    expect(res.status).toBe(200);
    const data = await res.json() as any;
    expect(data.provider).toBe("mock-oauth");
  });

  it("2. Mock OAuth server metadata is correct", async () => {
    const res = await fetch(`${OAUTH_URL}/.well-known/oauth-authorization-server`);
    expect(res.status).toBe(200);
    const data = await res.json() as any;
    expect(data.authorization_endpoint).toContain("/authorize");
    expect(data.token_endpoint).toContain("/token");
    expect(data.scopes_supported).toContain("repo");
  });

  it("3. ATH Gateway is healthy and in direct OAuth mode", async () => {
    const res = await fetch(`${GATEWAY_URL}/health`);
    expect(res.status).toBe(200);
  });

  it("4. Agent registers with ATH gateway", async () => {
    const attestation = await generateAttestation(agentId);
    const res = await jsonReq("POST", `${GATEWAY_URL}/ath/agents/register`, {
      agent_id: agentId,
      agent_attestation: attestation,
      developer: { name: "E2E Real OAuth Test", id: "dev-e2e-real" },
      requested_providers: [{ provider_id: "github", scopes: ["repo", "read:user"] }],
      purpose: "E2E test with real OAuth server",
      redirect_uris: [`${GATEWAY_URL}/ath/callback`],
    });
    expect(res.status).toBe(201);
    const data = await res.json() as any;
    expect(data.agent_status).toBe("approved");
    expect(data.approved_providers[0].approved_scopes).toContain("repo");
    clientId = data.client_id;
    clientSecret = data.client_secret;
  });

  it("5. Agent initiates authorization — gets real OAuth URL with PKCE", async () => {
    const attestation = await generateAttestation(agentId);
    const res = await jsonReq("POST", `${GATEWAY_URL}/ath/authorize`, {
      client_id: clientId,
      agent_attestation: attestation,
      provider_id: "github",
      scopes: ["repo", "read:user"],
      user_redirect_uri: `${GATEWAY_URL}/ath/callback`,
      state: "e2e-real-test",
      resource: "https://api.example.com",
    });
    expect(res.status).toBe(200);
    const data = await res.json() as any;
    expect(data.authorization_url).toContain(OAUTH_URL);
    expect(data.authorization_url).toContain("/authorize");
    expect(data.authorization_url).toContain("response_type=code");
    expect(data.authorization_url).toContain("code_challenge=");
    expect(data.authorization_url).toContain("code_challenge_method=S256");
    expect(data.authorization_url).toContain("resource=");
    authorizationUrl = data.authorization_url;
    sessionId = data.ath_session_id;
  });

  it("6. User visits OAuth authorize endpoint — auto-approve mode", async () => {
    const url = new URL(authorizationUrl);
    url.searchParams.set("auto_approve", "true");

    const res = await fetch(url.toString(), { redirect: "manual" });
    expect(res.status).toBe(302);

    const oauthRedirect = res.headers.get("location")!;
    expect(oauthRedirect).toContain("/ath/callback");
    expect(oauthRedirect).toContain("code=");

    const callbackRes = await fetch(oauthRedirect, { redirect: "manual" });
    expect(callbackRes.status).toBe(302);
    const finalRedirect = callbackRes.headers.get("location")!;
    expect(finalRedirect).toContain("success=true");
  });

  it("7. Agent exchanges code for ATH token — real OAuth token exchange happens", async () => {
    const tokenAttestation = await generateAttestation(agentId, `${GATEWAY_URL}/ath/token`);
    const res = await jsonReq("POST", `${GATEWAY_URL}/ath/token`, {
      grant_type: "authorization_code",
      client_id: clientId,
      client_secret: clientSecret,
      agent_attestation: tokenAttestation,
      code: "real_oauth_exchange",
      ath_session_id: sessionId,
    });
    expect(res.status).toBe(200);
    const data = await res.json() as any;
    expect(data.access_token).toBeTruthy();
    expect(data.token_type).toBe("Bearer");
    expect(data.effective_scopes).toContain("repo");
    expect(data.effective_scopes).toContain("read:user");
    expect(data.scope_intersection.agent_approved).toContain("repo");
    expect(data.scope_intersection.effective).toContain("repo");
    accessToken = data.access_token;
  });

  it("8. Agent calls proxy — request reaches real mock OAuth server's /userinfo", async () => {
    const res = await jsonReq("GET", `${GATEWAY_URL}/ath/proxy/github/userinfo`, undefined, {
      Authorization: `Bearer ${accessToken}`,
      "X-ATH-Agent-ID": agentId,
    });
    expect(res.status).toBe(200);
    const data = await res.json() as any;
    expect(data.login).toBe("test-user");
    expect(data.name).toBe("Test User");
    expect(data.email).toBe("test@example.com");
  });

  it("9. Agent calls proxy — /api/repos requires 'repo' scope and returns real data", async () => {
    const res = await jsonReq("GET", `${GATEWAY_URL}/ath/proxy/github/api/repos`, undefined, {
      Authorization: `Bearer ${accessToken}`,
      "X-ATH-Agent-ID": agentId,
    });
    expect(res.status).toBe(200);
    const data = await res.json() as any;
    expect(Array.isArray(data)).toBe(true);
    expect(data[0].name).toBe("ath-gateway");
    expect(data[0].full_name).toBe("test-user/ath-gateway");
  });

  it("10. Mock OAuth server metadata includes PKCE support", async () => {
    const res = await fetch(`${OAUTH_URL}/.well-known/oauth-authorization-server`);
    expect(res.status).toBe(200);
    const data = await res.json() as any;
    expect(data.code_challenge_methods_supported).toContain("S256");
    expect(data.code_challenge_methods_supported).toContain("plain");
  });

  it("11. Token revocation works — subsequent proxy calls fail", async () => {
    const revokeRes = await jsonReq("POST", `${GATEWAY_URL}/ath/revoke`, {
      client_id: clientId,
      client_secret: clientSecret,
      token: accessToken,
    });
    expect(revokeRes.status).toBe(200);

    const proxyRes = await jsonReq("GET", `${GATEWAY_URL}/ath/proxy/github/userinfo`, undefined, {
      Authorization: `Bearer ${accessToken}`,
      "X-ATH-Agent-ID": agentId,
    });
    expect(proxyRes.status).toBe(401);
    const data = await proxyRes.json() as any;
    expect(data.code).toBe("TOKEN_REVOKED");
  });
});
