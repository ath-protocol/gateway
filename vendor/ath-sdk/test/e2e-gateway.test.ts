/**
 * E2E Test: ATHGatewayClient — self-contained, no external repo imports.
 *
 * Builds a gateway-like service using @ath-protocol/server handlers,
 * backed by the SDK's own mock OAuth server. Real HTTP, real PKCE.
 */
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { generateKeyPair } from "jose";
import { Hono } from "hono";
import { serve } from "@hono/node-server";
import type { ServerType } from "@hono/node-server";

import { ATHGatewayClient } from "../packages/client/src/gateway.js";
import { ATHClientError } from "../packages/client/src/errors.js";
import {
  createATHHandlers,
  InMemoryAgentRegistry,
  InMemoryTokenStore,
  InMemorySessionStore,
} from "../packages/server/src/index.js";
import { createMockOAuthServer } from "./mock-oauth-server.js";

const OAUTH_PORT = 18000;
const GATEWAY_PORT = 18001;
const OAUTH_URL = `http://localhost:${OAUTH_PORT}`;
const GATEWAY_URL = `http://localhost:${GATEWAY_PORT}`;
const CLIENT_ID = "ath-gw-test-client";
const CLIENT_SECRET = "ath-gw-test-secret";

let oauthServer: ServerType;
let gatewayServer: ServerType;

function buildGatewayService() {
  const app = new Hono();
  const registry = new InMemoryAgentRegistry();
  const tokenStore = new InMemoryTokenStore();
  const sessionStore = new InMemorySessionStore();

  const handlers = createATHHandlers({
    registry, tokenStore, sessionStore,
    config: {
      audience: GATEWAY_URL,
      callbackUrl: `${GATEWAY_URL}/ath/callback`,
      availableScopes: ["repo", "read:user", "user:email", "read:org"],
      appId: "github",
      skipAttestationVerification: true,
      oauth: {
        authorize_endpoint: `${OAUTH_URL}/authorize`,
        token_endpoint: `${OAUTH_URL}/token`,
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
      },
    },
  });

  app.get("/.well-known/ath.json", (c) => c.json({
    ath_version: "0.1",
    gateway_id: GATEWAY_URL,
    agent_registration_endpoint: `${GATEWAY_URL}/ath/agents/register`,
    supported_providers: [{
      provider_id: "github", display_name: "GitHub", categories: [],
      available_scopes: ["repo", "read:user", "user:email", "read:org"],
      auth_mode: "OAUTH2", agent_approval_required: true,
    }],
  }));
  app.get("/health", (c) => c.json({ status: "ok" }));

  app.post("/ath/agents/register", async (c) => {
    const r = await handlers.register({ method: "POST", path: "/ath/agents/register", headers: {}, body: await c.req.json() });
    return c.json(r.body, r.status as any);
  });
  app.post("/ath/authorize", async (c) => {
    const r = await handlers.authorize({ method: "POST", path: "/ath/authorize", headers: {}, body: await c.req.json() });
    return c.json(r.body, r.status as any);
  });
  app.get("/ath/callback", async (c) => {
    const query: Record<string, string> = {};
    for (const [k, v] of Object.entries(c.req.query())) { if (v) query[k] = v; }
    const r = await handlers.callback({ method: "GET", path: "/ath/callback", headers: {}, query, url: c.req.url });
    if (r.status === 302 && r.headers?.Location) return c.redirect(r.headers.Location);
    return c.json(r.body, r.status as any);
  });
  app.post("/ath/token", async (c) => {
    const r = await handlers.token({ method: "POST", path: "/ath/token", headers: {}, body: await c.req.json() });
    return c.json(r.body, r.status as any);
  });
  app.post("/ath/revoke", async (c) => {
    const r = await handlers.revoke({ method: "POST", path: "/ath/revoke", headers: {}, body: await c.req.json() });
    return c.json(r.body, r.status as any);
  });

  // Proxy endpoint — validates ATH token, then returns service responses.
  // In a real gateway, this would forward to an upstream provider using the stored
  // OAuth token. Here we validate the ATH token and serve mock responses.
  app.all("/ath/proxy/:provider/*", async (c) => {
    const authHeader = c.req.header("Authorization");
    if (!authHeader?.startsWith("Bearer ")) return c.json({ code: "TOKEN_INVALID", message: "Missing token" }, 401);
    const token = authHeader.slice(7);
    const bound = await tokenStore.get(token);
    if (!bound) return c.json({ code: "TOKEN_INVALID", message: "Invalid token" }, 401);
    if (bound.revoked) return c.json({ code: "TOKEN_REVOKED", message: "Token revoked" }, 401);
    const provider = c.req.param("provider");
    if (bound.provider_id !== provider) return c.json({ code: "PROVIDER_MISMATCH", message: "Token not for this provider" }, 403);
    const agentIdHeader = c.req.header("X-ATH-Agent-ID");
    if (agentIdHeader && agentIdHeader !== bound.agent_id) return c.json({ code: "AGENT_IDENTITY_MISMATCH", message: "Agent mismatch" }, 403);

    const path = c.req.path.replace(`/ath/proxy/${provider}`, "");
    if (path === "/userinfo") {
      return c.json({ login: "test-user", name: "Test User", email: "test@example.com" });
    }
    if (path === "/api/repos") {
      return c.json([{ id: 1, name: "ath-gateway", full_name: "test-user/ath-gateway" }]);
    }
    return c.json({ mock: true, provider, path });
  });

  return app;
}

describe("ATHGatewayClient E2E — self-contained, real HTTP", () => {
  let client: ATHGatewayClient;

  beforeAll(async () => {
    const oauthApp = createMockOAuthServer({ clientId: CLIENT_ID, clientSecret: CLIENT_SECRET, baseUrl: OAUTH_URL });
    oauthServer = serve({ fetch: oauthApp.fetch, port: OAUTH_PORT, hostname: "127.0.0.1" });
    gatewayServer = serve({ fetch: buildGatewayService().fetch, port: GATEWAY_PORT, hostname: "127.0.0.1" });

    for (let i = 0; i < 20; i++) {
      try {
        const [g, o] = await Promise.all([
          fetch(`${GATEWAY_URL}/health`).then(r => r.ok),
          fetch(`${OAUTH_URL}/health`).then(r => r.ok),
        ]);
        if (g && o) break;
      } catch { /* retry */ }
      await new Promise(r => setTimeout(r, 200));
    }

    const { privateKey } = await generateKeyPair("ES256");
    client = new ATHGatewayClient({ url: GATEWAY_URL, agentId: "https://gw-e2e.example.com/agent.json", privateKey });
  });

  afterAll(() => { gatewayServer?.close(); oauthServer?.close(); });

  it("discovers the gateway", async () => {
    const d = await client.discover();
    expect(d.ath_version).toBe("0.1");
    expect(d.supported_providers.some(p => p.provider_id === "github")).toBe(true);
  });

  it("registers the agent", async () => {
    const r = await client.register({
      developer: { name: "Test", id: "dev" },
      providers: [{ provider_id: "github", scopes: ["repo", "read:user"] }],
      purpose: "test",
    });
    expect(r.agent_status).toBe("approved");
    expect(r.approved_providers[0].approved_scopes).toContain("repo");
  });

  it("authorizes with PKCE + resource indicator", async () => {
    const a = await client.authorize("github", ["repo", "read:user"], { resource: "https://api.github.com" });
    expect(a.authorization_url).toContain("code_challenge=");
    expect(a.authorization_url).toContain("resource=");
    expect(a.ath_session_id).toBeTruthy();
  });

  it("completes full flow: authorize → consent → token → proxy → revoke", async () => {
    const auth = await client.authorize("github", ["repo"]);
    const url = new URL(auth.authorization_url);
    url.searchParams.set("auto_approve", "true");
    const r1 = await fetch(url.toString(), { redirect: "manual" });
    expect(r1.status).toBe(302);
    const r2 = await fetch(r1.headers.get("location")!, { redirect: "manual" });
    expect(r2.status).toBe(302);

    const tok = await client.exchangeToken("code", auth.ath_session_id);
    expect(tok.access_token).toMatch(/^ath_tk_/);
    expect(tok.effective_scopes).toContain("repo");

    const user = await client.proxy<{ login: string }>("github", "GET", "/userinfo");
    expect(user.login).toBe("test-user");

    await client.revoke();
  });

  it("rejects proxy to wrong provider", async () => {
    // Need a valid token first
    const auth = await client.authorize("github", ["repo"]);
    const url = new URL(auth.authorization_url);
    url.searchParams.set("auto_approve", "true");
    const r1 = await fetch(url.toString(), { redirect: "manual" });
    await fetch(r1.headers.get("location")!, { redirect: "manual" });
    await client.exchangeToken("code", auth.ath_session_id);

    try {
      await client.proxy("slack", "GET", "/channels");
      expect.unreachable();
    } catch (e) {
      expect((e as ATHClientError).code).toBe("PROVIDER_MISMATCH");
    }
  });

  it("rejects unapproved scope", async () => {
    try {
      await client.authorize("github", ["admin:org"]);
      expect.unreachable();
    } catch (e) {
      expect((e as ATHClientError).code).toBe("SCOPE_NOT_APPROVED");
    }
  });

  it("revoked token is rejected", async () => {
    const auth = await client.authorize("github", ["repo"]);
    const url = new URL(auth.authorization_url);
    url.searchParams.set("auto_approve", "true");
    const r1 = await fetch(url.toString(), { redirect: "manual" });
    await fetch(r1.headers.get("location")!, { redirect: "manual" });
    const tok = await client.exchangeToken("code", auth.ath_session_id);
    await client.revoke();
    client.setToken(tok.access_token);
    try {
      await client.proxy("github", "GET", "/userinfo");
      expect.unreachable();
    } catch (e) {
      expect((e as ATHClientError).code).toBe("TOKEN_REVOKED");
    }
  });
});
