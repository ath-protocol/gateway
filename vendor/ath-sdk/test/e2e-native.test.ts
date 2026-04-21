/**
 * E2E Test: ATHNativeClient against a native ATH service.
 *
 * Starts:
 *  - Mock OAuth2 server on port 16000 (real PKCE, real token exchange)
 *  - Native ATH service on port 16001 (built with @ath-protocol/server handlers)
 *
 * Full coverage: discover → register → authorize → consent → token → api → revoke + errors.
 * No mock fetch — real HTTP only.
 */
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { generateKeyPair } from "jose";
import { Hono } from "hono";
import { serve } from "@hono/node-server";
import type { ServerType } from "@hono/node-server";

import { ATHNativeClient } from "../packages/client/src/native.js";
import { ATHClientError } from "../packages/client/src/errors.js";

import {
  createATHHandlers,
  createServiceDiscoveryDocument,
  InMemoryAgentRegistry,
  InMemoryTokenStore,
  InMemorySessionStore,
} from "../packages/server/src/index.js";

import { createMockOAuthServer } from "./mock-oauth-server.js";

const OAUTH_PORT = 16000;
const SERVICE_PORT = 16001;
const OAUTH_URL = `http://localhost:${OAUTH_PORT}`;
const SERVICE_URL = `http://localhost:${SERVICE_PORT}`;
const APP_ID = "com.test.native-service";

let oauthServer: ServerType;
let serviceServer: ServerType;

function buildNativeService() {
  const app = new Hono();
  const registry = new InMemoryAgentRegistry();
  const tokenStore = new InMemoryTokenStore();
  const sessionStore = new InMemorySessionStore();

  const handlers = createATHHandlers({
    registry,
    tokenStore,
    sessionStore,
    config: {
      audience: SERVICE_URL,
      callbackUrl: `${SERVICE_URL}/ath/callback`,
      availableScopes: ["mail:read", "mail:send", "mail:delete"],
      appId: APP_ID,
      tokenExpirySeconds: 3600,
      sessionExpirySeconds: 600,
      skipAttestationVerification: true,
      oauth: {
        authorize_endpoint: `${OAUTH_URL}/authorize`,
        token_endpoint: `${OAUTH_URL}/token`,
        client_id: "ath-gateway-client",
        client_secret: "ath-gateway-secret",
      },
    },
  });

  const discoveryDoc = createServiceDiscoveryDocument({
    app_id: APP_ID,
    name: "Test Native Mail Service",
    authorization_endpoint: `${OAUTH_URL}/authorize`,
    token_endpoint: `${OAUTH_URL}/token`,
    scopes_supported: ["mail:read", "mail:send", "mail:delete"],
    api_base: `${SERVICE_URL}/api`,
  });

  app.get("/.well-known/ath-app.json", (c) => c.json(discoveryDoc));
  app.get("/health", (c) => c.json({ status: "ok" }));

  app.post("/ath/agents/register", async (c) => {
    const res = await handlers.register({
      method: "POST", path: "/ath/agents/register",
      headers: {}, body: await c.req.json(),
    });
    return c.json(res.body, res.status as any);
  });

  app.post("/ath/authorize", async (c) => {
    const res = await handlers.authorize({
      method: "POST", path: "/ath/authorize",
      headers: {}, body: await c.req.json(),
    });
    return c.json(res.body, res.status as any);
  });

  app.get("/ath/callback", async (c) => {
    const query: Record<string, string> = {};
    for (const [k, v] of Object.entries(c.req.query())) {
      if (v) query[k] = v;
    }
    const res = await handlers.callback({
      method: "GET", path: "/ath/callback",
      headers: {}, query, url: c.req.url,
    });
    if (res.status === 302 && res.headers?.Location) {
      return c.redirect(res.headers.Location);
    }
    return c.json(res.body, res.status as any);
  });

  app.post("/ath/token", async (c) => {
    const res = await handlers.token({
      method: "POST", path: "/ath/token",
      headers: {}, body: await c.req.json(),
    });
    return c.json(res.body, res.status as any);
  });

  app.post("/ath/revoke", async (c) => {
    const res = await handlers.revoke({
      method: "POST", path: "/ath/revoke",
      headers: {}, body: await c.req.json(),
    });
    return c.json(res.body, res.status as any);
  });

  // Native API endpoints (the service's own business logic)
  app.get("/api/v1/messages", async (c) => {
    const authHeader = c.req.header("Authorization");
    if (!authHeader?.startsWith("Bearer ")) {
      return c.json({ error: "Unauthorized" }, 401);
    }
    const token = authHeader.slice(7);
    const bound = await tokenStore.get(token);
    if (!bound) return c.json({ error: "Invalid token" }, 401);
    if (bound.revoked) return c.json({ code: "TOKEN_REVOKED", message: "Token revoked" }, 401);

    return c.json([
      { id: 1, subject: "Flight confirmation", from: "airline@example.com" },
      { id: 2, subject: "Hotel booking", from: "hotel@example.com" },
    ]);
  });

  app.get("/api/v1/profile", async (c) => {
    const authHeader = c.req.header("Authorization");
    if (!authHeader?.startsWith("Bearer ")) {
      return c.json({ error: "Unauthorized" }, 401);
    }
    return c.json({ name: "Alice", email: "alice@example.com" });
  });

  return app;
}

describe("ATHNativeClient E2E — real HTTP, real OAuth (no mock)", () => {
  let client: ATHNativeClient;

  beforeAll(async () => {
    const oauthApp = createMockOAuthServer({ clientId: "ath-gateway-client", clientSecret: "ath-gateway-secret", baseUrl: OAUTH_URL });
    oauthServer = serve({ fetch: oauthApp.fetch, port: OAUTH_PORT, hostname: "127.0.0.1" });
    const nativeApp = buildNativeService();
    serviceServer = serve({ fetch: nativeApp.fetch, port: SERVICE_PORT, hostname: "127.0.0.1" });

    for (let i = 0; i < 20; i++) {
      try {
        const [s, o] = await Promise.all([
          fetch(`${SERVICE_URL}/health`).then((r) => r.ok),
          fetch(`${OAUTH_URL}/health`).then((r) => r.ok),
        ]);
        if (s && o) break;
      } catch { /* retry */ }
      await new Promise((r) => setTimeout(r, 200));
    }

    const { privateKey } = await generateKeyPair("ES256");
    client = new ATHNativeClient({
      url: SERVICE_URL,
      agentId: "https://native-test-agent.example.com/.well-known/agent.json",
      privateKey,
      keyId: "native-test-key",
    });
  });

  afterAll(() => {
    serviceServer?.close();
    oauthServer?.close();
  });

  // ── Discovery ──

  it("discovers the native service via /.well-known/ath-app.json", async () => {
    const doc = await client.discover();
    expect(doc.ath_version).toBe("0.1");
    expect(doc.app_id).toBe(APP_ID);
    expect(doc.name).toBe("Test Native Mail Service");
    expect(doc.auth.type).toBe("oauth2");
    expect(doc.auth.scopes_supported).toContain("mail:read");
    expect(doc.api_base).toBe(`${SERVICE_URL}/api`);
  });

  // ── Registration ──

  it("registers the agent with the native service", async () => {
    const reg = await client.register({
      developer: { name: "Native Test", id: "dev-native" },
      providers: [{ provider_id: APP_ID, scopes: ["mail:read", "mail:send"] }],
      purpose: "Native mode E2E test",
    });
    expect(reg.client_id).toBeTruthy();
    expect(reg.client_secret).toBeTruthy();
    expect(reg.agent_status).toBe("approved");
    expect(reg.approved_providers[0].approved_scopes).toContain("mail:read");
    expect(reg.approved_providers[0].approved_scopes).toContain("mail:send");
  });

  // ── Authorization with PKCE ──

  let sessionId: string;
  let authUrl: string;

  it("initiates authorization with PKCE", async () => {
    const auth = await client.authorize(APP_ID, ["mail:read"]);
    expect(auth.ath_session_id).toBeTruthy();
    expect(auth.authorization_url).toContain(OAUTH_URL);
    expect(auth.authorization_url).toContain("code_challenge=");
    expect(auth.authorization_url).toContain("code_challenge_method=S256");
    sessionId = auth.ath_session_id;
    authUrl = auth.authorization_url;
  });

  // ── User consent (real OAuth redirect) ──

  it("completes user consent via real OAuth redirect chain", async () => {
    const url = new URL(authUrl);
    url.searchParams.set("auto_approve", "true");

    const oauthRes = await fetch(url.toString(), { redirect: "manual" });
    expect(oauthRes.status).toBe(302);
    const callbackUrl = oauthRes.headers.get("location")!;
    expect(callbackUrl).toContain("/ath/callback");

    const callbackRes = await fetch(callbackUrl, { redirect: "manual" });
    expect(callbackRes.status).toBe(302);
    const finalUrl = callbackRes.headers.get("location")!;
    expect(finalUrl).toContain("success=true");
  });

  // ── Token exchange ──

  it("exchanges for ATH token with real PKCE verification", async () => {
    const token = await client.exchangeToken("code", sessionId);
    expect(token.access_token).toMatch(/^ath_tk_/);
    expect(token.token_type).toBe("Bearer");
    expect(token.effective_scopes).toContain("mail:read");
    expect(token.agent_id).toBe("https://native-test-agent.example.com/.well-known/agent.json");
    expect(token.scope_intersection.effective).toContain("mail:read");
  });

  // ── Native API call ──

  it("calls service API directly via api() — GET /v1/messages", async () => {
    const messages = await client.api<{ id: number; subject: string }[]>("GET", "/v1/messages");
    expect(Array.isArray(messages)).toBe(true);
    expect(messages.length).toBe(2);
    expect(messages[0].subject).toBe("Flight confirmation");
  });

  it("calls service API directly — GET /v1/profile", async () => {
    const profile = await client.api<{ name: string; email: string }>("GET", "/v1/profile");
    expect(profile.name).toBe("Alice");
    expect(profile.email).toBe("alice@example.com");
  });

  // ── Error: unapproved scope ──

  it("rejects authorization with unapproved scope", async () => {
    try {
      await client.authorize(APP_ID, ["mail:read", "admin:all"]);
      expect.unreachable("Should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(ATHClientError);
      expect((err as ATHClientError).code).toBe("SCOPE_NOT_APPROVED");
    }
  });

  // ── Error: unregistered agent ──

  it("rejects unregistered agent", async () => {
    const { privateKey: otherKey } = await generateKeyPair("ES256");
    const other = new ATHNativeClient({ url: SERVICE_URL, agentId: "https://unknown.example.com/agent.json", privateKey: otherKey });
    other.setCredentials("fake_id", "fake_secret");
    try {
      await other.authorize(APP_ID, ["mail:read"]);
      expect.unreachable("Should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(ATHClientError);
      expect((err as ATHClientError).code).toBe("AGENT_NOT_REGISTERED");
    }
  });

  // ── Token revocation ──

  it("revokes the token and rejects subsequent API calls", async () => {
    // Get a fresh token for revocation test
    const auth2 = await client.authorize(APP_ID, ["mail:read"]);
    const url2 = new URL(auth2.authorization_url);
    url2.searchParams.set("auto_approve", "true");
    const r1 = await fetch(url2.toString(), { redirect: "manual" });
    await fetch(r1.headers.get("location")!, { redirect: "manual" });
    const token2 = await client.exchangeToken("code", auth2.ath_session_id);

    const savedToken = token2.access_token;

    await client.revoke();

    client.setToken(savedToken);
    try {
      await client.api("GET", "/v1/messages");
      expect.unreachable("Should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(ATHClientError);
      expect((err as ATHClientError).code).toBe("TOKEN_REVOKED");
    }
  });

  // ── Error: invalid session ──

  it("rejects exchangeToken with fake session", async () => {
    try {
      await client.exchangeToken("fake", "fake_session");
      expect.unreachable("Should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(ATHClientError);
      expect((err as ATHClientError).code).toBe("SESSION_NOT_FOUND");
    }
  });
});
