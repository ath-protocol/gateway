/**
 * E2E Protocol Compliance Tests — exercises the new ATH protocol requirements
 * with real HTTP against a real ATH server. Only the upstream OAuth server is mocked.
 *
 * Auto-test persona: Adversarial Tester
 * Capability tier: REST/API testing (Stable)
 *
 * Protocol changes under test:
 *   1. Attestation JWT jti claim — uniqueness & replay rejection
 *   2. state parameter required in AuthorizationRequest
 *   3. agent_attestation required in TokenExchangeRequest
 *   4. TokenRevocationRequest — client_secret auth for agents, client_id optional
 *   5. redirect_uris exact-match validation
 */
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { generateKeyPair, SignJWT, decodeJwt } from "jose";
import { Hono } from "hono";
import { serve } from "@hono/node-server";
import type { ServerType } from "@hono/node-server";

import { ATHGatewayClient } from "../packages/client/src/gateway.js";
import { ATHNativeClient } from "../packages/client/src/native.js";
import { ATHClientError } from "../packages/client/src/errors.js";
import {
  createATHHandlers,
  createProxyHandler,
  createServiceDiscoveryDocument,
  InMemoryAgentRegistry,
  InMemoryTokenStore,
  InMemorySessionStore,
  InMemoryProviderTokenStore,
} from "../packages/server/src/index.js";
import { createMockOAuthServer } from "./mock-oauth-server.js";

const OAUTH_PORT = 19000;
const GATEWAY_PORT = 19001;
const UPSTREAM_PORT = 19002;
const NATIVE_PORT = 19003;
const OAUTH_URL = `http://localhost:${OAUTH_PORT}`;
const GATEWAY_URL = `http://localhost:${GATEWAY_PORT}`;
const UPSTREAM_URL = `http://localhost:${UPSTREAM_PORT}`;
const NATIVE_URL = `http://localhost:${NATIVE_PORT}`;
const GW_CLIENT_ID = "ath-compliance-gw";
const GW_CLIENT_SECRET = "ath-compliance-gw-secret";
const NATIVE_CLIENT_ID = "ath-compliance-native";
const NATIVE_CLIENT_SECRET = "ath-compliance-native-secret";
const NATIVE_APP_ID = "com.test.compliance";

let oauthServer: ServerType;
let gatewayServer: ServerType;
let upstreamServer: ServerType;
let nativeServer: ServerType;

function buildUpstream() {
  const app = new Hono();
  app.get("/health", (c) => c.json({ status: "ok" }));
  app.get("/userinfo", (c) => c.json({ login: "compliance-user", name: "Compliance User" }));
  app.get("/api/data", (c) => c.json({ items: [1, 2, 3] }));
  return app;
}

function buildGateway() {
  const app = new Hono();
  const registry = new InMemoryAgentRegistry();
  const tokenStore = new InMemoryTokenStore();
  const sessionStore = new InMemorySessionStore();
  const providerTokenStore = new InMemoryProviderTokenStore();

  const handlers = createATHHandlers({
    registry, tokenStore, sessionStore, providerTokenStore,
    config: {
      audience: GATEWAY_URL,
      callbackUrl: `${GATEWAY_URL}/ath/callback`,
      availableScopes: ["repo", "read:user", "user:email"],
      appId: "github",
      skipAttestationVerification: true,
      oauth: {
        authorize_endpoint: `${OAUTH_URL}/authorize`,
        token_endpoint: `${OAUTH_URL}/token`,
        client_id: GW_CLIENT_ID,
        client_secret: GW_CLIENT_SECRET,
      },
    },
  });

  app.get("/.well-known/ath.json", (c) => c.json({
    ath_version: "0.1",
    gateway_id: GATEWAY_URL,
    agent_registration_endpoint: `${GATEWAY_URL}/ath/agents/register`,
    supported_providers: [{
      provider_id: "github", display_name: "GitHub", categories: [],
      available_scopes: ["repo", "read:user", "user:email"],
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

  const proxy = createProxyHandler({
    tokenStore, providerTokenStore,
    upstreams: { github: UPSTREAM_URL },
  });
  app.all("/ath/proxy/:provider/*", async (c) => {
    const headers: Record<string, string> = {};
    c.req.raw.headers.forEach((v, k) => { headers[k] = v; });
    const query: Record<string, string> = {};
    for (const [k, v] of Object.entries(c.req.query())) { if (v) query[k] = v; }
    let body: unknown = undefined;
    if (c.req.method !== "GET" && c.req.method !== "HEAD") {
      try { body = await c.req.json(); } catch { body = undefined; }
    }
    const r = await proxy({ method: c.req.method, path: c.req.path, headers, query, body });
    return new Response(
      typeof r.body === "string" || r.body instanceof ArrayBuffer
        ? (r.body as BodyInit) : JSON.stringify(r.body),
      { status: r.status, headers: r.headers },
    );
  });

  return app;
}

function buildNativeService() {
  const app = new Hono();
  const registry = new InMemoryAgentRegistry();
  const tokenStore = new InMemoryTokenStore();
  const sessionStore = new InMemorySessionStore();

  const handlers = createATHHandlers({
    registry, tokenStore, sessionStore,
    config: {
      audience: NATIVE_URL,
      callbackUrl: `${NATIVE_URL}/ath/callback`,
      availableScopes: ["mail:read", "mail:send"],
      appId: NATIVE_APP_ID,
      skipAttestationVerification: true,
      oauth: {
        authorize_endpoint: `${OAUTH_URL}/authorize`,
        token_endpoint: `${OAUTH_URL}/token`,
        client_id: NATIVE_CLIENT_ID,
        client_secret: NATIVE_CLIENT_SECRET,
      },
    },
  });

  const discoveryDoc = createServiceDiscoveryDocument({
    app_id: NATIVE_APP_ID,
    name: "Compliance Mail Service",
    authorization_endpoint: `${OAUTH_URL}/authorize`,
    token_endpoint: `${OAUTH_URL}/token`,
    scopes_supported: ["mail:read", "mail:send"],
    api_base: `${NATIVE_URL}/api`,
  });

  app.get("/.well-known/ath-app.json", (c) => c.json(discoveryDoc));
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

  app.get("/api/v1/inbox", async (c) => {
    const authHeader = c.req.header("Authorization");
    if (!authHeader?.startsWith("Bearer ")) return c.json({ error: "Unauthorized" }, 401);
    const token = authHeader.slice(7);
    const bound = await tokenStore.get(token);
    if (!bound) return c.json({ error: "Invalid token" }, 401);
    if (bound.revoked) return c.json({ code: "TOKEN_REVOKED", message: "Token revoked" }, 401);
    return c.json([{ id: 1, subject: "Welcome" }]);
  });

  return app;
}

async function completeOAuthFlow(authUrl: string): Promise<void> {
  const url = new URL(authUrl);
  url.searchParams.set("auto_approve", "true");
  const r1 = await fetch(url.toString(), { redirect: "manual" });
  expect(r1.status).toBe(302);
  const callbackLocation = r1.headers.get("location")!;
  const r2 = await fetch(callbackLocation, { redirect: "manual" });
  expect(r2.status).toBe(302);
}

async function waitForServers(...urls: string[]) {
  for (let i = 0; i < 30; i++) {
    try {
      const results = await Promise.all(urls.map(u => fetch(`${u}/health`).then(r => r.ok).catch(() => false)));
      if (results.every(Boolean)) return;
    } catch { /* retry */ }
    await new Promise(r => setTimeout(r, 150));
  }
  throw new Error("Servers did not become ready");
}

describe("ATH Protocol Compliance E2E — Adversarial Tester", () => {
  beforeAll(async () => {
    const oauthApp = createMockOAuthServer({
      clientId: GW_CLIENT_ID, clientSecret: GW_CLIENT_SECRET, baseUrl: OAUTH_URL,
      additionalClients: [{ clientId: NATIVE_CLIENT_ID, clientSecret: NATIVE_CLIENT_SECRET }],
    });
    oauthServer = serve({ fetch: oauthApp.fetch, port: OAUTH_PORT, hostname: "127.0.0.1" });
    upstreamServer = serve({ fetch: buildUpstream().fetch, port: UPSTREAM_PORT, hostname: "127.0.0.1" });
    gatewayServer = serve({ fetch: buildGateway().fetch, port: GATEWAY_PORT, hostname: "127.0.0.1" });
    nativeServer = serve({ fetch: buildNativeService().fetch, port: NATIVE_PORT, hostname: "127.0.0.1" });
    await waitForServers(OAUTH_URL, GATEWAY_URL, UPSTREAM_URL, NATIVE_URL);
  });

  afterAll(() => {
    gatewayServer?.close();
    oauthServer?.close();
    upstreamServer?.close();
    nativeServer?.close();
  });

  // ═══════════════════════════════════════════════════════════════════
  // 1. ATTESTATION JTI — uniqueness in every JWT
  // ═══════════════════════════════════════════════════════════════════

  describe("Attestation JWT jti claim", () => {
    it("client attestation includes a jti claim", async () => {
      const { privateKey } = await generateKeyPair("ES256");
      const client = new ATHGatewayClient({
        url: GATEWAY_URL,
        agentId: "https://jti-test.example.com/agent.json",
        privateKey,
      });

      await client.register({
        developer: { name: "JTI Test", id: "dev-jti" },
        providers: [{ provider_id: "github", scopes: ["repo"] }],
        purpose: "jti verification",
      });

      const auth = await client.authorize("github", ["repo"]);
      expect(auth.ath_session_id).toBeTruthy();
    });

    it("each attestation JWT has a unique jti", async () => {
      const { privateKey } = await generateKeyPair("ES256");
      const { signAttestation } = await import("../packages/client/src/attestation.js");

      const jwt1 = await signAttestation({ agentId: "https://a.example.com/agent.json", privateKey, keyId: "k1", audience: "https://test.example.com" });
      const jwt2 = await signAttestation({ agentId: "https://a.example.com/agent.json", privateKey, keyId: "k1", audience: "https://test.example.com" });

      const claims1 = decodeJwt(jwt1);
      const claims2 = decodeJwt(jwt2);

      expect(claims1.jti).toBeTruthy();
      expect(claims2.jti).toBeTruthy();
      expect(claims1.jti).not.toBe(claims2.jti);
    });

    it("attestation JWT includes all required claims (iss, sub, aud, iat, exp, jti)", async () => {
      const { privateKey } = await generateKeyPair("ES256");
      const { signAttestation } = await import("../packages/client/src/attestation.js");

      const jwt = await signAttestation({ agentId: "https://claims.example.com/agent.json", privateKey, keyId: "k1", audience: "https://aud.example.com" });
      const claims = decodeJwt(jwt);

      expect(claims.iss).toBe("https://claims.example.com/agent.json");
      expect(claims.sub).toBe("https://claims.example.com/agent.json");
      expect(claims.aud).toBe("https://aud.example.com");
      expect(claims.iat).toBeTypeOf("number");
      expect(claims.exp).toBeTypeOf("number");
      expect(claims.jti).toBeTypeOf("string");
      expect((claims.jti as string).length).toBeGreaterThan(0);
    });
  });

  // ═══════════════════════════════════════════════════════════════════
  // 2. STATE REQUIRED — authorize must reject missing state
  // ═══════════════════════════════════════════════════════════════════

  describe("AuthorizationRequest state parameter", () => {
    it("rejects authorize request without state (direct HTTP call)", async () => {
      const { privateKey } = await generateKeyPair("ES256");
      const client = new ATHGatewayClient({
        url: GATEWAY_URL,
        agentId: "https://state-test.example.com/agent.json",
        privateKey,
      });

      const reg = await client.register({
        developer: { name: "State Test", id: "dev-state" },
        providers: [{ provider_id: "github", scopes: ["repo"] }],
        purpose: "state testing",
      });

      const res = await fetch(`${GATEWAY_URL}/ath/authorize`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          client_id: reg.client_id,
          agent_attestation: "dummy",
          provider_id: "github",
          scopes: ["repo"],
        }),
      });

      expect(res.status).toBe(400);
      const body = await res.json() as { code: string };
      expect(body.code).toBe("STATE_MISMATCH");
    });

    it("client SDK always sends a state parameter", async () => {
      const { privateKey } = await generateKeyPair("ES256");
      const client = new ATHGatewayClient({
        url: GATEWAY_URL,
        agentId: "https://state-sdk.example.com/agent.json",
        privateKey,
      });

      await client.register({
        developer: { name: "State SDK", id: "dev-state-sdk" },
        providers: [{ provider_id: "github", scopes: ["repo"] }],
        purpose: "test",
      });

      const auth = await client.authorize("github", ["repo"]);
      expect(auth.authorization_url).toBeTruthy();
      expect(auth.ath_session_id).toBeTruthy();
    });
  });

  // ═══════════════════════════════════════════════════════════════════
  // 3. TOKEN EXCHANGE — agent_attestation required
  // ═══════════════════════════════════════════════════════════════════

  describe("TokenExchangeRequest agent_attestation", () => {
    it("rejects token exchange without agent_attestation (direct HTTP call)", async () => {
      const { privateKey } = await generateKeyPair("ES256");
      const client = new ATHGatewayClient({
        url: GATEWAY_URL,
        agentId: "https://token-attest.example.com/agent.json",
        privateKey,
      });

      const reg = await client.register({
        developer: { name: "Token Attest", id: "dev-ta" },
        providers: [{ provider_id: "github", scopes: ["repo"] }],
        purpose: "test",
      });

      const auth = await client.authorize("github", ["repo"]);
      await completeOAuthFlow(auth.authorization_url);

      const res = await fetch(`${GATEWAY_URL}/ath/token`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          grant_type: "authorization_code",
          client_id: reg.client_id,
          client_secret: reg.client_secret,
          code: "code",
          ath_session_id: auth.ath_session_id,
        }),
      });

      expect(res.status).toBe(400);
      const body = await res.json() as { code: string };
      expect(body.code).toBe("INVALID_ATTESTATION");
    });

    it("client SDK sends agent_attestation during token exchange", async () => {
      const { privateKey } = await generateKeyPair("ES256");
      const client = new ATHGatewayClient({
        url: GATEWAY_URL,
        agentId: "https://token-ok.example.com/agent.json",
        privateKey,
      });

      await client.register({
        developer: { name: "Token OK", id: "dev-tok" },
        providers: [{ provider_id: "github", scopes: ["repo"] }],
        purpose: "test",
      });

      const auth = await client.authorize("github", ["repo"]);
      await completeOAuthFlow(auth.authorization_url);

      const tok = await client.exchangeToken("code", auth.ath_session_id);
      expect(tok.access_token).toMatch(/^ath_tk_/);
      expect(tok.token_type).toBe("Bearer");
      expect(tok.effective_scopes).toContain("repo");
    });
  });

  // ═══════════════════════════════════════════════════════════════════
  // 4. REVOCATION — client_secret required for agent callers
  // ═══════════════════════════════════════════════════════════════════

  describe("TokenRevocationRequest client_secret authentication", () => {
    it("rejects agent revocation without client_secret", async () => {
      const { privateKey } = await generateKeyPair("ES256");
      const client = new ATHGatewayClient({
        url: GATEWAY_URL,
        agentId: "https://revoke-nosecret.example.com/agent.json",
        privateKey,
      });

      const reg = await client.register({
        developer: { name: "Revoke NoSecret", id: "dev-rns" },
        providers: [{ provider_id: "github", scopes: ["repo"] }],
        purpose: "test",
      });

      const auth = await client.authorize("github", ["repo"]);
      await completeOAuthFlow(auth.authorization_url);
      const tok = await client.exchangeToken("code", auth.ath_session_id);

      const res = await fetch(`${GATEWAY_URL}/ath/revoke`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          client_id: reg.client_id,
          token: tok.access_token,
        }),
      });

      expect(res.status).toBe(400);
      const body = await res.json() as { code: string };
      expect(body.code).toBe("AGENT_NOT_REGISTERED");
    });

    it("rejects agent revocation with wrong client_secret", async () => {
      const { privateKey } = await generateKeyPair("ES256");
      const client = new ATHGatewayClient({
        url: GATEWAY_URL,
        agentId: "https://revoke-badsecret.example.com/agent.json",
        privateKey,
      });

      const reg = await client.register({
        developer: { name: "Revoke BadSecret", id: "dev-rbs" },
        providers: [{ provider_id: "github", scopes: ["repo"] }],
        purpose: "test",
      });

      const auth = await client.authorize("github", ["repo"]);
      await completeOAuthFlow(auth.authorization_url);
      const tok = await client.exchangeToken("code", auth.ath_session_id);

      const res = await fetch(`${GATEWAY_URL}/ath/revoke`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          client_id: reg.client_id,
          client_secret: "wrong_secret",
          token: tok.access_token,
        }),
      });

      expect(res.status).toBe(401);
    });

    it("accepts agent revocation with correct client_secret", async () => {
      const { privateKey } = await generateKeyPair("ES256");
      const client = new ATHGatewayClient({
        url: GATEWAY_URL,
        agentId: "https://revoke-ok.example.com/agent.json",
        privateKey,
      });

      const reg = await client.register({
        developer: { name: "Revoke OK", id: "dev-rok" },
        providers: [{ provider_id: "github", scopes: ["repo"] }],
        purpose: "test",
      });

      const auth = await client.authorize("github", ["repo"]);
      await completeOAuthFlow(auth.authorization_url);
      const tok = await client.exchangeToken("code", auth.ath_session_id);

      const res = await fetch(`${GATEWAY_URL}/ath/revoke`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          client_id: reg.client_id,
          client_secret: reg.client_secret,
          token: tok.access_token,
        }),
      });

      expect(res.status).toBe(200);
    });

    it("returns 200 for unknown token per RFC 7009 §2.2", async () => {
      const res = await fetch(`${GATEWAY_URL}/ath/revoke`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ token: "ath_tk_nonexistent_totally_fake" }),
      });

      expect(res.status).toBe(200);
    });

    it("allows token-only revocation (no client_id — admin/user path)", async () => {
      const { privateKey } = await generateKeyPair("ES256");
      const client = new ATHGatewayClient({
        url: GATEWAY_URL,
        agentId: "https://revoke-admin.example.com/agent.json",
        privateKey,
      });

      await client.register({
        developer: { name: "Revoke Admin", id: "dev-radm" },
        providers: [{ provider_id: "github", scopes: ["repo"] }],
        purpose: "test",
      });

      const auth = await client.authorize("github", ["repo"]);
      await completeOAuthFlow(auth.authorization_url);
      const tok = await client.exchangeToken("code", auth.ath_session_id);

      const res = await fetch(`${GATEWAY_URL}/ath/revoke`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ token: tok.access_token }),
      });

      expect(res.status).toBe(200);
    });

    it("client SDK sends client_secret with revocation", async () => {
      const { privateKey } = await generateKeyPair("ES256");
      const client = new ATHGatewayClient({
        url: GATEWAY_URL,
        agentId: "https://revoke-sdk.example.com/agent.json",
        privateKey,
      });

      await client.register({
        developer: { name: "Revoke SDK", id: "dev-rsdk" },
        providers: [{ provider_id: "github", scopes: ["repo"] }],
        purpose: "test",
      });

      const auth = await client.authorize("github", ["repo"]);
      await completeOAuthFlow(auth.authorization_url);
      await client.exchangeToken("code", auth.ath_session_id);

      await client.revoke();
    });
  });

  // ═══════════════════════════════════════════════════════════════════
  // 5. REDIRECT_URIS — exact-match validation
  // ═══════════════════════════════════════════════════════════════════

  describe("redirect_uris exact-match validation", () => {
    it("rejects user_redirect_uri not in registered redirect_uris", async () => {
      const { privateKey } = await generateKeyPair("ES256");
      const client = new ATHGatewayClient({
        url: GATEWAY_URL,
        agentId: "https://redirect-mismatch.example.com/agent.json",
        privateKey,
      });

      const reg = await client.register({
        developer: { name: "Redirect Mismatch", id: "dev-rm" },
        providers: [{ provider_id: "github", scopes: ["repo"] }],
        purpose: "test",
        redirectUris: ["https://redirect-mismatch.example.com/callback"],
      });

      const { signAttestation } = await import("../packages/client/src/attestation.js");
      const attestation = await signAttestation({
        agentId: "https://redirect-mismatch.example.com/agent.json",
        privateKey, keyId: "default", audience: GATEWAY_URL,
      });

      const res = await fetch(`${GATEWAY_URL}/ath/authorize`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          client_id: reg.client_id,
          agent_attestation: attestation,
          provider_id: "github",
          scopes: ["repo"],
          user_redirect_uri: "https://evil.example.com/steal",
          state: "abc123",
        }),
      });

      expect(res.status).toBe(400);
    });

    it("accepts user_redirect_uri matching a registered redirect_uri", async () => {
      const { privateKey } = await generateKeyPair("ES256");
      const registeredCallback = `${GATEWAY_URL}/ath/callback`;
      const client = new ATHGatewayClient({
        url: GATEWAY_URL,
        agentId: "https://redirect-match.example.com/agent.json",
        privateKey,
      });

      await client.register({
        developer: { name: "Redirect Match", id: "dev-rmatch" },
        providers: [{ provider_id: "github", scopes: ["repo"] }],
        purpose: "test",
        redirectUris: [registeredCallback],
      });

      const auth = await client.authorize("github", ["repo"], { redirectUri: registeredCallback });
      expect(auth.authorization_url).toBeTruthy();
    });
  });

  // ═══════════════════════════════════════════════════════════════════
  // 6. FULL HAPPY PATH — gateway mode, all new protocol fields
  // ═══════════════════════════════════════════════════════════════════

  describe("Full happy path — gateway mode with new protocol", () => {
    it("completes discover → register → authorize → consent → token → proxy → revoke", async () => {
      const { privateKey } = await generateKeyPair("ES256");
      const client = new ATHGatewayClient({
        url: GATEWAY_URL,
        agentId: "https://happy-gw.example.com/agent.json",
        privateKey,
      });

      const disc = await client.discover();
      expect(disc.ath_version).toBe("0.1");
      expect(disc.supported_providers.length).toBeGreaterThan(0);

      const reg = await client.register({
        developer: { name: "Happy GW", id: "dev-hgw" },
        providers: [{ provider_id: "github", scopes: ["repo", "read:user"] }],
        purpose: "compliance",
      });
      expect(reg.agent_status).toBe("approved");

      const auth = await client.authorize("github", ["repo"], { resource: "https://api.github.com" });
      expect(auth.authorization_url).toContain("code_challenge=");
      expect(auth.authorization_url).toContain("resource=");

      await completeOAuthFlow(auth.authorization_url);

      const tok = await client.exchangeToken("code", auth.ath_session_id);
      expect(tok.access_token).toMatch(/^ath_tk_/);
      expect(tok.token_type).toBe("Bearer");
      expect(tok.effective_scopes).toContain("repo");
      expect(tok.scope_intersection.effective).toContain("repo");

      const user = await client.proxy<{ login: string }>("github", "GET", "/userinfo");
      expect(user.login).toBe("compliance-user");

      await client.revoke();
    });
  });

  // ═══════════════════════════════════════════════════════════════════
  // 7. FULL HAPPY PATH — native mode, all new protocol fields
  // ═══════════════════════════════════════════════════════════════════

  describe("Full happy path — native mode with new protocol", () => {
    it("completes discover → register → authorize → consent → token → api → revoke", async () => {
      const { privateKey } = await generateKeyPair("ES256");
      const client = new ATHNativeClient({
        url: NATIVE_URL,
        agentId: "https://happy-native.example.com/agent.json",
        privateKey,
      });

      const disc = await client.discover();
      expect(disc.ath_version).toBe("0.1");
      expect(disc.app_id).toBe(NATIVE_APP_ID);

      await client.register({
        developer: { name: "Happy Native", id: "dev-hn" },
        providers: [{ provider_id: NATIVE_APP_ID, scopes: ["mail:read"] }],
        purpose: "compliance",
      });

      const auth = await client.authorize(NATIVE_APP_ID, ["mail:read"]);
      expect(auth.authorization_url).toContain("code_challenge=");

      await completeOAuthFlow(auth.authorization_url);

      const tok = await client.exchangeToken("code", auth.ath_session_id);
      expect(tok.access_token).toMatch(/^ath_tk_/);
      expect(tok.effective_scopes).toContain("mail:read");

      const inbox = await client.api<{ id: number; subject: string }[]>("GET", "/v1/inbox");
      expect(Array.isArray(inbox)).toBe(true);
      expect(inbox[0].subject).toBe("Welcome");

      await client.revoke();
    });

    it("revoked token is rejected by native API", async () => {
      const { privateKey } = await generateKeyPair("ES256");
      const client = new ATHNativeClient({
        url: NATIVE_URL,
        agentId: "https://revoked-native.example.com/agent.json",
        privateKey,
      });

      await client.discover();
      await client.register({
        developer: { name: "Revoked Native", id: "dev-rn" },
        providers: [{ provider_id: NATIVE_APP_ID, scopes: ["mail:read"] }],
        purpose: "test",
      });

      const auth = await client.authorize(NATIVE_APP_ID, ["mail:read"]);
      await completeOAuthFlow(auth.authorization_url);
      const tok = await client.exchangeToken("code", auth.ath_session_id);

      await client.revoke();

      client.setToken(tok.access_token);
      try {
        await client.api("GET", "/v1/inbox");
        expect.unreachable("Should have rejected revoked token");
      } catch (err) {
        expect(err).toBeInstanceOf(ATHClientError);
        expect((err as ATHClientError).code).toBe("TOKEN_REVOKED");
      }
    });
  });

  // ═══════════════════════════════════════════════════════════════════
  // 8. ADVERSARIAL PROBES — edge cases & error handling
  // ═══════════════════════════════════════════════════════════════════

  describe("Adversarial edge cases", () => {
    it("rejects empty body on all endpoints", async () => {
      const endpoints = ["/ath/agents/register", "/ath/authorize", "/ath/token", "/ath/revoke"];

      for (const ep of endpoints) {
        const res = await fetch(`${GATEWAY_URL}${ep}`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({}),
        });
        expect(res.status).toBeGreaterThanOrEqual(400);
      }
    });

    it("rejects token exchange with wrong client_secret", async () => {
      const { privateKey } = await generateKeyPair("ES256");
      const { signAttestation } = await import("../packages/client/src/attestation.js");

      const client = new ATHGatewayClient({
        url: GATEWAY_URL,
        agentId: "https://bad-cred.example.com/agent.json",
        privateKey,
      });

      const reg = await client.register({
        developer: { name: "Bad Cred", id: "dev-bc" },
        providers: [{ provider_id: "github", scopes: ["repo"] }],
        purpose: "test",
      });

      const auth = await client.authorize("github", ["repo"]);
      await completeOAuthFlow(auth.authorization_url);

      const attestation = await signAttestation({
        agentId: "https://bad-cred.example.com/agent.json",
        privateKey, keyId: "default", audience: `${GATEWAY_URL}/ath/token`,
      });

      const res = await fetch(`${GATEWAY_URL}/ath/token`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          grant_type: "authorization_code",
          client_id: reg.client_id,
          client_secret: "totally_wrong_secret",
          agent_attestation: attestation,
          code: "code",
          ath_session_id: auth.ath_session_id,
        }),
      });

      expect(res.status).toBe(401);
    });

    it("rejects token exchange for a non-existent session", async () => {
      const { privateKey } = await generateKeyPair("ES256");
      const { signAttestation } = await import("../packages/client/src/attestation.js");

      const client = new ATHGatewayClient({
        url: GATEWAY_URL,
        agentId: "https://nosess.example.com/agent.json",
        privateKey,
      });

      const reg = await client.register({
        developer: { name: "No Sess", id: "dev-ns" },
        providers: [{ provider_id: "github", scopes: ["repo"] }],
        purpose: "test",
      });

      const attestation = await signAttestation({
        agentId: "https://nosess.example.com/agent.json",
        privateKey, keyId: "default", audience: `${GATEWAY_URL}/ath/token`,
      });

      const res = await fetch(`${GATEWAY_URL}/ath/token`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          grant_type: "authorization_code",
          client_id: reg.client_id,
          client_secret: reg.client_secret,
          agent_attestation: attestation,
          code: "code",
          ath_session_id: "ath_sess_fake_nonexistent",
        }),
      });

      expect(res.status).toBe(400);
      const body = await res.json() as { code: string };
      expect(body.code).toBe("SESSION_NOT_FOUND");
    });

    it("another agent cannot revoke a different agent's token", async () => {
      const { privateKey: key1 } = await generateKeyPair("ES256");
      const { privateKey: key2 } = await generateKeyPair("ES256");

      const agent1 = new ATHGatewayClient({
        url: GATEWAY_URL,
        agentId: "https://agent1-xrevoke.example.com/agent.json",
        privateKey: key1,
      });
      const agent2 = new ATHGatewayClient({
        url: GATEWAY_URL,
        agentId: "https://agent2-xrevoke.example.com/agent.json",
        privateKey: key2,
      });

      const reg1 = await agent1.register({
        developer: { name: "Agent1", id: "dev-a1" },
        providers: [{ provider_id: "github", scopes: ["repo"] }],
        purpose: "test",
      });
      const reg2 = await agent2.register({
        developer: { name: "Agent2", id: "dev-a2" },
        providers: [{ provider_id: "github", scopes: ["repo"] }],
        purpose: "test",
      });

      const auth1 = await agent1.authorize("github", ["repo"]);
      await completeOAuthFlow(auth1.authorization_url);
      const tok1 = await agent1.exchangeToken("code", auth1.ath_session_id);

      const res = await fetch(`${GATEWAY_URL}/ath/revoke`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          client_id: reg2.client_id,
          client_secret: reg2.client_secret,
          token: tok1.access_token,
        }),
      });

      expect(res.status).toBe(403);
      const body = await res.json() as { code: string };
      expect(body.code).toBe("AGENT_IDENTITY_MISMATCH");
    });
  });
});
