/**
 * E2E Test: Full ATH protocol flow with user authentication.
 * Tests the complete happy path: login → discover → register → authorize → consent → token → proxy → revoke.
 */
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { app } from "../../src/app.js";
import { agentStore } from "../../src/registry/agent-store.js";
import { tokenStore } from "../../src/auth/token.js";
import { sessionStore } from "../../src/auth/session-store.js";
import { providerStore } from "../../src/providers/store.js";
import { userStore } from "../../src/users/store.js";
import { createSessionToken } from "../../src/users/middleware.js";
import * as jose from "jose";
import fs from "node:fs";
import path from "node:path";

const BASE = "http://localhost";

function resetProviders() {
  const configFile = path.join(process.cwd(), "providers.json");
  fs.writeFileSync(configFile, "{}", "utf-8");
  providerStore.clearCache();
}
let authToken: string;
let testUserId: string;

/** Shared setup — creates a test admin user and auth token */
async function ensureTestUser() {
  if (authToken) return;
  const existing = await userStore.getByUsername("testuser");
  if (existing) {
    testUserId = existing.id;
    authToken = await createSessionToken(existing.id, existing.role);
    return;
  }
  const user = await userStore.create("testuser", "testpass123", "admin");
  testUserId = user.id;
  authToken = await createSessionToken(user.id, user.role);
}

async function req(method: string, path: string, body?: unknown, headers?: Record<string, string>) {
  const init: RequestInit = {
    method,
    headers: {
      "Content-Type": "application/json",
      ...(authToken ? { "X-ATH-User-Token": authToken } : {}),
      ...headers,
    },
  };
  if (body) init.body = JSON.stringify(body);
  return app.request(path, init);
}

async function generateAttestation(agentId: string): Promise<string> {
  const { privateKey } = await jose.generateKeyPair("ES256");
  return new jose.SignJWT({ capabilities: [] })
    .setProtectedHeader({ alg: "ES256", kid: "test-key" })
    .setIssuer(agentId)
    .setSubject(agentId)
    .setAudience("http://localhost:3000")
    .setIssuedAt()
    .setExpirationTime("1h")
    .sign(privateKey);
}

describe("E2E-0: User Authentication", () => {
  beforeAll(async () => {
    agentStore.clear();
    tokenStore.clear();
    sessionStore.clear();
    resetProviders();
    userStore.clear();
    authToken = "";
    await ensureTestUser();
  });

  it("Unauthenticated agent register is rejected", async () => {
    const res = await app.request("/ath/agents/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ agent_id: "x", agent_attestation: "x", requested_providers: [] }),
    });
    expect(res.status).toBe(401);
  });

  it("Login returns a session token", async () => {
    const res = await app.request("/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username: "testuser", password: "testpass123" }),
    });
    expect(res.status).toBe(200);
    const data = await res.json() as any;
    expect(data.token).toBeTruthy();
    expect(data.user.role).toBe("admin");
  });

  it("Signup is disabled by default", async () => {
    const res = await app.request("/auth/signup", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username: "newuser", password: "pass123" }),
    });
    expect(res.status).toBe(403);
  });
});

describe("E2E-1: Agent registers and accesses a service (Happy Path)", () => {
  beforeAll(async () => {
    agentStore.clear();
    tokenStore.clear();
    sessionStore.clear();
    resetProviders();
    await ensureTestUser();
  });

  const agentId = "https://test-agent.example.com/.well-known/agent.json";
  let clientId: string;
  let clientSecret: string;
  let sessionId: string;
  let accessToken: string;

  it("Step 1: Discovery returns supported providers (public, no auth)", async () => {
    const res = await app.request("/.well-known/ath.json");
    expect(res.status).toBe(200);
    const data = await res.json() as any;
    expect(data.ath_version).toBe("0.1");
    expect(data.supported_providers.length).toBeGreaterThan(0);
    expect(data.supported_providers.some((p: any) => p.provider_id === "github")).toBe(true);
  });

  it("Step 2: Agent registers successfully", async () => {
    const attestation = await generateAttestation(agentId);
    const res = await req("POST", "/ath/agents/register", {
      agent_id: agentId,
      agent_attestation: attestation,
      developer: { name: "Test Dev", id: "dev-test-001" },
      requested_providers: [{ provider_id: "github", scopes: ["repo", "read:user"] }],
      purpose: "E2E test",
      redirect_uris: ["http://localhost:3000/ath/callback"],
    });
    expect(res.status).toBe(201);
    const data = await res.json() as any;
    expect(data.client_id).toBeTruthy();
    expect(data.client_secret).toBeTruthy();
    expect(data.agent_status).toBe("approved");
    expect(data.approved_providers[0].approved_scopes).toContain("repo");
    expect(data.approved_providers[0].approved_scopes).toContain("read:user");
    clientId = data.client_id;
    clientSecret = data.client_secret;
  });

  it("Step 3: Agent initiates authorization flow", async () => {
    const attestation = await generateAttestation(agentId);
    const res = await req("POST", "/ath/authorize", {
      client_id: clientId,
      agent_attestation: attestation,
      provider_id: "github",
      scopes: ["repo", "read:user"],
      user_redirect_uri: "http://localhost:3000/ath/callback",
      state: "test-state-123",
    });
    expect(res.status).toBe(200);
    const data = await res.json() as any;
    expect(data.authorization_url).toBeTruthy();
    expect(data.ath_session_id).toBeTruthy();
    sessionId = data.ath_session_id;
  });

  it("Step 4: Simulate user consent via mock consent page", async () => {
    const session = await sessionStore.get(sessionId);
    expect(session).toBeTruthy();

    const callbackRes = await req("GET", `/ath/callback?code=mock_code_e2e&state=${session!.oauth_state}`);
    expect(callbackRes.status).toBe(302);
    const location = callbackRes.headers.get("location") || "";
    expect(location).toContain("success=true");
  });

  it("Step 5: Agent exchanges code for ATH token with scope intersection", async () => {
    const res = await req("POST", "/ath/token", {
      grant_type: "authorization_code",
      client_id: clientId,
      client_secret: clientSecret,
      code: "mock_code_e2e",
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

  it("Step 6: Agent calls proxy API with ATH token", async () => {
    const res = await req("GET", "/ath/proxy/github/user", undefined, {
      Authorization: `Bearer ${accessToken}`,
      "X-ATH-Agent-ID": agentId,
    });
    expect(res.status).toBe(200);
    const data = await res.json() as any;
    expect(data.mock).toBe(true);
    expect(data.provider).toBe("github");
  });

  afterAll(() => {
    agentStore.clear();
    tokenStore.clear();
    sessionStore.clear();
  });
});

describe("E2E-2: Trusted Handshake Enforcement (Scope Restriction)", () => {
  beforeAll(async () => {
    agentStore.clear();
    tokenStore.clear();
    sessionStore.clear();
    resetProviders();
    await ensureTestUser();
  });

  const agentId = "https://restricted-agent.example.com/.well-known/agent.json";
  let clientId: string;
  let clientSecret: string;

  it("Step 1: Agent registers requesting scopes [repo, read:user, admin:org]", async () => {
    const attestation = await generateAttestation(agentId);
    const res = await req("POST", "/ath/agents/register", {
      agent_id: agentId,
      agent_attestation: attestation,
      developer: { name: "Test", id: "dev-test" },
      requested_providers: [{ provider_id: "github", scopes: ["repo", "read:user", "admin:org"] }],
      purpose: "Scope restriction test",
      redirect_uris: [],
    });
    const data = await res.json() as any;
    expect(data.agent_status).toBe("approved");
    expect(data.approved_providers[0].approved_scopes).toContain("repo");
    expect(data.approved_providers[0].approved_scopes).toContain("read:user");
    expect(data.approved_providers[0].denied_scopes).toContain("admin:org");
    clientId = data.client_id;
    clientSecret = data.client_secret;
  });

  it("Step 2: Agent requesting unapproved scope is rejected", async () => {
    const attestation = await generateAttestation(agentId);
    const res = await req("POST", "/ath/authorize", {
      client_id: clientId,
      agent_attestation: attestation,
      provider_id: "github",
      scopes: ["repo", "admin:org"],
      user_redirect_uri: "http://localhost/callback",
      state: "test",
    });
    expect(res.status).toBe(403);
    const data = await res.json() as any;
    expect(data.code).toBe("SCOPE_NOT_APPROVED");
  });

  it("Step 3: Agent requesting only approved scopes succeeds", async () => {
    const attestation = await generateAttestation(agentId);
    const res = await req("POST", "/ath/authorize", {
      client_id: clientId,
      agent_attestation: attestation,
      provider_id: "github",
      scopes: ["repo"],
      user_redirect_uri: "http://localhost:3000/ath/callback",
      state: "test",
    });
    expect(res.status).toBe(200);
    const data = await res.json() as any;
    expect(data.authorization_url).toBeTruthy();
  });

  afterAll(() => {
    agentStore.clear();
    tokenStore.clear();
    sessionStore.clear();
  });
});

describe("E2E-3: Unapproved Agent Rejected", () => {
  beforeAll(async () => {
    agentStore.clear();
    await ensureTestUser();
  });

  it("Unregistered agent is rejected before OAuth flow", async () => {
    const attestation = await generateAttestation("https://unknown.example.com/agent.json");
    const res = await req("POST", "/ath/authorize", {
      client_id: "fake_client_id",
      agent_attestation: attestation,
      provider_id: "github",
      scopes: ["repo"],
      user_redirect_uri: "http://localhost/callback",
      state: "test",
    });
    expect(res.status).toBe(403);
    const data = await res.json() as any;
    expect(data.code).toBe("AGENT_NOT_REGISTERED");
  });

  afterAll(() => {
    agentStore.clear();
  });
});

describe("E2E-4: Token Revocation", () => {
  beforeAll(async () => {
    agentStore.clear();
    tokenStore.clear();
    sessionStore.clear();
    resetProviders();
    await ensureTestUser();
  });

  const agentId = "https://revoke-test.example.com/.well-known/agent.json";
  let clientId: string;
  let clientSecret: string;
  let accessToken: string;

  it("Setup: Register agent and get token", async () => {
    const attestation = await generateAttestation(agentId);
    const regRes = await req("POST", "/ath/agents/register", {
      agent_id: agentId,
      agent_attestation: attestation,
      developer: { name: "Test", id: "dev-test" },
      requested_providers: [{ provider_id: "github", scopes: ["repo"] }],
      purpose: "Revocation test",
      redirect_uris: [],
    });
    const regData = await regRes.json() as any;
    clientId = regData.client_id;
    clientSecret = regData.client_secret;

    const authAttestation = await generateAttestation(agentId);
    const authRes = await req("POST", "/ath/authorize", {
      client_id: clientId,
      agent_attestation: authAttestation,
      provider_id: "github",
      scopes: ["repo"],
      user_redirect_uri: "http://localhost:3000/ath/callback",
      state: "test",
    });
    const authData = await authRes.json() as any;

    const session = await sessionStore.get(authData.ath_session_id);
    await req("GET", `/ath/callback?code=mock_code&state=${session!.oauth_state}`);

    const tokenRes = await req("POST", "/ath/token", {
      grant_type: "authorization_code",
      client_id: clientId,
      client_secret: clientSecret,
      code: "mock_code",
      ath_session_id: authData.ath_session_id,
    });
    const tokenData = await tokenRes.json() as any;
    accessToken = tokenData.access_token;

    const proxyRes = await req("GET", "/ath/proxy/github/user", undefined, {
      Authorization: `Bearer ${accessToken}`,
    });
    expect(proxyRes.status).toBe(200);
  });

  it("Revoke token", async () => {
    const res = await req("POST", "/ath/revoke", {
      client_id: clientId,
      token: accessToken,
    });
    expect(res.status).toBe(200);
  });

  it("Revoked token is rejected", async () => {
    const res = await req("GET", "/ath/proxy/github/user", undefined, {
      Authorization: `Bearer ${accessToken}`,
    });
    expect(res.status).toBe(401);
    const data = await res.json() as any;
    expect(data.code).toBe("TOKEN_REVOKED");
  });

  afterAll(() => {
    agentStore.clear();
    tokenStore.clear();
    sessionStore.clear();
  });
});

describe("E2E-5: Proxy rejects mismatched agent/provider", () => {
  beforeAll(async () => {
    agentStore.clear();
    tokenStore.clear();
    sessionStore.clear();
    resetProviders();
    await ensureTestUser();
  });

  const agentId = "https://mismatch-test.example.com/.well-known/agent.json";
  let accessToken: string;

  it("Setup: Get a valid token for github", async () => {
    const attestation = await generateAttestation(agentId);
    const regRes = await req("POST", "/ath/agents/register", {
      agent_id: agentId,
      agent_attestation: attestation,
      developer: { name: "Test", id: "dev-test" },
      requested_providers: [{ provider_id: "github", scopes: ["repo"] }],
      purpose: "Mismatch test",
      redirect_uris: [],
    });
    const regData = await regRes.json() as any;

    const authAttestation = await generateAttestation(agentId);
    const authRes = await req("POST", "/ath/authorize", {
      client_id: regData.client_id,
      agent_attestation: authAttestation,
      provider_id: "github",
      scopes: ["repo"],
      user_redirect_uri: "http://localhost:3000/ath/callback",
      state: "test",
    });
    const authData = await authRes.json() as any;

    const session = await sessionStore.get(authData.ath_session_id);
    await req("GET", `/ath/callback?code=mock_code&state=${session!.oauth_state}`);

    const tokenRes = await req("POST", "/ath/token", {
      grant_type: "authorization_code",
      client_id: regData.client_id,
      client_secret: regData.client_secret,
      code: "mock_code",
      ath_session_id: authData.ath_session_id,
    });
    const tokenData = await tokenRes.json() as any;
    accessToken = tokenData.access_token;
  });

  it("Token for github is rejected when used for slack", async () => {
    const res = await req("GET", "/ath/proxy/slack/channels", undefined, {
      Authorization: `Bearer ${accessToken}`,
    });
    expect(res.status).toBe(403);
    const data = await res.json() as any;
    expect(data.code).toBe("PROVIDER_MISMATCH");
  });

  it("Token with wrong agent ID header is rejected", async () => {
    const res = await req("GET", "/ath/proxy/github/user", undefined, {
      Authorization: `Bearer ${accessToken}`,
      "X-ATH-Agent-ID": "https://different-agent.example.com/agent.json",
    });
    expect(res.status).toBe(403);
    const data = await res.json() as any;
    expect(data.code).toBe("AGENT_IDENTITY_MISMATCH");
  });

  afterAll(() => {
    agentStore.clear();
    tokenStore.clear();
    sessionStore.clear();
  });
});

describe("E2E-6: Cross-tenant isolation", () => {
  let userAToken: string;
  let userBToken: string;
  let agentClientIdA: string;

  beforeAll(async () => {
    agentStore.clear();
    tokenStore.clear();
    sessionStore.clear();
    userStore.clear();

    const userA = await userStore.create("alice", "passA", "user");
    const userB = await userStore.create("bob", "passB", "user");
    userAToken = await createSessionToken(userA.id, userA.role);
    userBToken = await createSessionToken(userB.id, userB.role);
  });

  it("User A registers an agent", async () => {
    const attestation = await generateAttestation("https://agent-a.example.com/agent.json");
    const res = await app.request("/ath/agents/register", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-ATH-User-Token": userAToken,
      },
      body: JSON.stringify({
        agent_id: "https://agent-a.example.com/agent.json",
        agent_attestation: attestation,
        developer: { name: "Alice", id: "dev-alice" },
        requested_providers: [{ provider_id: "github", scopes: ["repo"] }],
        purpose: "Isolation test",
        redirect_uris: [],
      }),
    });
    expect(res.status).toBe(201);
    const data = await res.json() as any;
    agentClientIdA = data.client_id;
  });

  it("User B cannot see User A's agent", async () => {
    const res = await app.request(`/ath/agents/${agentClientIdA}`, {
      method: "GET",
      headers: {
        "Content-Type": "application/json",
        "X-ATH-User-Token": userBToken,
      },
    });
    expect(res.status).toBe(404);
  });

  it("User B can register same agent_id independently", async () => {
    const attestation = await generateAttestation("https://agent-a.example.com/agent.json");
    const res = await app.request("/ath/agents/register", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-ATH-User-Token": userBToken,
      },
      body: JSON.stringify({
        agent_id: "https://agent-a.example.com/agent.json",
        agent_attestation: attestation,
        developer: { name: "Bob", id: "dev-bob" },
        requested_providers: [{ provider_id: "github", scopes: ["repo"] }],
        purpose: "Isolation test B",
        redirect_uris: [],
      }),
    });
    expect(res.status).toBe(201);
    const data = await res.json() as any;
    expect(data.client_id).not.toBe(agentClientIdA);
  });

  afterAll(() => {
    agentStore.clear();
    tokenStore.clear();
    sessionStore.clear();
    userStore.clear();
  });
});

describe("E2E-7: Admin-only provider management", () => {
  let adminToken: string;
  let regularToken: string;

  beforeAll(async () => {
    userStore.clear();
    const admin = await userStore.create("admin", "adminpass", "admin");
    const regular = await userStore.create("regular", "regularpass", "user");
    adminToken = await createSessionToken(admin.id, admin.role);
    regularToken = await createSessionToken(regular.id, regular.role);
  });

  it("Regular user can read providers", async () => {
    const res = await app.request("/ath/admin/providers", {
      headers: { "X-ATH-User-Token": regularToken },
    });
    expect(res.status).toBe(200);
  });

  it("Regular user cannot add a provider", async () => {
    const res = await app.request("/ath/admin/providers", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-ATH-User-Token": regularToken,
      },
      body: JSON.stringify({
        provider_id: "evil",
        display_name: "Evil",
        authorize_endpoint: "https://evil.com/auth",
        token_endpoint: "https://evil.com/token",
        client_id: "x",
        client_secret: "x",
        available_scopes: [],
      }),
    });
    expect(res.status).toBe(403);
  });

  it("Admin user can add a provider", async () => {
    const res = await app.request("/ath/admin/providers", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-ATH-User-Token": adminToken,
      },
      body: JSON.stringify({
        provider_id: "test-provider",
        display_name: "Test",
        authorize_endpoint: "https://test.com/auth",
        token_endpoint: "https://test.com/token",
        client_id: "tc",
        client_secret: "ts",
        available_scopes: ["read"],
      }),
    });
    expect(res.status).toBe(201);
  });

  afterAll(() => {
    userStore.clear();
    providerStore.delete("test-provider");
    providerStore.clearCache();
  });
});
