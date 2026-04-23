import { describe, it, expect, beforeEach } from "vitest";
import { InMemoryTokenStore } from "../tokens.js";
import { InMemoryProviderTokenStore } from "../provider-tokens.js";
import { createProxyHandler, type ProxyRequest } from "../proxy.js";

const AGENT = "https://agent.example.com/.well-known/agent.json";

function makeFakeFetch(record: {
  url?: string;
  init?: RequestInit;
  response?: { status: number; headers?: Record<string, string>; body?: unknown };
}) {
  return async function fakeFetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
    record.url = typeof input === "string" ? input : input.toString();
    record.init = init;
    const r = record.response ?? { status: 200, body: { ok: true } };
    const headers = new Headers(r.headers ?? { "content-type": "application/json" });
    const body = typeof r.body === "string" ? r.body : JSON.stringify(r.body ?? null);
    return new Response(body, { status: r.status, headers });
  };
}

async function seedToken(
  tokenStore: InMemoryTokenStore,
  providerTokenStore: InMemoryProviderTokenStore,
  overrides: Partial<{ agent_id: string; provider_id: string; scopes: string[]; connection: string }> = {},
) {
  const connection = overrides.connection ?? "conn_1";
  const token = await tokenStore.create({
    agent_id: overrides.agent_id ?? AGENT,
    client_id: "ath_client_1",
    user_id: "user_1",
    provider_id: overrides.provider_id ?? "github",
    scopes: overrides.scopes ?? ["repo"],
    oauth_connection_id: connection,
    created_at: new Date().toISOString(),
    expires_at: new Date(Date.now() + 60_000).toISOString(),
  });
  await providerTokenStore.set(connection, { access_token: "provider_at_secret" });
  return token;
}

function makeHandler(
  opts: {
    tokenStore: InMemoryTokenStore;
    providerTokenStore: InMemoryProviderTokenStore;
    upstreams?: Record<string, string>;
    fetchRecord?: Parameters<typeof makeFakeFetch>[0];
  },
) {
  return createProxyHandler({
    tokenStore: opts.tokenStore,
    providerTokenStore: opts.providerTokenStore,
    upstreams: opts.upstreams ?? { github: "https://api.github.example" },
    fetch: opts.fetchRecord ? makeFakeFetch(opts.fetchRecord) : (async () => new Response("{}", { status: 200, headers: { "content-type": "application/json" } })),
  });
}

function baseReq(token: string | undefined, path = "/ath/proxy/github/user"): ProxyRequest {
  return {
    method: "GET",
    path,
    headers: {
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      "X-ATH-Agent-ID": AGENT,
    },
  };
}

describe("createProxyHandler", () => {
  let tokenStore: InMemoryTokenStore;
  let providerTokenStore: InMemoryProviderTokenStore;

  beforeEach(() => {
    tokenStore = new InMemoryTokenStore();
    providerTokenStore = new InMemoryProviderTokenStore();
  });

  it("MH-X1: returns 401 when Authorization is missing", async () => {
    const handler = makeHandler({ tokenStore, providerTokenStore });
    const res = await handler({ method: "GET", path: "/ath/proxy/github/user", headers: {} });
    expect(res.status).toBe(401);
    expect(res.body).toMatchObject({ code: "TOKEN_INVALID" });
  });

  it("MH-X2: returns 401 on malformed Bearer header", async () => {
    const handler = makeHandler({ tokenStore, providerTokenStore });
    const res = await handler({
      method: "GET",
      path: "/ath/proxy/github/user",
      headers: { Authorization: "Basic xyz" },
    });
    expect(res.status).toBe(401);
    expect(res.body).toMatchObject({ code: "TOKEN_INVALID" });
  });

  it("MH-X3: returns 403 on agent-id header mismatch", async () => {
    const token = await seedToken(tokenStore, providerTokenStore);
    const handler = makeHandler({ tokenStore, providerTokenStore });
    const res = await handler({
      method: "GET",
      path: "/ath/proxy/github/user",
      headers: {
        Authorization: `Bearer ${token}`,
        "X-ATH-Agent-ID": "https://OTHER.example.com/.well-known/agent.json",
      },
    });
    expect(res.status).toBe(403);
    expect(res.body).toMatchObject({ code: "AGENT_IDENTITY_MISMATCH" });
  });

  it("returns 403 when token is bound to a different provider", async () => {
    const token = await seedToken(tokenStore, providerTokenStore, { provider_id: "slack" });
    const handler = makeHandler({ tokenStore, providerTokenStore });
    const res = await handler(baseReq(token));
    expect(res.status).toBe(403);
    expect(res.body).toMatchObject({ code: "PROVIDER_MISMATCH" });
  });

  it("MH-X4: returns 403 when upstream is not configured for provider", async () => {
    const token = await seedToken(tokenStore, providerTokenStore);
    const handler = makeHandler({ tokenStore, providerTokenStore, upstreams: {} });
    const res = await handler(baseReq(token));
    expect(res.status).toBe(403);
    expect(res.body).toMatchObject({ code: "PROVIDER_NOT_CONFIGURED" });
  });

  it("MH-X5: returns 502 when no provider token stored for the connection", async () => {
    // seed a token but then wipe the provider token store
    const token = await seedToken(tokenStore, providerTokenStore);
    await providerTokenStore.delete("conn_1");
    const handler = makeHandler({ tokenStore, providerTokenStore });
    const res = await handler(baseReq(token));
    expect(res.status).toBe(502);
    expect(res.body).toMatchObject({ code: "PROVIDER_TOKEN_MISSING" });
  });

  it("MH-X6: happy path forwards provider bearer and returns upstream response", async () => {
    const token = await seedToken(tokenStore, providerTokenStore);
    const record: Parameters<typeof makeFakeFetch>[0] = {
      response: { status: 200, headers: { "content-type": "application/json" }, body: { login: "octocat" } },
    };
    const handler = makeHandler({ tokenStore, providerTokenStore, fetchRecord: record });
    const res = await handler(baseReq(token, "/ath/proxy/github/user"));

    expect(res.status).toBe(200);
    expect(res.body).toEqual({ login: "octocat" });
    expect(record.url).toBe("https://api.github.example/user");

    const fwd = (record.init?.headers ?? {}) as Record<string, string>;
    expect(fwd.Authorization).toBe("Bearer provider_at_secret");
    // The ATH bearer MUST NOT have leaked through.
    const anyAthBearer = Object.values(fwd).some((v) => typeof v === "string" && v.includes(token));
    expect(anyAthBearer).toBe(false);
    // Agent-id header is internal, not forwarded.
    expect(fwd["X-ATH-Agent-ID"]).toBeUndefined();
    expect(fwd["x-ath-agent-id"]).toBeUndefined();
  });

  it("forwards request body on POST", async () => {
    const token = await seedToken(tokenStore, providerTokenStore);
    const record: Parameters<typeof makeFakeFetch>[0] = {
      response: { status: 201, headers: { "content-type": "application/json" }, body: { created: true } },
    };
    const handler = makeHandler({ tokenStore, providerTokenStore, fetchRecord: record });
    const res = await handler({
      method: "POST",
      path: "/ath/proxy/github/repos",
      headers: { Authorization: `Bearer ${token}`, "X-ATH-Agent-ID": AGENT },
      body: { name: "new-repo" },
    });
    expect(res.status).toBe(201);
    expect(record.init?.body).toBe(JSON.stringify({ name: "new-repo" }));
  });

  it("rejects requests on a revoked token", async () => {
    const token = await seedToken(tokenStore, providerTokenStore);
    await tokenStore.revoke(token);
    const handler = makeHandler({ tokenStore, providerTokenStore });
    const res = await handler(baseReq(token));
    expect(res.status).toBe(401);
    expect(res.body).toMatchObject({ code: "TOKEN_REVOKED" });
  });

  it("rejects requests when path does not match proxy shape", async () => {
    const token = await seedToken(tokenStore, providerTokenStore);
    const handler = makeHandler({ tokenStore, providerTokenStore });
    const res = await handler({
      method: "GET",
      path: "/some/other/path",
      headers: { Authorization: `Bearer ${token}`, "X-ATH-Agent-ID": AGENT },
    });
    expect(res.status).toBe(400);
    expect(res.body).toMatchObject({ code: "INVALID_PATH" });
  });
});
