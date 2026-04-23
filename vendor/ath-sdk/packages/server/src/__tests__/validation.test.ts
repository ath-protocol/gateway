import { describe, it, expect, beforeEach } from "vitest";
import { InMemoryTokenStore } from "../tokens.js";
import { validateToken } from "../validation.js";

const futureISO = () => new Date(Date.now() + 60_000).toISOString();
const pastISO = () => new Date(Date.now() - 60_000).toISOString();

async function seed(
  store: InMemoryTokenStore,
  overrides: Partial<{
    agent_id: string;
    client_id: string;
    user_id: string;
    provider_id: string;
    scopes: string[];
    oauth_connection_id: string;
    expires_at: string;
  }> = {},
) {
  return store.create({
    agent_id: overrides.agent_id ?? "https://agent.example.com/.well-known/agent.json",
    client_id: overrides.client_id ?? "ath_client_1",
    user_id: overrides.user_id ?? "user_1",
    provider_id: overrides.provider_id ?? "github",
    scopes: overrides.scopes ?? ["repo", "read:user"],
    oauth_connection_id: overrides.oauth_connection_id ?? "conn_1",
    created_at: new Date().toISOString(),
    expires_at: overrides.expires_at ?? futureISO(),
  });
}

describe("validateToken", () => {
  let store: InMemoryTokenStore;

  beforeEach(() => {
    store = new InMemoryTokenStore();
  });

  it("MH-V1: returns TOKEN_INVALID for unknown token", async () => {
    const result = await validateToken(store, "ath_tk_does_not_exist");
    expect(result).toMatchObject({ valid: false, code: "TOKEN_INVALID" });
  });

  it("MH-V1: returns TOKEN_INVALID for empty/undefined token", async () => {
    expect(await validateToken(store, "")).toMatchObject({ valid: false, code: "TOKEN_INVALID" });
    expect(await validateToken(store, undefined)).toMatchObject({ valid: false, code: "TOKEN_INVALID" });
  });

  it("MH-V2: returns TOKEN_REVOKED for revoked token", async () => {
    const token = await seed(store);
    await store.revoke(token);
    const result = await validateToken(store, token);
    expect(result).toMatchObject({ valid: false, code: "TOKEN_REVOKED" });
  });

  it("MH-V3: returns TOKEN_EXPIRED when expires_at is in the past", async () => {
    const token = await seed(store, { expires_at: pastISO() });
    const result = await validateToken(store, token);
    expect(result).toMatchObject({ valid: false, code: "TOKEN_EXPIRED" });
  });

  it("MH-V4: returns AGENT_IDENTITY_MISMATCH when agentId does not match binding", async () => {
    const token = await seed(store, { agent_id: "https://a.example.com/.well-known/agent.json" });
    const result = await validateToken(store, token, {
      agentId: "https://b.example.com/.well-known/agent.json",
    });
    expect(result).toMatchObject({ valid: false, code: "AGENT_IDENTITY_MISMATCH" });
  });

  it("MH-V5: returns SCOPE_NOT_APPROVED with denied list when missing a scope", async () => {
    const token = await seed(store, { scopes: ["repo"] });
    const result = await validateToken(store, token, { requiredScopes: ["repo", "admin:org"] });
    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.code).toBe("SCOPE_NOT_APPROVED");
      expect(result.denied).toEqual(["admin:org"]);
    }
  });

  it("MH-V6: returns valid result on happy path", async () => {
    const token = await seed(store);
    const result = await validateToken(store, token, {
      agentId: "https://agent.example.com/.well-known/agent.json",
      requiredScopes: ["repo"],
    });
    expect(result.valid).toBe(true);
    if (result.valid) {
      expect(result.token.scopes).toContain("repo");
      expect(result.token.revoked).toBe(false);
    }
  });

  it("order: revoked before expired", async () => {
    const token = await seed(store, { expires_at: pastISO() });
    await store.revoke(token);
    const result = await validateToken(store, token);
    expect(result).toMatchObject({ valid: false, code: "TOKEN_REVOKED" });
  });

  it("does not mutate the bound token", async () => {
    const token = await seed(store);
    const before = await store.get(token);
    await validateToken(store, token, { requiredScopes: ["admin:org"] });
    const after = await store.get(token);
    expect(after).toEqual(before);
  });
});
